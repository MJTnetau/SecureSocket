using System.IO.Pipelines;
using System.Net;
using System.Net.Security;

namespace SecureSocket;

/// <summary>
/// Server-private representation of an active client session over TLS.
/// Contains private connection state (IP address, TLS stream, connection ID) strictly isolated to the server.
/// </summary>
public class SslClientSession : IDisposable, IAsyncDisposable
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    /// <summary>
    /// Gets the unique server-assigned integer connection ID (e.g. 101).
    /// </summary>
    public int ConnId { get; }

    /// <summary>
    /// Gets or sets the public user identity (UserId and DisplayName).
    /// </summary>
    public UserIdentifier User { get; internal set; }

    /// <summary>
    /// Gets the remote IP endpoint of the client socket (Server-Private).
    /// </summary>
    public IPEndPoint RemoteEndPoint { get; }

    /// <summary>
    /// Gets a value indicating whether the client has successfully registered/logged in.
    /// </summary>
    public bool IsAuthenticated { get; internal set; }

    /// <summary>
    /// Gets the timestamp when the client connected.
    /// </summary>
    public DateTime ConnectedAt { get; }

    /// <summary>
    /// Gets the underlying SslStream (Server-Private).
    /// </summary>
    internal SslStream SslStream { get; }

    /// <summary>
    /// Gets the System.IO.Pipelines PipeReader for receiving zero-allocation stream frames.
    /// </summary>
    internal PipeReader Reader { get; }

    /// <summary>
    /// Gets the System.IO.Pipelines PipeWriter for sending zero-allocation stream frames.
    /// </summary>
    internal PipeWriter Writer { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SslClientSession"/> class.
    /// </summary>
    public SslClientSession(int connId, SslStream sslStream, IPEndPoint remoteEndPoint)
    {
        ConnId = connId;
        SslStream = sslStream ?? throw new ArgumentNullException(nameof(sslStream));
        RemoteEndPoint = remoteEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
        User = new UserIdentifier($"conn_{connId}", $"Anonymous@{connId}");
        ConnectedAt = DateTime.UtcNow;

        // Create System.IO.Pipelines around the TLS SslStream
        Reader = PipeReader.Create(sslStream);
        Writer = PipeWriter.Create(sslStream);
    }

    /// <summary>
    /// Sends a formatted Message2 frame asynchronously to the client.
    /// Thread-safe via SemaphoreSlim write lock.
    /// </summary>
    public async Task SendAsync(Message2 message)
    {
        if (message == null) return;
        byte[] frameBytes = PipelineFraming.FormatFrame(message.MsgType, message.Arguments, message.BinaryPayload.Span);
        await SendBytesAsync(frameBytes);
    }

    /// <summary>
    /// Sends a message type opcode with positional string arguments.
    /// </summary>
    public async Task SendAsync(MessageType msgType, params string[] arguments)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(msgType, arguments);
        await SendBytesAsync(frameBytes);
    }

    /// <summary>
    /// Sends a message type opcode with positional string arguments and binary payload.
    /// </summary>
    public async Task SendAsync(MessageType msgType, string[]? arguments, ReadOnlyMemory<byte> binaryPayload)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(msgType, arguments, binaryPayload.Span);
        await SendBytesAsync(frameBytes);
    }

    /// <summary>
    /// Writes raw byte frame directly to the SslStream pipe.
    /// </summary>
    public async Task SendBytesAsync(ReadOnlyMemory<byte> frameBytes)
    {
        await _writeLock.WaitAsync();
        try
        {
            await Writer.WriteAsync(frameBytes);
            await Writer.FlushAsync();
        }
        catch
        {
            // Socket write dropped
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Closes and disposes the TLS session.
    /// </summary>
    public void Close()
    {
        try
        {
            Reader.Complete();
            Writer.Complete();
            SslStream.Close();
            SslStream.Dispose();
        }
        catch
        {
            // Ignored on teardown
        }
    }

    /// <summary>
    /// Disposes disposable resources associated with the session.
    /// </summary>
    public void Dispose()
    {
        Close();
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Asynchronously disposes session resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        Close();
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
        await Task.CompletedTask;
    }

    /// <summary>
    /// Returns a string representation of the client session.
    /// </summary>
    public override string ToString()
    {
        return $"Client#{ConnId} ({User}) [{RemoteEndPoint}]";
    }

}
