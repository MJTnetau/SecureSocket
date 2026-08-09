using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace SecureSocket;

/// <summary>
/// High-performance TLS Socket Client built on System.IO.Pipelines.
/// Generic domain-agnostic drop-in replacement for legacy SecureSocket.Client.
/// </summary>
public class Client : IDisposable, IAsyncDisposable
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<int, Action<Message2>> _customHandlers = new();

    private volatile bool _connecting = false;
    private volatile bool _connected = false;
    private bool _retryConnect = true;
    private int _retryAttempts = 0;
    private readonly int _retryDelay = 3000;

    private IPAddress _serverIP = IPAddress.Loopback;
    private int _serverPort = 20001;
    private string _hostname = "localhost";
    private readonly bool _allowSelfSignedCerts;

    private TcpClient? _tcpClient;
    private SslStream? _sslStream;
    private PipeReader? _reader;
    private PipeWriter? _writer;

    private readonly SemaphoreSlim _authLock = new(1, 1);
    private TaskCompletionSource<(bool Success, string Message)>? _authTcs;

    // Events matching original SecureSocket + clean C# event aliases
    public EventHandler<RawFrameEventArgs>? OnRawFrameEvent;
    public EventHandler<TextReceivedEventArgs>? OnTextReceivedEvent;
    public EventHandler<TextReceivedEventArgs>? OnUncategorizedMessageEvent;
    public EventHandler<StatusEventArgs>? OnStatusEvent;
    public EventHandler<LogEventArgs>? OnLogEvent;
    public EventHandler<TickEventArgs>? OnTickEvent;
    public EventHandler<PingEventArgs>? OnPingEvent;
    public EventHandler<EventArgs>? OnServerConnectedEvent;
    public EventHandler<EventArgs>? OnServerDisconnectedEvent;

    public event EventHandler<RawFrameEventArgs>? RawFrameReceived { add => OnRawFrameEvent += value; remove => OnRawFrameEvent -= value; }
    public event EventHandler<TextReceivedEventArgs>? TextReceived { add => OnTextReceivedEvent += value; remove => OnTextReceivedEvent -= value; }
    public event EventHandler<TextReceivedEventArgs>? UncategorizedMessage { add => OnUncategorizedMessageEvent += value; remove => OnUncategorizedMessageEvent -= value; }
    public event EventHandler<StatusEventArgs>? Status { add => OnStatusEvent += value; remove => OnStatusEvent -= value; }
    public event EventHandler<LogEventArgs>? Log { add => OnLogEvent += value; remove => OnLogEvent -= value; }
    public event EventHandler<TickEventArgs>? Tick { add => OnTickEvent += value; remove => OnTickEvent -= value; }
    public event EventHandler<PingEventArgs>? Ping { add => OnPingEvent += value; remove => OnPingEvent -= value; }
    public event EventHandler<EventArgs>? ServerConnected { add => OnServerConnectedEvent += value; remove => OnServerConnectedEvent -= value; }
    public event EventHandler<EventArgs>? ServerDisconnected { add => OnServerDisconnectedEvent += value; remove => OnServerDisconnectedEvent -= value; }

    #region Properties

    // Never cache this variable in a CPU register.
    private volatile bool _isClosed;

    public bool IsConnected => _connected;
    public bool IsConnecting => _connecting;
    public bool AutoReconnect { get => _retryConnect; set => _retryConnect = value; }

    public IPAddress ServerIPAddress => _serverIP;
    public int ServerPort => _serverPort;

    public UserIdentifier User { get; private set; } = UserIdentifier.Anonymous;

    /// <summary>
    /// Gets the strongly-typed client configuration options.
    /// </summary>
    public ClientOptions Options { get; }

    #endregion

    /// <summary>
    /// Initializes a new instance of <see cref="Client"/> using optional <see cref="ClientOptions"/>.
    /// </summary>
    /// <param name="options">Configuration options. If <c>null</c>, default options targeting 127.0.0.1:20001 are used.</param>
    public Client(ClientOptions? options = null)
    {
        Options = options ?? new ClientOptions();
        _serverPort = Options.Port;
        _allowSelfSignedCerts = Options.AllowSelfSignedCerts;
        _retryConnect = Options.AutoReconnect;
        _retryDelay = Options.RetryDelayMs;
        SetServerIPAddress(Options.Host);
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Client"/> targeting specified server host and port.
    /// </summary>
    /// <param name="host">Server host IP or domain name.</param>
    /// <param name="port">Server listening port.</param>
    /// <param name="allowSelfSignedCerts">Set to <c>true</c> ONLY in development mode to accept untrusted/self-signed certificates. Hostname mismatches and missing certs remain rejected.</param>
    public Client(string host, int port = 20001, bool allowSelfSignedCerts = false)
    {
        Options = new ClientOptions { Host = host, Port = port, AllowSelfSignedCerts = allowSelfSignedCerts };
        _serverPort = Options.Port;
        _allowSelfSignedCerts = Options.AllowSelfSignedCerts;
        _retryConnect = Options.AutoReconnect;
        _retryDelay = Options.RetryDelayMs;
        SetServerIPAddress(Options.Host);
    }

    /// <summary>
    /// Sets the target server IP address or hostname.
    /// </summary>
    public bool SetServerIPAddress(string serverAddress)
    {
        if (string.IsNullOrWhiteSpace(serverAddress))
        {
            WriteLog("Invalid server address supplied.");
            return false;
        }

        if (IPAddress.TryParse(serverAddress, out var ip))
        {
            _serverIP = ip;
            _hostname = ip.ToString();
            return true;
        }

        try
        {
            var hostEntry = Dns.GetHostEntry(serverAddress);
            if (hostEntry.AddressList.Length > 0)
            {
                _serverIP = hostEntry.AddressList[0];
                _hostname = serverAddress;
                return true;
            }
        }
        catch
        {
            // Invalid hostname
        }

        WriteLog($"Could not resolve server address: '{serverAddress}'.");
        return false;
    }

    /// <summary>
    /// Sets the target server port number.
    /// </summary>
    public bool SetPortNumber(int port)
    {
        if (port <= 0 || port > 65535)
        {
            WriteLog("Invalid server port. Must be 1 to 65535.");
            return false;
        }
        _serverPort = port;
        return true;
    }

    /// <summary>
    /// Registers a custom protocol extension handler for the specified message opcode.
    /// </summary>
    public void RegisterHandler(MessageType msgType, Action<Message2> handler)
    {
        int opcode = (int)msgType;
        _customHandlers[opcode] = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    /// <summary>
    /// Unregisters a custom protocol extension handler.
    /// </summary>
    public void UnregisterHandler(MessageType msgType)
    {
        _customHandlers.TryRemove((int)msgType, out _);
    }

    /// <summary>
    /// Connects asynchronously to the target TLS server.
    /// </summary>
    public async Task Connect()
    {
        if (_connecting)
        {
            WriteLog("Connection attempt already in progress.");
            return;
        }

        if (_connected)
        {
            WriteLog("Client is already connected.");
            return;
        }

        _connecting = true;
        _isClosed = false;
        _retryAttempts++;

        try
        {
            WriteLog($"Connecting to TLS Server at {_serverIP}:{_serverPort}...");
            _tcpClient = new TcpClient();
            _tcpClient.NoDelay = true; // Low-latency high performance

            await _tcpClient.ConnectAsync(_serverIP, _serverPort);

            Stream networkStream = _tcpClient.GetStream();
            _sslStream = new SslStream(networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate));

            await _sslStream.AuthenticateAsClientAsync(_hostname);

            _reader = PipeReader.Create(_sslStream);
            _writer = PipeWriter.Create(_sslStream);

            _connecting = false;
            _connected = true;
            _retryAttempts = 0;

            WriteLog("TLS Handshake successful. Connected to server.");
            OnServerConnectedEvent?.Invoke(this, EventArgs.Empty);

            // Start background pipe reader loop
            _ = ProcessServerPipelineLoopAsync();
        }
        catch (Exception ex)
        {
            _connecting = false;
            Close();
            WriteLog($"Error connecting to server: {ex.Message}");

            if (_retryConnect && !_isClosed)
            {
                await RetryConnectingAsync();
            }
        }
    }

    private bool ValidateServerCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate, System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        if (_allowSelfSignedCerts)
        {
            // Reject if certificate was not supplied by server
            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
            {
                WriteLog("[SECURITY ERROR] TLS Certificate validation failed: RemoteCertificateNotAvailable.");
                return false;
            }

            bool isLoopback = string.Equals(_hostname, "localhost", StringComparison.OrdinalIgnoreCase)
                || string.Equals(_hostname, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
                || string.Equals(_hostname, "::1", StringComparison.OrdinalIgnoreCase)
                || IPAddress.IsLoopback(_serverIP);

            // Allow self-signed chain errors, and for local loopback connections allow hostname mismatches
            if (isLoopback || !sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
            {
                WriteLog($"[WARNING] Accepting untrusted/self-signed server TLS certificate ({sslPolicyErrors}) (Development Mode).");
                return true;
            }
        }

        WriteLog($"[SECURITY ERROR] TLS Certificate validation failed: {sslPolicyErrors}.");
        return false;
    }

    private async Task RetryConnectingAsync()
    {
        int maxRetries = Options.MaxRetryAttempts;
        if (maxRetries > 0 && _retryAttempts >= maxRetries)
        {
            WriteLog($"Maximum retry attempts ({maxRetries}) reached. Giving up.");
            return;
        }

        WriteLog($"Waiting {_retryDelay}ms before retry attempt #{_retryAttempts}...");
        await Task.Delay(_retryDelay);
        if (!_connected && !_isClosed)
        {
            await Connect();
        }
    }

    private async Task ProcessServerPipelineLoopAsync()
    {
        if (_reader == null) return;

        while (_connected && !_isClosed)
        {
            ReadResult readResult;
            try
            {
                readResult = await _reader.ReadAsync();
            }
            catch (Exception ex)
            {
                WriteLog($"Pipe read error: {ex.Message}");
                break;
            }

            var buffer = readResult.Buffer;

            try
            {
                while (PipelineFraming.TryParseFrame(ref buffer, out Message2? frame))
                {
                    if (frame != null)
                    {
                        ProcessReceivedFrame(frame);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Protocol framing violation from server: {ex.Message}");
                break;
            }

            _reader.AdvanceTo(buffer.Start, buffer.End);

            if (readResult.IsCompleted || readResult.IsCanceled)
            {
                break;
            }
        }

        Close();
    }

    private void ProcessReceivedFrame(Message2 frame)
    {
        // 1. Raw Tap: Raised for EVERY frame without exception (Option 1)
        OnRawFrameEvent?.Invoke(this, new RawFrameEventArgs("Server", frame));

        bool handled = false;

        // 2. Built-in protocol handlers
        switch (frame.MsgType)
        {
            case MessageType.Ping:
                string nonce = frame.GetArgument(0);
                OnPingEvent?.Invoke(this, new PingEventArgs(nonce, isPong: false));
                _ = SendMessageAsync(MessageType.Pong, nonce);
                handled = true;
                break;

            case MessageType.Pong:
                string pongNonce = frame.GetArgument(0);
                string sentTimestampStr = frame.GetArgument(1);
                double latencyMs = 0;
                if (long.TryParse(sentTimestampStr, out long sentTicks))
                {
                    latencyMs = (Stopwatch.GetTimestamp() - sentTicks) * 1000.0 / Stopwatch.Frequency;
                }
                OnPingEvent?.Invoke(this, new PingEventArgs(pongNonce, isPong: true, latencyMs));
                handled = true;
                break;

            case MessageType.Tick:
                if (int.TryParse(frame.GetArgument(0), out int tickCount) && DateTime.TryParse(frame.GetArgument(1), out var ts))
                {
                    OnTickEvent?.Invoke(this, new TickEventArgs(tickCount, ts));
                }
                handled = true;
                break;

            case MessageType.RegisterResp:
                string regStatus = frame.GetArgument(0);
                string regEmail = frame.GetArgument(1);
                bool regOk = string.Equals(regStatus, "SUCCESS", StringComparison.OrdinalIgnoreCase);
                string regMsg = regOk 
                    ? (frame.Arguments.Length > 3 ? frame.GetArgument(3) : $"Registration successful for '{regEmail}'. Please log in using: /login {regEmail} <password>")
                    : (frame.Arguments.Length > 2 ? frame.GetArgument(2) : $"Registration failed for '{regEmail}'.");
                
                WriteLog(regMsg);
                _authTcs?.TrySetResult((regOk, regMsg));
                handled = true;
                break;

            case MessageType.LoginResp:
                string loginStatus = frame.GetArgument(0);
                if (string.Equals(loginStatus, "SUCCESS", StringComparison.OrdinalIgnoreCase))
                {
                    string userId = frame.GetArgument(1);
                    string displayName = frame.GetArgument(2);
                    User = new UserIdentifier(userId, displayName);
                    string msg = $"User login successful as '{User}'.";
                    WriteLog(msg);
                    _authTcs?.TrySetResult((true, msg));
                }
                else if (string.Equals(loginStatus, "LOGOUT", StringComparison.OrdinalIgnoreCase))
                {
                    User = UserIdentifier.Anonymous;
                    string msg = "User logged out.";
                    WriteLog(msg);
                    _authTcs?.TrySetResult((true, msg));
                }
                else
                {
                    string err = frame.Arguments.Length > 2 ? frame.GetArgument(2) : "Invalid email or password.";
                    string msg = $"User login failed: {err}";
                    WriteLog(msg);
                    _authTcs?.TrySetResult((false, msg));
                }
                handled = true;
                break;
        }

        // 3. Custom protocol extension handlers
        int opcode = (int)frame.MsgType;
        if (_customHandlers.TryGetValue(opcode, out var handler))
        {
            try
            {
                handler(frame);
                handled = true;
            }
            catch (Exception ex)
            {
                WriteLog($"Error in custom handler for opcode {opcode}: {ex.Message}");
            }
        }

        // 4. Spillover / Uncategorized Message Handler (Option 2)
        if (!handled)
        {
            WriteLog($"Received uncategorized frame: {frame}");
            var textArgs = new TextReceivedEventArgs("Server", frame.ToString(), frame);
            OnUncategorizedMessageEvent?.Invoke(this, textArgs);
            OnTextReceivedEvent?.Invoke(this, textArgs);
        }
    }


    #region Send Operations

    /// <summary>
    /// Sends a Ping message with a custom nonce string and high-precision timestamp to the server.
    /// </summary>
    public async Task SendPingAsync(string? nonce = null)
    {
        nonce ??= Guid.NewGuid().ToString("N")[..8];
        long currentTicks = Stopwatch.GetTimestamp();
        await SendMessageAsync(MessageType.Ping, nonce, currentTicks.ToString());
    }

    /// <summary>
    /// Sends a UserRegister request to the server with email and password and awaits server confirmation.
    /// </summary>
    public async Task<(bool Success, string Message)> RegisterAsync(string email, string password, string? displayName = null)
    {
        await _authLock.WaitAsync();
        try
        {
            _authTcs = new TaskCompletionSource<(bool Success, string Message)>(TaskCreationOptions.RunContinuationsAsynchronously);
            await SendMessageAsync(MessageType.UserRegister, email, password, displayName ?? string.Empty);
            
            using var cts = new CancellationTokenSource(5000);
            cts.Token.Register(() => _authTcs.TrySetResult((false, "Registration request timed out.")));
            return await _authTcs.Task;
        }
        finally
        {
            _authLock.Release();
        }
    }

    /// <summary>
    /// Sends a UserLogin request to the server with email and password and awaits authentication outcome.
    /// </summary>
    public async Task<(bool Success, string Message)> LoginAsync(string email, string password)
    {
        await _authLock.WaitAsync();
        try
        {
            _authTcs = new TaskCompletionSource<(bool Success, string Message)>(TaskCreationOptions.RunContinuationsAsynchronously);
            await SendMessageAsync(MessageType.UserLogin, email, password);

            using var cts = new CancellationTokenSource(5000);
            cts.Token.Register(() => _authTcs.TrySetResult((false, "Login request timed out.")));
            return await _authTcs.Task;
        }
        finally
        {
            _authLock.Release();
        }
    }

    /// <summary>
    /// Sends a UserLogout request to the server.
    /// </summary>
    public async Task LogoutAsync()
    {
        await SendMessageAsync(MessageType.UserLogout);
        User = UserIdentifier.Anonymous;
    }

    /// <summary>
    /// Sends a message type opcode with positional string arguments asynchronously.
    /// </summary>
    public async Task SendMessageAsync(MessageType msgType, params string[] arguments)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(msgType, arguments);
        await SendBytesAsync(frameBytes);
    }

    /// <summary>
    /// Sends a message type opcode with positional string arguments and binary payload asynchronously.
    /// </summary>
    public async Task SendMessageAsync(MessageType msgType, string[] arguments, ReadOnlyMemory<byte> binaryPayload)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(msgType, arguments, binaryPayload.Span);
        await SendBytesAsync(frameBytes);
    }

    /// <summary>
    /// Writes frame bytes directly to the TLS socket.
    /// </summary>
    public async Task SendBytesAsync(ReadOnlyMemory<byte> frameBytes)
    {
        if (!_connected || _writer == null) return;

        await _writeLock.WaitAsync();
        try
        {
            await _writer.WriteAsync(frameBytes);
            await _writer.FlushAsync();
        }
        catch (Exception ex)
        {
            WriteLog($"Error sending frame bytes: {ex.Message}");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    #endregion

    /// <summary>
    /// Disconnects and closes the client socket.
    /// </summary>
    public void Close()
    {
        _connected = false;
        _isClosed = true;
        try
        {
            _reader?.Complete();
            _writer?.Complete();
            _sslStream?.Close();
            _sslStream?.Dispose();
            _tcpClient?.Close();
            _tcpClient?.Dispose();

            WriteLog("Disconnected from server.");
            OnServerDisconnectedEvent?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            // Ignored on teardown
        }
    }

    private void WriteLog(string message, bool isError = false, Exception? exception = null)
    {
        string formatted = $"[SecureSocket.Client {DateTime.Now:HH:mm:ss}] {message}";

        if (isError && Options.ErrorAction != null)
        {
            Options.ErrorAction.Invoke(message, exception);
        }
        else if (Options.LogAction != null)
        {
            Options.LogAction.Invoke(message);
        }
        else
        {
            Debug.WriteLine(formatted);
        }

        OnStatusEvent?.Invoke(this, new StatusEventArgs(formatted));
        OnLogEvent?.Invoke(this, new LogEventArgs(formatted));
    }

    /// <summary>
    /// Disconnects socket and disposes client resources.
    /// </summary>
    public void Dispose()
    {
        Close();
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Asynchronously disconnects socket and disposes client resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        Close();
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
        await Task.CompletedTask;
    }
}
