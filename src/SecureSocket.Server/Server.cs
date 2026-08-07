using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SecureSocket.Auth;

namespace SecureSocket;

/// <summary>
/// High-performance TLS Socket Server built on System.IO.Pipelines.
/// Generic domain-agnostic drop-in replacement for legacy SecureSocket.
/// </summary>
public class Server : IDisposable, IAsyncDisposable
{
    private bool _isVerbose = true;
    private readonly X509Certificate2 _serverCertificate;
    private readonly IUserStore? _userStore;

    private IPAddress? _ip;
    private int _port = 20001;
    private TcpListener? _listener;

    private int _connIdCount = 100;
    private readonly ConcurrentDictionary<int, SslClientSession> _clients = new();
    private readonly ConcurrentDictionary<int, Func<SslClientSession, Message2, Task>> _customHandlers = new();

    // Heartbeat / Tick settings
    private int _interval = 500;
    private int _tickCount = 0;
    private System.Timers.Timer? _tickTimer;
    private readonly Stopwatch _tickStopwatch = new();
    private string _tickLastStopwatch = string.Empty;

    private readonly ConcurrentDictionary<int, (int Attempts, DateTime WindowStart)> _authAttempts = new();

    // Events (Idiomatic C# names + backwards compatible aliases)
    public EventHandler<ClientConnectedEventArgs>? OnClientConnectedEvent;
    public EventHandler<ClientDisconnectEventArgs>? OnClientDisconnectedEvent;
    public EventHandler<TextReceivedEventArgs>? OnTextReceivedEvent;
    public EventHandler<StatusEventArgs>? OnStatusEvent;
    public EventHandler<TickEventArgs>? OnTickEvent;
    public EventHandler<PingEventArgs>? OnPingEvent;

    public event EventHandler<ClientConnectedEventArgs>? ClientConnected { add => OnClientConnectedEvent += value; remove => OnClientConnectedEvent -= value; }
    public event EventHandler<ClientDisconnectEventArgs>? ClientDisconnected { add => OnClientDisconnectedEvent += value; remove => OnClientDisconnectedEvent -= value; }
    public event EventHandler<TextReceivedEventArgs>? TextReceived { add => OnTextReceivedEvent += value; remove => OnTextReceivedEvent -= value; }
    public event EventHandler<StatusEventArgs>? Status { add => OnStatusEvent += value; remove => OnStatusEvent -= value; }
    public event EventHandler<TickEventArgs>? Tick { add => OnTickEvent += value; remove => OnTickEvent -= value; }
    public event EventHandler<PingEventArgs>? Ping { add => OnPingEvent += value; remove => OnPingEvent -= value; }

    #region Properties

    // Never cache this variable in a CPU register.
    private volatile bool _isRunning;

    /// <summary>
    /// Gets a value indicating whether the server listener is active and processing connections.
    /// </summary>
    public bool IsRunning => _isRunning;

    public int GetClientCount => _clients.Count;

    public IReadOnlyDictionary<int, SslClientSession> Clients => _clients;

    public int GetInterval => _interval;

    public int GetLastTick => _tickCount;

    public string GetLastStopwatch => _tickLastStopwatch;

    public bool IsVerbose { get => _isVerbose; set => _isVerbose = value; }

    public IUserStore? UserStore => _userStore;

    /// <summary>
    /// Gets the strongly-typed server configuration options.
    /// </summary>
    public ServerOptions Options { get; }

    #endregion

    /// <summary>
    /// Initializes a new instance of <see cref="Server"/> using an X509Certificate2 instance and optional <see cref="ServerOptions"/>.
    /// </summary>
    public Server(X509Certificate2 certificate, ServerOptions? options = null, IUserStore? userStore = null)
    {
        _serverCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        Options = options ?? new ServerOptions();
        _userStore = userStore;
        _ip = Options.IPAddress;
        _port = Options.Port;
        _isVerbose = Options.IsVerbose;
        _interval = Options.TickIntervalMs;
        WriteLog("Server certificate loaded from X509Certificate2 instance.");
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Server"/> using an X509Certificate2 instance and specified <see cref="IUserStore"/>.
    /// </summary>
    public Server(X509Certificate2 certificate, IUserStore? userStore)
    {
        _serverCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        Options = new ServerOptions();
        _userStore = userStore;
        _ip = Options.IPAddress;
        _port = Options.Port;
        _isVerbose = Options.IsVerbose;
        _interval = Options.TickIntervalMs;
        WriteLog("Server certificate loaded from X509Certificate2 instance.");
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Server"/> loading a certificate from path, thumbprint, or secrets.
    /// </summary>
    public Server(string certPathOrThumbprint, string? password = null, ServerOptions? options = null, IUserStore? userStore = null)
    {
        _serverCertificate = CertificateHelper.LoadCertificate(certPathOrThumbprint, password);
        Options = options ?? new ServerOptions();
        _userStore = userStore;
        _ip = Options.IPAddress;
        _port = Options.Port;
        _isVerbose = Options.IsVerbose;
        _interval = Options.TickIntervalMs;
        WriteLog($"Server certificate loaded successfully ({certPathOrThumbprint}).");
    }

    /// <summary>
    /// Registers an async custom protocol extension message handler for the specified opcode.
    /// </summary>
    public void RegisterHandler(MessageType msgType, Func<SslClientSession, Message2, Task> handler)
    {
        int opcode = (int)msgType;
        _customHandlers[opcode] = handler ?? throw new ArgumentNullException(nameof(handler));
        WriteLog($"Registered custom handler for opcode {msgType} ({opcode}).");
    }

    /// <summary>
    /// Registers a synchronous custom protocol extension message handler for the specified opcode.
    /// </summary>
    public void RegisterHandler(MessageType msgType, Action<SslClientSession, Message2> handler)
    {
        if (handler == null) throw new ArgumentNullException(nameof(handler));
        RegisterHandler(msgType, (session, msg) =>
        {
            handler(session, msg);
            return Task.CompletedTask;
        });
    }

    /// <summary>
    /// Unregisters a custom protocol extension message handler.
    /// </summary>
    public void UnregisterHandler(MessageType msgType)
    {
        _customHandlers.TryRemove((int)msgType, out _);
    }

    /// <summary>
    /// Starts listening for incoming TLS socket connections asynchronously.
    /// Uses port from <see cref="ServerOptions.Port"/> if not specified.
    /// </summary>
    public async Task StartListeningAsync(IPAddress? ip = null, int port = 0, CancellationToken cancellationToken = default)
    {
        _ip = ip ?? Options.IPAddress ?? IPAddress.Any;
        _port = port > 0 ? port : Options.Port;

        _listener = new TcpListener(_ip, _port);

        try
        {
            _listener.Start();
            _isRunning = true;
            WriteLog($"SecureSocket Server listening on {_ip}:{_port} (TLS 1.2/1.3)...");

            while (_isRunning && !cancellationToken.IsCancellationRequested)
            {
                TcpClient tcpClient = await _listener.AcceptTcpClientAsync(cancellationToken);
                tcpClient.NoDelay = true; // High performance socket

                _ = HandleClientConnectionAsync(tcpClient);
            }
        }
        catch (Exception ex)
        {
            if (_isRunning && !cancellationToken.IsCancellationRequested)
            {
                WriteLog($"Server Listener Exception: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Starts listening for incoming TLS socket connections asynchronously (non-blocking trigger).
    /// Uses port from <see cref="ServerOptions.Port"/> if not specified.
    /// </summary>
    public void StartListening(IPAddress? ip = null, int port = 0)
    {
        _ = StartListeningAsync(ip, port);
    }

    /// <summary>
    /// Stops the server listener and closes all connected sessions.
    /// </summary>
    public void StopListening()
    {
        _isRunning = false;
        try
        {
            _listener?.Stop();
            StopTicking();

            foreach (var session in _clients.Values)
            {
                session.Close();
            }
            _clients.Clear();
            _authAttempts.Clear();

            WriteLog("Server stopped listening.");
        }
        catch (Exception ex)
        {
            WriteLog($"Error stopping server: {ex.Message}");
        }
    }

    /// <summary>
    /// Starts emitting periodic server heartbeat Ticks at the specified interval in milliseconds.
    /// </summary>
    public void StartTicking(int intervalMs = 500)
    {
        _interval = intervalMs <= 0 ? 500 : intervalMs;
        StopTicking();

        _tickTimer = new System.Timers.Timer(_interval);
        _tickTimer.Elapsed += async (s, e) => await OnTickTimerElapsed();
        _tickTimer.AutoReset = true;
        _tickTimer.Start();

        WriteLog($"Started Server Ticks (Interval: {_interval}ms).");
    }

    /// <summary>
    /// Stops periodic server Ticks.
    /// </summary>
    public void StopTicking()
    {
        if (_tickTimer != null)
        {
            _tickTimer.Stop();
            _tickTimer.Dispose();
            _tickTimer = null;
        }
    }

    private async Task OnTickTimerElapsed()
    {
        _tickStopwatch.Restart();
        _tickCount++;

        var timestamp = DateTime.UtcNow;

        // Broadcast Tick to all connected clients
        await BroadcastAsync(MessageType.Tick, _tickCount.ToString(), timestamp.ToString("o"));

        _tickStopwatch.Stop();
        _tickLastStopwatch = $"{_tickStopwatch.ElapsedMilliseconds} ms";

        OnTickEvent?.Invoke(this, new TickEventArgs(_tickCount, timestamp));
    }

    private async Task HandleClientConnectionAsync(TcpClient tcpClient)
    {
        int connId = Interlocked.Increment(ref _connIdCount);
        IPEndPoint remoteEP = (IPEndPoint)(tcpClient.Client.RemoteEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0));

        SslStream? sslStream = null;
        SslClientSession? session = null;

        try
        {
            sslStream = new SslStream(tcpClient.GetStream(), false);
            await sslStream.AuthenticateAsServerAsync(_serverCertificate, false, enabledSslProtocols: System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, checkCertificateRevocation: false);

            session = new SslClientSession(connId, sslStream, remoteEP);
            _clients[connId] = session;

            WriteLog($"Client connected: {session}");
            OnClientConnectedEvent?.Invoke(this, new ClientConnectedEventArgs(connId, session.User));

            // Execute System.IO.Pipelines reader loop for this client session
            await ProcessClientPipelineLoopAsync(session);
        }
        catch (Exception ex)
        {
            WriteLog($"Client #{connId} handshake/pipe error: {ex.Message}");
        }
        finally
        {
            if (session != null)
            {
                _clients.TryRemove(connId, out _);
                _authAttempts.TryRemove(connId, out _);
                session.Close();
                WriteLog($"Client disconnected: {session}");
                OnClientDisconnectedEvent?.Invoke(this, new ClientDisconnectEventArgs(connId, session.User));
            }
        }
    }

    private async Task ProcessClientPipelineLoopAsync(SslClientSession session)
    {
        while (_isRunning)
        {
            var readResult = await session.Reader.ReadAsync();
            var buffer = readResult.Buffer;

            try
            {
                while (PipelineFraming.TryParseFrame(ref buffer, out Message2? frame, Options.MaxFrameSizeBytes))
                {
                    if (frame != null)
                    {
                        frame.SenderUser = session.User;
                        await ProcessReceivedFrameAsync(session, frame);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Protocol framing violation from {session}: {ex.Message}. Closing connection.");
                // Send protocol error frame before closing
                await session.SendAsync(MessageType.ERROR, "PROTOCOL_VIOLATION", ex.Message);
                break; // Teardown session on framing corruption
            }

            session.Reader.AdvanceTo(buffer.Start, buffer.End);

            if (readResult.IsCompleted || readResult.IsCanceled)
            {
                break;
            }
        }
    }

    private bool CheckAuthRateLimit(int connId)
    {
        var now = DateTime.UtcNow;
        int windowSeconds = Options.AuthWindowSeconds;
        int maxAttempts = Options.MaxAuthAttemptsPerWindow;

        var entry = _authAttempts.GetOrAdd(connId, _ => (0, now));
        if ((now - entry.WindowStart).TotalSeconds > windowSeconds)
        {
            entry = (0, now);
        }

        entry.Attempts++;
        _authAttempts[connId] = entry;

        return entry.Attempts <= maxAttempts;
    }

    private async Task ProcessReceivedFrameAsync(SslClientSession session, Message2 frame)
    {
        // Filter out background heartbeat Ticks, Pings, and Pongs from status logs
        if (frame.MsgType != MessageType.Tick && frame.MsgType != MessageType.Ping && frame.MsgType != MessageType.Pong)
        {
            WriteLog($"Received frame from {session.User}: {frame}");
            OnTextReceivedEvent?.Invoke(this, new TextReceivedEventArgs(session.User.ToString(), frame.ToString(), frame));
        }

        // 1. Built-in Protocol Handlers
        switch (frame.MsgType)
        {
            case MessageType.Ping:
                string nonce = frame.GetArgument(0);
                string clientTimestamp = frame.GetArgument(1);

                // 1. Send PONG back IMMEDIATELY over socket first!
                await session.SendAsync(MessageType.Pong, nonce, clientTimestamp);

                // 2. Raise log events after packet is sent
                OnPingEvent?.Invoke(this, new PingEventArgs(nonce, isPong: false));
                break;

            case MessageType.UserRegister:
                if (!CheckAuthRateLimit(session.ConnId))
                {
                    await session.SendAsync(MessageType.RegisterResp, "FAIL", frame.GetArgument(0), "Too many authentication requests. Please wait 10 seconds.");
                    return;
                }

                string regEmail = frame.GetArgument(0);
                string regPass = frame.GetArgument(1);
                string regDisplayName = frame.GetArgument(2);
                string regErr = string.Empty;

                if (_userStore != null && _userStore.RegisterUser(regEmail, regPass, regDisplayName, out regErr))
                {
                    string assignedName = _userStore.GetDisplayName(regEmail);
                    // Do NOT auto-login. User remains anonymous until explicit /login.
                    await session.SendAsync(MessageType.RegisterResp, "SUCCESS", regEmail, assignedName, $"Registration successful! Please log in using: /login {regEmail} <password>");
                    WriteLog($"Client #{session.ConnId} registered account '{regEmail}'.");
                }
                else
                {
                    string err = _userStore == null ? "Authentication is disabled on this server." : regErr;
                    await session.SendAsync(MessageType.RegisterResp, "FAIL", regEmail, err);
                }
                break;

            case MessageType.UserLogin:
                if (!CheckAuthRateLimit(session.ConnId))
                {
                    await session.SendAsync(MessageType.LoginResp, "FAIL", frame.GetArgument(0), "Too many authentication requests. Please wait 10 seconds.");
                    return;
                }

                string loginEmail = frame.GetArgument(0);
                string loginPass = frame.GetArgument(1);
                string loginErr = string.Empty;

                if (_userStore != null && _userStore.ValidateUser(loginEmail, loginPass, out UserIdentifier authenticatedUser, out loginErr))
                {
                    session.User = authenticatedUser;
                    session.IsAuthenticated = true;
                    await session.SendAsync(MessageType.LoginResp, "SUCCESS", authenticatedUser.UserId, authenticatedUser.DisplayName);
                    WriteLog($"Client #{session.ConnId} authenticated as '{authenticatedUser}'.");
                }
                else
                {
                    string err = _userStore == null ? "Authentication is disabled on this server." : loginErr;
                    await session.SendAsync(MessageType.LoginResp, "FAIL", loginEmail, err);
                }
                break;

            case MessageType.UserLogout:
                session.IsAuthenticated = false;
                session.User = new UserIdentifier($"conn_{session.ConnId}", $"Anonymous@{session.ConnId}");
                await session.SendAsync(MessageType.LoginResp, "LOGOUT", "User logged out.");
                break;
        }

        // 2. Custom Protocol Extension Handlers
        int opcode = (int)frame.MsgType;
        if (_customHandlers.TryGetValue(opcode, out var handler))
        {
            try
            {
                await handler(session, frame);
            }
            catch (Exception ex)
            {
                WriteLog($"Error in custom handler for opcode {opcode}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Transmits a parsed <see cref="Message2"/> frame directly to a specific connected client session by connection ID.
    /// </summary>
    /// <param name="connId">Target client connection ID.</param>
    /// <param name="message">The message frame to transmit.</param>
    /// <returns><c>true</c> if the client session was found and frame was queued; otherwise <c>false</c>.</returns>
    public async Task<bool> SendToClientAsync(int connId, Message2 message)
    {
        if (_clients.TryGetValue(connId, out var session))
        {
            await session.SendAsync(message.MsgType, message.Arguments, message.BinaryPayload);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Transmits a message opcode with positional arguments directly to a specific connected client session by connection ID.
    /// </summary>
    /// <param name="connId">Target client connection ID.</param>
    /// <param name="msgType">The protocol opcode.</param>
    /// <param name="arguments">Positional string arguments.</param>
    /// <returns><c>true</c> if the client session was found and frame was queued; otherwise <c>false</c>.</returns>
    public async Task<bool> SendToClientAsync(int connId, MessageType msgType, params string[] arguments)
    {
        if (_clients.TryGetValue(connId, out var session))
        {
            await session.SendAsync(msgType, arguments);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Transmits a message opcode with positional arguments and binary payload directly to a specific connected client session by connection ID.
    /// </summary>
    /// <param name="connId">Target client connection ID.</param>
    /// <param name="msgType">The protocol opcode.</param>
    /// <param name="arguments">Positional string arguments.</param>
    /// <param name="binaryPayload">Raw binary payload data.</param>
    /// <returns><c>true</c> if the client session was found and frame was queued; otherwise <c>false</c>.</returns>
    public async Task<bool> SendToClientAsync(int connId, MessageType msgType, string[]? arguments, ReadOnlyMemory<byte> binaryPayload)
    {
        if (_clients.TryGetValue(connId, out var session))
        {
            await session.SendAsync(msgType, arguments, binaryPayload);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Broadcasts a message to all connected client sessions concurrently.
    /// </summary>
    public async Task BroadcastAsync(Message2 message)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(message.MsgType, message.Arguments, message.BinaryPayload.Span);
        var tasks = _clients.Values.Select(s => s.SendBytesAsync(frameBytes));
        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Broadcasts an opcode with positional arguments to all connected client sessions concurrently.
    /// </summary>
    public async Task BroadcastAsync(MessageType msgType, params string[] arguments)
    {
        byte[] frameBytes = PipelineFraming.FormatFrame(msgType, arguments);
        var tasks = _clients.Values.Select(s => s.SendBytesAsync(frameBytes));
        await Task.WhenAll(tasks);
    }

    private void WriteLog(string message, bool isError = false, Exception? exception = null)
    {
        string formatted = $"[SecureSocket.Server {DateTime.Now:HH:mm:ss}] {message}";

        if (isError && Options.ErrorAction != null)
        {
            Options.ErrorAction.Invoke(message, exception);
        }
        else if (Options.LogAction != null)
        {
            Options.LogAction.Invoke(message);
        }
        else if (_isVerbose)
        {
            Debug.WriteLine(formatted);
        }

        OnStatusEvent?.Invoke(this, new StatusEventArgs(formatted));
    }

    /// <summary>
    /// Stops the server listener and disposes server resources.
    /// </summary>
    public void Dispose()
    {
        StopListening();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Asynchronously stops server listener and disposes resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        StopListening();
        GC.SuppressFinalize(this);
        await Task.CompletedTask;
    }
}
