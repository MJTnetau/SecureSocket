namespace SecureSocket;

/// <summary>
/// Event arguments raised when a client connects to the server.
/// </summary>
public class ClientConnectedEventArgs : EventArgs
{
    /// <summary>
    /// Gets the unique connection ID assigned by the server.
    /// </summary>
    public int ConnId { get; }

    /// <summary>
    /// Gets the user identity of the connected client.
    /// </summary>
    public UserIdentifier User { get; }

    /// <summary>
    /// Gets the timestamp when the connection occurred.
    /// </summary>
    public DateTime ConnectedAt { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="ClientConnectedEventArgs"/>.
    /// </summary>
    /// <param name="connId">The client connection ID.</param>
    /// <param name="user">The connected user identity.</param>
    public ClientConnectedEventArgs(int connId, UserIdentifier user)
    {
        ConnId = connId;
        User = user;
        ConnectedAt = DateTime.UtcNow;
    }
}

/// <summary>
/// Event arguments raised when a client disconnects from the server.
/// </summary>
public class ClientDisconnectEventArgs : EventArgs
{
    /// <summary>
    /// Gets the connection ID of the disconnected client.
    /// </summary>
    public int ConnId { get; }

    /// <summary>
    /// Gets the user identity of the disconnected client.
    /// </summary>
    public UserIdentifier User { get; }

    /// <summary>
    /// Gets the reason for disconnection.
    /// </summary>
    public string Reason { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="ClientDisconnectEventArgs"/>.
    /// </summary>
    /// <param name="connId">The client connection ID.</param>
    /// <param name="user">The user identity.</param>
    /// <param name="reason">The disconnection reason.</param>
    public ClientDisconnectEventArgs(int connId, UserIdentifier user, string reason = "Disconnected")
    {
        ConnId = connId;
        User = user;
        Reason = reason;
    }
}

/// <summary>
/// Event arguments raised when a text message or parsed packet is received.
/// </summary>
public class TextReceivedEventArgs : EventArgs
{
    /// <summary>
    /// Gets the sender identification string.
    /// </summary>
    public string SenderInfo { get; }

    /// <summary>
    /// Gets the text payload or formatted message.
    /// </summary>
    public string MessageText { get; }

    /// <summary>
    /// Gets the parsed Message2 frame if available.
    /// </summary>
    public Message2? Frame { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="TextReceivedEventArgs"/>.
    /// </summary>
    /// <param name="senderInfo">Identification of the sender.</param>
    /// <param name="messageText">The formatted message text.</param>
    /// <param name="frame">Optional parsed Message2 frame.</param>
    public TextReceivedEventArgs(string senderInfo, string messageText, Message2? frame = null)
    {
        SenderInfo = senderInfo;
        MessageText = messageText;
        Frame = frame;
    }
}

/// <summary>
/// Event arguments raised when a status update is logged.
/// </summary>
public class StatusEventArgs : EventArgs
{
    /// <summary>
    /// Gets the status message text.
    /// </summary>
    public string StatusMessage { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="StatusEventArgs"/>.
    /// </summary>
    /// <param name="statusMessage">The status update text.</param>
    public StatusEventArgs(string statusMessage)
    {
        StatusMessage = statusMessage;
    }
}

/// <summary>
/// Event arguments raised when log messages are generated.
/// </summary>
public class LogEventArgs : EventArgs
{
    /// <summary>
    /// Gets the internal log message text.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="LogEventArgs"/>.
    /// </summary>
    /// <param name="message">The internal log text.</param>
    public LogEventArgs(string message)
    {
        Message = message;
    }
}

/// <summary>
/// Event arguments raised when a Ping or Pong packet is processed.
/// </summary>
public class PingEventArgs : EventArgs
{
    /// <summary>
    /// Gets the ping/pong nonce string.
    /// </summary>
    public string Nonce { get; }

    /// <summary>
    /// Gets a value indicating whether this packet is a Pong reply.
    /// </summary>
    public bool IsPong { get; }

    /// <summary>
    /// Gets the measured round-trip latency in milliseconds.
    /// </summary>
    public double LatencyMs { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="PingEventArgs"/>.
    /// </summary>
    /// <param name="nonce">The nonce identifier.</param>
    /// <param name="isPong">True if pong reply; false if ping request.</param>
    /// <param name="latencyMs">Measured round-trip latency in milliseconds.</param>
    public PingEventArgs(string nonce, bool isPong, double latencyMs = 0)
    {
        Nonce = nonce;
        IsPong = isPong;
        LatencyMs = latencyMs;
    }
}

/// <summary>
/// Event arguments raised when a server heartbeat Tick is emitted.
/// </summary>
public class TickEventArgs : EventArgs
{
    /// <summary>
    /// Gets the current tick sequence counter.
    /// </summary>
    public int TickCount { get; }

    /// <summary>
    /// Gets the UTC timestamp when the tick was emitted.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="TickEventArgs"/>.
    /// </summary>
    /// <param name="tickCount">The tick sequence number.</param>
    /// <param name="timestamp">The tick timestamp.</param>
    public TickEventArgs(int tickCount, DateTime timestamp)
    {
        TickCount = tickCount;
        Timestamp = timestamp;
    }
}

/// <summary>
/// Event arguments raised for every raw message frame received (Raw Tap observation).
/// </summary>
public class RawFrameEventArgs : EventArgs
{
    /// <summary>
    /// Gets the sender identification string.
    /// </summary>
    public string SenderInfo { get; }

    /// <summary>
    /// Gets the raw parsed Message2 frame.
    /// </summary>
    public Message2 Frame { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="RawFrameEventArgs"/>.
    /// </summary>
    /// <param name="senderInfo">Identification of the sender.</param>
    /// <param name="frame">The raw parsed Message2 frame.</param>
    public RawFrameEventArgs(string senderInfo, Message2 frame)
    {
        SenderInfo = senderInfo;
        Frame = frame ?? throw new ArgumentNullException(nameof(frame));
    }
}


