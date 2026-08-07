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
    public string StatusMessage { get; }

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
    public string Message { get; }

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
    public string Nonce { get; }
    public bool IsPong { get; }
    public double LatencyMs { get; }

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
    public int TickCount { get; }
    public DateTime Timestamp { get; }

    public TickEventArgs(int tickCount, DateTime timestamp)
    {
        TickCount = tickCount;
        Timestamp = timestamp;
    }
}
