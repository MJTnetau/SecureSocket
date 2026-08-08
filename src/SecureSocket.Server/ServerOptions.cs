using System.Net;

namespace SecureSocket;

/// <summary>
/// Strongly-typed configuration options for initializing a <see cref="Server"/> instance.
/// </summary>
public class ServerOptions
{
    /// <summary>
    /// Listening IP address. Defaults to <see cref="IPAddress.IPv6Any"/> (::) to support dual-stack (IPv4 + IPv6).
    /// </summary>
    public IPAddress IPAddress { get; set; } = IPAddress.IPv6Any;

    /// <summary>
    /// Listening port number. Defaults to 20001.
    /// </summary>
    public int Port { get; set; } = 20001;

    /// <summary>
    /// Server heartbeat tick interval in milliseconds. Defaults to 500ms.
    /// </summary>
    public int TickIntervalMs { get; set; } = 500;

    /// <summary>
    /// Enables verbose diagnostic logging to Debug output and Status events. Defaults to <c>true</c>.
    /// </summary>
    public bool IsVerbose { get; set; } = true;

    /// <summary>
    /// Maximum allowed frame size in bytes. Defaults to 10 MB (10,485,760 bytes).
    /// </summary>
    public int MaxFrameSizeBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>
    /// Maximum failed authentication attempts allowed per connection window before rate-limiting. Defaults to 5.
    /// </summary>
    public int MaxAuthAttemptsPerWindow { get; set; } = 5;

    /// <summary>
    /// Rate limiting window duration in seconds. Defaults to 10 seconds.
    /// </summary>
    public int AuthWindowSeconds { get; set; } = 10;

    /// <summary>
    /// Optional custom logging callback delegate for status and diagnostic info messages.
    /// </summary>
    public Action<string>? LogAction { get; set; }

    /// <summary>
    /// Optional custom logging callback delegate for warning and error messages.
    /// </summary>
    public Action<string, Exception?>? ErrorAction { get; set; }
}
