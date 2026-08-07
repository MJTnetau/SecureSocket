namespace SecureSocket;

/// <summary>
/// Strongly-typed configuration options for initializing a <see cref="Client"/> instance.
/// </summary>
public class ClientOptions
{
    /// <summary>
    /// Target server host IP or domain name. Defaults to "127.0.0.1".
    /// </summary>
    public string Host { get; set; } = "127.0.0.1";

    /// <summary>
    /// Target server listening port. Defaults to 20001.
    /// </summary>
    public int Port { get; set; } = 20001;

    /// <summary>
    /// Set to <c>true</c> ONLY in development mode to accept untrusted/self-signed certificates. Defaults to <c>false</c>.
    /// </summary>
    public bool AllowSelfSignedCerts { get; set; } = false;

    /// <summary>
    /// Enables automatic reconnection retries on disconnect. Defaults to <c>true</c>.
    /// </summary>
    public bool AutoReconnect { get; set; } = true;

    /// <summary>
    /// Delay in milliseconds between connection retry attempts. Defaults to 3000ms.
    /// </summary>
    public int RetryDelayMs { get; set; } = 3000;

    /// <summary>
    /// Maximum number of connection retry attempts (0 = unlimited). Defaults to 0.
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 0;

    /// <summary>
    /// Optional custom logging callback delegate for status and diagnostic info messages.
    /// </summary>
    public Action<string>? LogAction { get; set; }

    /// <summary>
    /// Optional custom logging callback delegate for warning and error messages.
    /// </summary>
    public Action<string, Exception?>? ErrorAction { get; set; }
}
