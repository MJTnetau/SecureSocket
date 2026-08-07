# SecureSocket API Reference

This document provides complete API reference documentation for all public classes, methods, properties, and events in **SecureSocket**.

---

## `SecureSocket.Server`

The core TLS socket server managing incoming connections, authentication, tick heartbeats, and message routing.

### Constructors

```csharp
public Server(X509Certificate2 certificate, ServerOptions? options = null, IUserStore? userStore = null)
public Server(string certPathOrThumbprint, string? password = null, ServerOptions? options = null, IUserStore? userStore = null)
```

### Properties

| Property | Type | Access | Description |
| :--- | :--- | :--- | :--- |
| `Options` | `ServerOptions` | `get;` | Gets the strongly-typed server configuration options. |
| `IsRunning` | `bool` | `get;` | Returns `true` if server listener is active and processing connections. |
| `GetClientCount` | `int` | `get;` | Active count of connected clients in `Clients`. |
| `Clients` | `IReadOnlyDictionary<int, SslClientSession>` | `get;` | Dictionary of active client sessions indexed by connection ID (`ConnId`). |
| `GetInterval` | `int` | `get;` | Current tick heartbeat interval in milliseconds. |
| `GetLastTick` | `int` | `get;` | Counter value of the last emitted server tick. |
| `GetLastStopwatch` | `string` | `get;` | Elapsed execution time of the last tick cycle. |
| `IsVerbose` | `bool` | `get; set;` | Enables verbose diagnostic log outputs to `Debug` and `Status` event. |
| `UserStore` | `IUserStore?` | `get;` | Registered user store implementation. |

### Core Methods

```csharp
// Connection Listening
public Task StartListeningAsync(IPAddress? ip = null, int port = 20001, CancellationToken cancellationToken = default)
public void StartListening(IPAddress? ip = null, int port = 20001)
public void StopListening()

// Heartbeat Ticks
public void StartTicking(int intervalMs = 500)
public void StopTicking()

// Custom Message Handlers
public void RegisterHandler(MessageType msgType, Func<SslClientSession, Message2, Task> handler)
public void RegisterHandler(MessageType msgType, Action<SslClientSession, Message2> handler)
public void UnregisterHandler(MessageType msgType)

// Targeting Specific Clients
public Task<bool> SendToClientAsync(int connId, Message2 message)
public Task<bool> SendToClientAsync(int connId, MessageType msgType, params string[] arguments)
public Task<bool> SendToClientAsync(int connId, MessageType msgType, string[]? arguments, ReadOnlyMemory<byte> binaryPayload)

// Broadcasting
public Task BroadcastAsync(Message2 message)
public Task BroadcastAsync(MessageType msgType, params string[] arguments)
```

### Events

| Event | Backwards-Compatible Alias | Delegate Type | Description |
| :--- | :--- | :--- | :--- |
| `OnClientConnectedEvent` | `ClientConnected` | `EventHandler<ClientConnectedEventArgs>` | Raised when a client completes TLS handshake. |
| `OnClientDisconnectedEvent` | `ClientDisconnected` | `EventHandler<ClientDisconnectEventArgs>` | Raised when a client disconnects. |
| `OnTextReceivedEvent` | `TextReceived` | `EventHandler<TextReceivedEventArgs>` | Raised when a frame is received. |
| `OnStatusEvent` | `Status` | `EventHandler<StatusEventArgs>` | Raised when log/status messages are written. |
| `OnTickEvent` | `Tick` | `EventHandler<TickEventArgs>` | Raised on every heartbeat tick interval. |
| `OnPingEvent` | `Ping` | `EventHandler<PingEventArgs>` | Raised when a ping is received or pong processed. |

---

## `SecureSocket.SslClientSession`

Server-private representation of an active connected client session. Exposed via `server.Clients[connId]`.

### Properties

| Property | Type | Description |
| :--- | :--- | :--- |
| `ConnId` | `int` | Server-assigned unique connection ID (e.g., 101). |
| `User` | `UserIdentifier` | Public identity (`UserId` and `DisplayName`) of the session. |
| `RemoteEndPoint` | `IPEndPoint` | Remote IP address and port of the client socket. |
| `IsAuthenticated` | `bool` | True if client has logged in successfully. |
| `ConnectedAt` | `DateTime` | UTC timestamp when connection was established. |

### Methods

```csharp
public Task SendAsync(Message2 message)
public Task SendAsync(MessageType msgType, params string[] arguments)
public Task SendBytesAsync(ReadOnlyMemory<byte> frameBytes)
public void Close()
```

---

## `SecureSocket.Client`

The TLS socket client managing automated connection maintenance, authentication, and zero-allocation frame reading.

### Constructors

```csharp
public Client(ClientOptions? options = null)
public Client(string host, int port = 20001, bool allowSelfSignedCerts = false)
```

### Properties

| Property | Type | Description |
| :--- | :--- | :--- |
| `Options` | `ClientOptions` | Gets the strongly-typed client configuration options. |
| `IsConnected` | `bool` | Returns `true` if TLS socket is active. |
| `IsConnecting` | `bool` | Returns `true` if connection attempt is in progress. |
| `AutoReconnect` | `bool` | Enables automatic reconnection retries on disconnect. |
| `ServerIPAddress` | `IPAddress` | Resolved IP address of target server. |
| `ServerPort` | `int` | Target server port number. |
| `User` | `UserIdentifier` | Current user identity (defaults to `UserIdentifier.Anonymous`). |

### Methods

```csharp
// Lifecycle & Connection
public Task Connect()
public void Close()
public bool SetServerIPAddress(string serverAddress)
public bool SetPortNumber(int port)

// Authentication
public Task<(bool Success, string Message)> RegisterAsync(string email, string password, string? displayName = null)
public Task<(bool Success, string Message)> LoginAsync(string email, string password)
public Task LogoutAsync()

// Messaging
public Task SendMessageAsync(MessageType msgType, params string[] arguments)
public Task SendMessageAsync(MessageType msgType, string[] arguments, ReadOnlyMemory<byte> binaryPayload)
public Task SendBytesAsync(ReadOnlyMemory<byte> frameBytes)
public Task SendPingAsync(string? nonce = null)

// Custom Handlers
public void RegisterHandler(MessageType msgType, Action<Message2> handler)
public void UnregisterHandler(MessageType msgType)
```

### Events

| Event | Backwards-Compatible Alias | Delegate Type | Description |
| :--- | :--- | :--- | :--- |
| `OnServerConnectedEvent` | `ServerConnected` | `EventHandler<EventArgs>` | Raised on successful TLS connection. |
| `OnServerDisconnectedEvent` | `ServerDisconnected` | `EventHandler<EventArgs>` | Raised when connection to server drops. |
| `OnTextReceivedEvent` | `TextReceived` | `EventHandler<TextReceivedEventArgs>` | Raised when a message frame arrives. |
| `OnPingEvent` | `Ping` | `EventHandler<PingEventArgs>` | Raised on Ping/Pong events with latency. |
| `OnTickEvent` | `Tick` | `EventHandler<TickEventArgs>` | Raised on server tick broadcast. |
| `OnStatusEvent` | `Status` | `EventHandler<StatusEventArgs>` | Raised on client status changes. |
| `OnLogEvent` | `Log` | `EventHandler<LogEventArgs>` | Raised on internal log messages. |

---

## Data Structures

### `SecureSocket.Message2`

Represents a parsed wire frame containing header fields, arguments, and optional binary payload.

```csharp
public class Message2
{
    public MessageType MsgType { get; set; }
    public int MsgLength { get; set; }
    public string[] Arguments { get; set; }
    public ReadOnlyMemory<byte> BinaryPayload { get; set; }
    public UserIdentifier SenderUser { get; set; }
    public int Checksum { get; set; }

    public string GetArgument(int index)
    public override string ToString()
}
```

### `SecureSocket.UserIdentifier`

`record struct` representing public user identity.

```csharp
public record struct UserIdentifier
{
    public string UserId { get; init; }
    public string DisplayName { get; init; }

    public UserIdentifier(string userId, string? displayName = null)

    public static UserIdentifier Anonymous { get; }
    public static UserIdentifier System { get; }
}
```

### `SecureSocket.PipelineFraming`

Static utility class for zero-allocation wire framing format and parsing.

```csharp
public static class PipelineFraming
{
    public static int ComputeChecksum(ReadOnlySpan<byte> bytes)
    public static byte[] FormatFrame(MessageType msgType, string[]? arguments = null, ReadOnlySpan<byte> binaryPayload = default)
    public static bool TryParseFrame(ref ReadOnlySequence<byte> buffer, out Message2? message)
}
```

### `SecureSocket.CertificateHelper`

Static security helper for loading or generating TLS certificates.

```csharp
public static class CertificateHelper
{
    public static X509Certificate2 LoadCertificate(string pathOrThumbprint, string? password = null)
    public static X509Certificate2 CreateSelfSignedDevelopmentCertificate(string subjectName = "CN=localhost")
}
```

---

## Event Arguments Classes

- **`ClientConnectedEventArgs`**: `ConnId` (`int`), `User` (`UserIdentifier`), `ConnectedAt` (`DateTime`).
- **`ClientDisconnectEventArgs`**: `ConnId` (`int`), `User` (`UserIdentifier`), `Reason` (`string`).
- **`TextReceivedEventArgs`**: `SenderInfo` (`string`), `MessageText` (`string`), `Frame` (`Message2?`).
- **`StatusEventArgs`**: `StatusMessage` (`string`).
- **`LogEventArgs`**: `Message` (`string`).
- **`PingEventArgs`**: `Nonce` (`string`), `IsPong` (`bool`), `LatencyMs` (`double`).
- **`TickEventArgs`**: `TickCount` (`int`), `Timestamp` (`DateTime`).

---

## Configuration Options Classes

### `SecureSocket.ServerOptions`

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `IPAddress` | `IPAddress` | `IPAddress.Any` | Listening IP address. |
| `Port` | `int` | `20001` | Listening port number. |
| `TickIntervalMs` | `int` | `500` | Heartbeat tick interval in milliseconds. |
| `IsVerbose` | `bool` | `true` | Enables verbose diagnostic log outputs to `Debug` and `Status` event. |
| `MaxFrameSizeBytes` | `int` | `10485760` (10 MB) | Maximum allowed frame size in bytes. |
| `MaxAuthAttemptsPerWindow` | `int` | `5` | Maximum failed authentication attempts allowed per window. |
| `AuthWindowSeconds` | `int` | `10` | Rate limiting window duration in seconds. |
| `LogAction` | `Action<string>?` | `null` | Optional custom logging callback delegate for status and info messages. |
| `ErrorAction` | `Action<string, Exception?>?` | `null` | Optional custom logging callback delegate for warning and error messages. |

### `SecureSocket.ClientOptions`

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Host` | `string` | `"127.0.0.1"` | Target server host IP or domain name. |
| `Port` | `int` | `20001` | Target server listening port. |
| `AllowSelfSignedCerts` | `bool` | `false` | Set to `true` **ONLY** in development mode to accept untrusted/self-signed certificates. |
| `AutoReconnect` | `bool` | `true` | Enables automatic reconnection retries on disconnect. |
| `RetryDelayMs` | `int` | `3000` | Delay in milliseconds between connection retry attempts. |
| `MaxRetryAttempts` | `int` | `0` (unlimited) | Maximum number of connection retry attempts. |
| `LogAction` | `Action<string>?` | `null` | Optional custom logging callback delegate for status and info messages. |
| `ErrorAction` | `Action<string, Exception?>?` | `null` | Optional custom logging callback delegate for warning and error messages. |
