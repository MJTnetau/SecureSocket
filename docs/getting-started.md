# Getting Started with SecureSocket

This guide walks you through setting up a **SecureSocket** server and client, configuring TLS certificates, and transmitting messages.

---

## Installation & Package Reference

**Prerequisites**: [.NET 8.0 SDK](https://dotnet.microsoft.com/) or higher.

### Target Frameworks & Multi-Targeting
The **SecureSocket** core libraries multi-target **`.NET 8.0 LTS`** and **`.NET 10.0`** (`<TargetFrameworks>net8.0;net10.0</TargetFrameworks>`):
- **On .NET 8.0**: The libraries automatically include the `System.IO.Pipelines` NuGet package (v8.0.0) and use standard `X509Certificate2` certificate loading.
- **On .NET 9+ / .NET 10.0**: The libraries leverage base framework `System.IO.Pipelines` and native `X509CertificateLoader` APIs.
- **Sample Applications**: Sample projects in `samples/` target `.NET 8.0` for out-of-the-box compatibility across standard developer environments.

Include `SecureSocket` projects directly in your solution:

```xml
<ItemGroup>
  <ProjectReference Include="..\SecureSocket.Client\SecureSocket.Client.csproj" />
  <ProjectReference Include="..\SecureSocket.Server\SecureSocket.Server.csproj" />
</ItemGroup>
```

---

## 3-Line Quickstart

### Server Quickstart

```csharp
var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");
var server = new SecureSocket.Server(cert);
server.StartListening(port: 20001);
```

### Client Quickstart

```csharp
var client = new SecureSocket.Client("127.0.0.1", 20001, allowSelfSignedCerts: true);
client.OnTextReceivedEvent += (s, e) => Console.WriteLine($"Received: {e.MessageText}");
await client.Connect();
```

---

## Configuration Options (`ServerOptions` & `ClientOptions`)

`SecureSocket` provides strongly-typed configuration classes for fine-grained control over listening ports, TLS certificates, frame limits, rate-limiting, and reconnection behavior:

### 1. Server Configuration (`ServerOptions`)

#### Quickstart Default Constructor

```csharp
// Quickstart default (port 20001, 500ms ticks, 10 MB frame cap)
var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");
using var server = new SecureSocket.Server(cert);
server.StartListening(port: 20001);
```

#### Advanced Server Configuration with `ServerOptions` & Production Certificate

```csharp
// 1. Load certificate from PFX file or Certificate Store (auto-generates .pfx with SANs if path does not exist)
X509Certificate2 cert = CertificateHelper.LoadCertificate("C:\\certs\\server.pfx", "SecretPass");

// 2. Configure server options
var options = new ServerOptions
{
    IPAddress = IPAddress.IPv6Any,        // Dual-stack listening on IPv4 (127.0.0.1) & IPv6 (::1)
    Port = 20002,                         // Custom listening port
    TickIntervalMs = 1000,                // 1-second server heartbeat tick interval
    IsVerbose = true,                      // Enable status diagnostic logging
    MaxFrameSizeBytes = 5 * 1024 * 1024,  // 5 MB max frame payload limit
    MaxAuthAttemptsPerWindow = 5,         // Max 5 login/register attempts per IP window
    AuthWindowSeconds = 10,               // 10-second rate-limiting window
    LogAction = msg => MyLogger.LogInfo(msg),                 // Custom log callback
    ErrorAction = (msg, ex) => MyLogger.LogError(msg, ex)     // Custom error callback
};

// 3. Instantiate server with options and optional user store
using var server = new SecureSocket.Server(cert, options, userStore: null);
server.StartListening();
```

---

### 2. Client Configuration (`ClientOptions`)

#### Quickstart Default Constructor

```csharp
// Quickstart default targeting 127.0.0.1:20001
using var client = new SecureSocket.Client("127.0.0.1", port: 20001, allowSelfSignedCerts: true);
await client.Connect();
```

#### Advanced Client Configuration with `ClientOptions`

```csharp
// Configure client connection and retry policies
var options = new ClientOptions
{
    Host = "192.168.1.50",               // Target server hostname or IP address
    Port = 20002,                         // Target server listening port
    AllowSelfSignedCerts = false,         // Strict Root CA certificate validation (Production)
    AutoReconnect = true,                // Enable automatic reconnect on drop
    RetryDelayMs = 2000,                  // Wait 2 seconds between retry attempts
    MaxRetryAttempts = 10,                // Maximum 10 retry attempts (0 = infinite)
    LogAction = msg => MyLogger.LogInfo(msg),                 // Custom log callback
    ErrorAction = (msg, ex) => MyLogger.LogError(msg, ex)     // Custom error callback
};

using var client = new SecureSocket.Client(options);
client.OnServerConnectedEvent += (s, e) => Console.WriteLine("Connected to server!");
client.OnServerDisconnectedEvent += (s, e) => Console.WriteLine("Disconnected from server.");

await client.Connect();
```

---

## Complete Server Example

The following example initializes a TLS server, attaches event listeners, starts periodic heartbeats (ticks), and handles incoming client messages:

```csharp
using System;
using System.Threading.Tasks;
using SecureSocket;

class ServerProgram
{
    static async Task Main(string[] args)
    {
        // 1. Generate or load a TLS certificate
        var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");

        // 2. Instantiate the server
        var server = new SecureSocket.Server(cert);

        // 3. Register event handlers
        server.OnClientConnectedEvent += (s, e) => 
            Console.WriteLine($"[+] Client #{e.ConnId} connected from user: {e.User}");

        server.OnClientDisconnectedEvent += (s, e) => 
            Console.WriteLine($"[-] Client #{e.ConnId} disconnected: {e.Reason}");

        server.OnTextReceivedEvent += (s, e) => 
            Console.WriteLine($"[Msg] {e.SenderInfo}: {e.MessageText}");

        // 4. Start listening on port 20001 and enable tick heartbeats (every 1000ms)
        server.StartListening(port: 20001);
        server.StartTicking(intervalMs: 1000);

        Console.WriteLine("Server listening on port 20001. Press ENTER to stop.");
        Console.ReadLine();

        server.StopListening();
    }
}
```

---

## Complete Client Example

The following example connects to the TLS server, sends messages, measures latency via pings, and handles disconnection:

```csharp
using System;
using System.Threading.Tasks;
using SecureSocket;

class ClientProgram
{
    static async Task Main(string[] args)
    {
        // 1. Instantiate client pointing to server address and port
        var client = new SecureSocket.Client("127.0.0.1", port: 20001, allowSelfSignedCerts: true);

        // 2. Register event handlers
        client.OnServerConnectedEvent += (s, e) => Console.WriteLine("Connected to TLS Server!");
        client.OnTextReceivedEvent += (s, e) => Console.WriteLine($"Received: {e.MessageText}");
        client.OnPingEvent += (s, e) => 
        {
            if (e.IsPong)
                Console.WriteLine($"Pong received! Round-trip latency: {e.LatencyMs:F2} ms");
        };

        // 3. Connect to server
        await client.Connect();

        // 4. Send message frame and ping
        await client.SendMessageAsync(MessageType.EMPTY, "Hello from SecureSocket Client!");
        await client.SendPingAsync("PING_NONCE_123");

        await Task.Delay(2000);
        client.Close();
    }
}
```

---

## Custom Message Types & Opcode Routing (`RegisterHandler`)

Applications can define custom message opcodes outside the built-in ranges (e.g. `80..89` or `100+`) and register routing handlers on both `Server` and `Client`:

```csharp
// 1. Define custom opcode enum
public enum AppMessageType : int
{
    CustomData = 80
}

// 2. Register server-side handler router
server.RegisterHandler((MessageType)AppMessageType.CustomData, async (session, msg) => 
{
    string data = msg.GetArgument(0);
    Console.WriteLine($"Received CustomData from {session.User}: {data}");
});

// 3. Register client-side handler router
client.RegisterHandler((MessageType)AppMessageType.CustomData, msg => 
{
    string data = msg.GetArgument(0);
    Console.WriteLine($"Client received CustomData: {data}");
});

// 4. Send custom opcode
await client.SendMessageAsync((MessageType)AppMessageType.CustomData, "Payload text argument");
```

### Transmitting Metadata Arguments + Binary Payloads (Image Upload)

```csharp
// Send filename metadata arg + raw image bytes in binary payload
byte[] imageBytes = File.ReadAllBytes("photo.jpg");
await client.SendMessageAsync(
    (MessageType)AppMessageType.UploadImage, 
    new string[] { "photo.jpg", "image/jpeg" }, 
    imageBytes
);

// Server handler extracts metadata and saves binary payload
server.RegisterHandler((MessageType)AppMessageType.UploadImage, async (session, msg) =>
{
    string filename = msg.GetArgument(0);
    byte[] payload = msg.BinaryPayload.ToArray();
    await File.WriteAllBytesAsync(Path.Combine("uploads", filename), payload);
});
```

---

## Next Steps

- Explore [Architecture & Protocol Framing](architecture-and-protocol.md) to understand wire frame layouts and high-throughput zero-allocation stream parsing.
- Read [Authentication & Security](authentication-and-security.md) to enable SQLite/JSON user databases and PBKDF2 authentication.
- Check out [API Reference](api-reference.md) for full method and event descriptions.
