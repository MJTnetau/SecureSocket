# SecureSocket

[![NuGet Version](https://img.shields.io/nuget/v/SecureSocket.svg)](https://www.nuget.org/packages/SecureSocket)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET 8.0 | .NET 10.0](https://img.shields.io/badge/dotnet-8.0%20%7C%2010.0-purple.svg)](https://dotnet.microsoft.com/)

**SecureSocket** is a modern, zero-allocation TLS networking library for .NET. Built on `System.IO.Pipelines`, it seamlessly fuses developer-friendly, human-readable UTF-8 wire headers with ultra-fast binary payload streaming—giving you high-throughput TLS encryption without compromising on memory efficiency or diagnostic transparency.

---

## Benefits & Key Features

- **Zero-Allocation Stream Parsing**: Built on `.NET System.IO.Pipelines` (`PipeReader` / `PipeWriter`), `ReadOnlySequence<byte>`, and `Utf8Parser` to achieve $O(1)$ stream reading without managed heap Garbage Collection (GC) pressure.
- **Human-Readable UTF-8 Wire Framing**: Uses pipe-delimited UTF-8 headers (`[MessageType]|[PayloadLength]|[Args]...\n`) that are easy to parse and human-readable in server console logs, diagnostic outputs, and trace loggers, while preserving raw binary data payloads.
- **Raw Binary Payload Streaming**: Seamlessly transmits binary struct payloads (such as historical candles or market tick archives) alongside header metadata without payload serialization overhead.
- **Auto-Generated Dev Certificates with SANs**: Automatically creates and persists self-signed `.pfx` certificates containing Subject Alternative Names (`localhost`, `127.0.0.1`, `::1`) when loading non-existent `.pfx` file paths.
- **Dual-Stack Socket Listening**: Out-of-the-box support for simultaneous IPv4 (`127.0.0.1`) and IPv6 (`::1`) connections via `IPAddress.IPv6Any` and `DualMode` socket listeners.
- **Built-In Authentication & Security**: Complete TLS (`SslStream`) transport security with modular `IUserStore` implementations (`InMemoryUserStore`, `JsonFileUserStore`, `SqliteUserStore`) and industry-standard PBKDF2 password hashing.
- **Resilient Framing Guard & Auto-Recovery**: Includes tail validation guards, max message size caps, and automatic 50ms stream reconnect recovery.
- **Idiomatic Developer API**: Rich C# event model (`ClientConnected`, `TextReceived`, `Ping`, `Tick`, `Status`) and custom message opcode extension handlers via `RegisterHandler`.

---

## Developer Quickstart

**Prerequisites**: [.NET 8.0 SDK](https://dotnet.microsoft.com/) or higher (supports .NET 8.0 LTS & .NET 10.0).

Include **SecureSocket** in your C# project via project reference:

```xml
<ItemGroup>
  <ProjectReference Include="..\SecureSocket.Client\SecureSocket.Client.csproj" />
  <ProjectReference Include="..\SecureSocket.Server\SecureSocket.Server.csproj" />
</ItemGroup>
```

### Barebones 3-Line Snippets

#### Server Quickstart (3 Lines)

```csharp
var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");
var server = new SecureSocket.Server(cert);
server.StartListening(20001);
```

#### Client Quickstart (3 Lines)

```csharp
var client = new SecureSocket.Client("127.0.0.1", 20001, allowSelfSignedCerts: true);
client.OnTextReceivedEvent += (s, e) => Console.WriteLine($"Received: {e.MessageText}");
await client.Connect();
```

---

### Advanced Configuration Options

#### Server with `ServerOptions`

```csharp
var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");
var options = new ServerOptions
{
    Port = 20001,
    TickIntervalMs = 1000,
    MaxFrameSizeBytes = 5 * 1024 * 1024, // 5 MB max frame cap
    MaxAuthAttemptsPerWindow = 5,
    LogAction = msg => Console.WriteLine($"[LOG] {msg}"),
    ErrorAction = (msg, ex) => Console.WriteLine($"[ERROR] {msg} {ex?.Message}")
};

using var server = new SecureSocket.Server(cert, options);
server.StartListening();
```

#### Client with `ClientOptions`

```csharp
var options = new ClientOptions
{
    Host = "127.0.0.1",
    Port = 20001,
    AllowSelfSignedCerts = true,
    AutoReconnect = true,
    RetryDelayMs = 2000,
    LogAction = msg => Console.WriteLine($"[CLIENT LOG] {msg}"),
    ErrorAction = (msg, ex) => Console.WriteLine($"[CLIENT ERROR] {msg} {ex?.Message}")
};

using var client = new SecureSocket.Client(options);
client.OnTextReceivedEvent += (s, e) => Console.WriteLine($"Received: {e.MessageText}");
await client.Connect();
```

---

## Included Samples

The repository includes runnable sample projects in the [`samples/`](samples) directory illustrating common architecture patterns:

### 1. Basic Anonymous Ping & Telemetry Sample (`samples/Basic`)
- **[Basic.Server](samples/Basic/Server)**: Initializes an anonymous TLS server using self-signed development certificates, emitting 1-second server heartbeat ticks and displaying live console telemetry.
- **[Basic.Client](samples/Basic/Client)**: Connects anonymously, sends periodic ping nonces, and measures round-trip latency (displaying immediate latency and 10-tick rolling averages in the console title bar).

### 2. Multi-User IRC Chat Application (`samples/Chat`)
- **[Chat.Server](samples/Chat/Server)**: Hosts a full-featured IRC-style chat server backed by an embedded SQLite user database (`SqliteUserStore` with PBKDF2 password hashing). Demonstrates custom opcode registration (`RegisterHandler`), multi-room channel broadcasting, user state management, and direct messaging.
- **[Chat.Client](samples/Chat/Client)**: Interactive CLI chat client supporting user registration (`/register`), authentication (`/login`), joining/leaving channels (`/join`, `/leave`), direct messaging (`/msg`), and online user lists (`/who`).

---

## Documentation

Full developer guides, architectural deep-dives, security specs, and API references are available in the **[`docs/`](docs/README.md)** directory:

- **[docs/getting-started.md](docs/getting-started.md)**: Comprehensive quickstart guide for setup, TLS certificates, and client/server event handling.
- **[docs/architecture-and-protocol.md](docs/architecture-and-protocol.md)**: Wire protocol specification, framing field diagrams, zero-allocation `System.IO.Pipelines` architecture, and opcode mapping.
- **[docs/authentication-and-security.md](docs/authentication-and-security.md)**: TLS certificate configuration, user store implementations (`InMemory`, `Json`, `SQLite`), and PBKDF2 password security.
- **[docs/api-reference.md](docs/api-reference.md)**: Detailed API reference for `SecureSocket.Server`, `SecureSocket.Client`, `Message2`, `UserIdentifier`, and events.

---

## License

Distributed under the [MIT License](LICENSE).
