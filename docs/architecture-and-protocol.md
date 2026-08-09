# Architecture & Protocol Framing Specification

**SecureSocket** uses a high-performance, zero-allocation framing scheme built on `System.IO.Pipelines` designed for maximum throughput, low garbage collection overhead, and easy debugging.

> [!NOTE]
> **In-Flight Encryption vs. Header Readability**:
> All network traffic transmitted across the wire is encrypted in-flight using **TLS** (`SslStream`). The "human-readable" nature of the UTF-8 pipe-delimited headers (`MessageType|PayloadLength|ArgsCount|Arg0|...`) applies to application trace logs, server/client console output, debug loggers (`Message2.ToString()`), and decrypted stream diagnostics during development. This makes packet structures far easier to inspect and debug than opaque binary encodings, while binary payload sections (such as tick archives) remain unparsed raw byte streams.

---

## Wire Protocol Framing

Every packet transmitted across the TLS stream consists of a **Prefix Header** (`MessageType|PayloadLength|`) followed by an **Argument Section**, optional **Binary Payload**, and terminated by a **FIX-Style Checksum Tag** (`10=XXX|`).

```text
+-----------------------------------------------------------------------------------------------+
| MessageType | PayloadLength | ArgsCount | Arg0 | Arg1 | ... | BinaryPayload | 10=Checksum |
+-----------------------------------------------------------------------------------------------+
| <-- Prefix Header --------> | <-- Payload Section (Total Length = PayloadLength) ------------> |
```

### Wire Format Structure

The protocol fields are delimited by pipe ASCII characters (`|`, `0x7C`):

`MessageType|PayloadLength|ArgsCount|Arg0|Arg1|...|BinaryPayload|10=Checksum|`

| Field | Type | Description |
| :--- | :--- | :--- |
| **`MessageType`** | `int` | Opcode mapping to the `MessageType` enum. |
| **`PayloadLength`** | `int` | Total byte length of the payload section (from `ArgsCount|` up to and including `10=Checksum|`). Max frame limit: 10 MB. |
| **`ArgsCount`** | `int` | Count of URL-encoded string arguments in the frame. |
| **`Arg0..N`** | `string` | Positional string arguments escaped via `Uri.EscapeDataString()`. |
| **`BinaryPayload`** | `byte[]` | Optional raw binary bytes located after the last argument pipe. |
| **`10=Checksum|`** | `string` | 7-byte FIX-style checksum tag (`10=XXX|`) calculated as `(sum of byte values) % 256` over the payload content preceding `10=`. Serves as a framing sanity check to confirm complete delivery and alignment before parsing. (In-flight encryption and cryptographic integrity are provided by TLS). |

---

## Example Frame Wire Byte Layouts

### 1. Ping / Pong Frame

Sending ping request with nonce `"PING_999"` and timestamp `"638000000"` (Opcode 10 - `Ping`):

- Arguments: `PING_999`, `638000000` (ArgsCount = 2)
- Header: `10|36|2|PING_999|638000000|10=042|`

### 2. User Authentication Frame

Sending login request with email `"alice@example.com"` and password `"Pass123"` (Opcode 22 - `UserLogin`):

- Arguments: `alice%40example.com`, `Pass123` (ArgsCount = 2)
- Wire representation: `22|48|2|alice%40example.com|Pass123|10=189|`

### 3. Binary Payload Frame

Sending binary payload of 256 bytes with opcode `90` (`EMPTY`):

- Header: `90|265|0|` + `[256 Raw Binary Bytes]` + `10=120|`

---

## Zero-Allocation `System.IO.Pipelines` Architecture

Legacy socket implementations often allocate byte arrays (`byte[]`) for every packet read or written, triggering frequent Garbage Collection (GC) pauses. SecureSocket eliminates managed heap allocations during stream parsing by leveraging `.NET System.IO.Pipelines`:

```text
 NetworkStream (TLS SslStream)
        │
        ▼
   PipeReader ────► ReadAsync() ────► ReadOnlySequence<byte>
                                              │
                                              ├─ Utf8Parser (Zero-alloc integer parsing)
                                              ├─ ArrayPool<byte> (Rented buffers for multi-segment frames)
                                              └─ Slice() & AdvanceTo() (Zero-alloc memory view)
```

### Memory Efficiency Highlights

- **`PipeReader` & `PipeWriter`**: Direct socket stream framing without intermediate byte array allocations.
- **`ReadOnlySequence<byte>`**: Handles fragmented TCP buffers cleanly across block boundaries.
- **`Utf8Parser.TryParse`**: Parses opcodes and payload lengths directly from UTF-8 byte spans without allocating managed `string` objects.
- **`ArrayPool<byte>`**: Rents temporary buffers only when processing multi-segment sequence buffers, returning them safely in `finally` blocks.
- **`ReadOnlyMemory<byte>`**: Enables zero-copy binary payload representation on parsed `Message2` frames.

---

## Standard Message Opcodes (`MessageType`)

Defined in [`MessageType.cs`](../src/SecureSocket.Common/MessageType.cs):

| Opcode Range (`int`) | Enum Name | Description |
| :--- | :--- | :--- |
| `0..9` | `Illegal_0` .. `Illegal_9` | Reserved illegal range. Packets with these opcodes are rejected. |
| `10` | `Ping` | Connectivity ping containing nonce and timestamp string. |
| `11` | `Pong` | Ping reply returning nonce and timestamp string. |
| `12` | `Tick` | Server-emitted heartbeat tick counter and ISO timestamp. |
| `20` | `UserRegister` | Account registration request (`email`, `password`, `displayName`). |
| `21` | `RegisterResp` | Registration response status (`SUCCESS`/`FAIL`, message). |
| `22` | `UserLogin` | User authentication login request (`email`, `password`). |
| `23` | `LoginResp` | Authentication response status (`SUCCESS`/`FAIL`/`LOGOUT`, identity). |
| `24` | `UserLogout` | User logout request. |
| `90` | `EMPTY` | General purpose empty/text frame. |
| `91` | `ERROR` | System error notification frame. |
| `92` | `SystemNotice` | Server system notice broadcast. |
| `99` | `UNKNOWN` | Unknown or fallback opcode. |
| `100+` | Custom Opcodes | Application-defined custom message extensions (registered via `RegisterHandler`). |

---

## Custom Protocol Extensions & Message Routing (`RegisterHandler`)

Applications can extend the wire protocol with custom domain-specific message types without modifying the core `SecureSocket` library.

### Message Processing & Routing Pipeline

When a frame is received on the socket, it flows through a clean 4-stage pipeline:

```text
Incoming Socket Stream -> Message2 frame
       │
       ├──► Stage 1: Raw Tap (RawFrameReceived / OnRawFrameEvent) [Option 1]
       │             Fires for 100% of received frames (Tick, Ping, Custom, etc.) without consuming them.
       │
       ├──► Stage 2: Built-in Switch Handlers
       │             Handles built-in opcodes (Ping, Pong, Tick, RegisterResp, LoginResp).
       │
       ├──► Stage 3: Custom Handlers (_customHandlers)
       │             Executes domain handlers registered via RegisterHandler.
       │
       └──► Stage 4: Uncategorized Spillover (UncategorizedMessage / TextReceived) [Option 2]
                     Fires only if the frame was NOT handled in Stage 2 or Stage 3.
```

### Option 1: Raw Tap (`RawFrameReceived`)
To inspect every single packet on the stream (e.g. for full logging, telemetry, or raw packet capture):
```csharp
client.RawFrameReceived += (sender, e) => 
{
    Console.WriteLine($"[RAW TAP] {e.Frame.MsgType} | Payload: {e.Frame}");
};
```
*Note*: The raw tap is a non-consuming observation tap. It does not mark messages as read or prevent downstream handlers from running.

### Option 2: Categorized Handlers + Uncategorized Spillover
Register handlers for specific message types you are interested in. Any message type that is not handled by built-in cases or your custom handlers automatically spills over into `UncategorizedMessage` / `TextReceived`:

```csharp
// 1. Handle targeted custom opcodes
client.RegisterHandler((MessageType)TradeMessageType.ExecutionReport, msg => 
{
    Console.WriteLine($"Execution Report: {msg.GetArgument(0)}");
});

// 2. Capture any unhandled spillover messages
client.UncategorizedMessage += (sender, e) => 
{
    Console.WriteLine($"Uncategorized Message: {e.MessageText}");
};
```

### 1. Defining Custom Message Opcodes
Define an application-level `enum` backed by `int` using non-reserved opcode numbers (e.g. `80..89` or `100+`):

```csharp
public enum TradeMessageType : int
{
    NewOrder = 80,
    CancelOrder = 81,
    ExecutionReport = 82
}
```

### 2. Registering Server & Client Message Routers
Both `Server` and `Client` feature opcode routing via `RegisterHandler(...)`. Because both `MessageType` and your custom enum use `int` as their underlying type, cast your custom enum values directly to `MessageType`:

```csharp
// Server-side opcode routing
server.RegisterHandler((MessageType)TradeMessageType.NewOrder, OnNewOrder);
server.RegisterHandler((MessageType)TradeMessageType.CancelOrder, OnCancelOrder);

private async Task OnNewOrder(SslClientSession session, Message2 msg)
{
    string symbol = msg.GetArgument(0);
    string qty = msg.GetArgument(1);
    // Process new order...
}

// Client-side opcode routing
client.RegisterHandler((MessageType)TradeMessageType.ExecutionReport, msg => 
{
    string orderId = msg.GetArgument(0);
    string fillStatus = msg.GetArgument(1);
    Console.WriteLine($"Order {orderId} execution update: {fillStatus}");
});
```


### 3. Transmitting Custom Opcodes
Send custom opcodes using `SendMessageAsync`:

```csharp
await client.SendMessageAsync((MessageType)TradeMessageType.NewOrder, "BTCUSD", "1.5");
```

### 4. Combining String Arguments & Binary Payloads (Image Upload Example)
For messages requiring both metadata (like filename and MIME type) and raw binary data (like picture bytes), pass string arguments alongside a binary byte array:

```csharp
public enum MediaMessageType : int
{
    UploadImage = 105
}

// 1. Sender (Client): Read binary picture bytes and transmit metadata args + binary payload
byte[] imageBytes = File.ReadAllBytes("avatar.jpg");

await client.SendMessageAsync(
    (MessageType)MediaMessageType.UploadImage,
    new string[] { "avatar.jpg", "image/jpeg" }, // Positional metadata args
    imageBytes                                  // Raw binary payload
);

// 2. Receiver (Server): Register handler and process string metadata + binary bytes
server.RegisterHandler((MessageType)MediaMessageType.UploadImage, OnUploadImage);

private async Task OnUploadImage(SslClientSession session, Message2 msg)
{
    // Extract metadata arguments
    string filename = msg.GetArgument(0); // "avatar.jpg"
    string mimeType = msg.GetArgument(1); // "image/jpeg"

    if (msg.BinaryPayload.Length > 0)
    {
        // Save binary payload directly to disk or decode image
        string savePath = Path.Combine("uploads", filename);
        await File.WriteAllBytesAsync(savePath, msg.BinaryPayload.ToArray());
        Console.WriteLine($"Saved {filename} ({msg.BinaryPayload.Length} bytes) from {session.User}");
    }
}
```

---

## Framing Guards & Resiliency

To prevent memory exhaustion attacks and corrupted stream states:

1. **Max Frame Limit (10 MB Cap)**: `PipelineFraming.TryParseFrame` enforces a 10 MB maximum payload length safety guard.
2. **Checksum Integrity Guard**: Every frame validates `10=XXX|` checksum matching before parsing arguments. Corrupt frames throw framing exceptions and close the session cleanly.
3. **Low-Latency TCP Nagle Control**: Sockets set `NoDelay = true` to optimize immediate frame transmission.
