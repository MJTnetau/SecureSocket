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

## Framing Guards & Resiliency

To prevent memory exhaustion attacks and corrupted stream states:

1. **Max Frame Limit (10 MB Cap)**: `PipelineFraming.TryParseFrame` enforces a 10 MB maximum payload length safety guard.
2. **Checksum Integrity Guard**: Every frame validates `10=XXX|` checksum matching before parsing arguments. Corrupt frames throw framing exceptions and close the session cleanly.
3. **Low-Latency TCP Nagle Control**: Sockets set `NoDelay = true` to optimize immediate frame transmission.
