# Changelog

All notable changes to **SecureSocket** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned / In Progress
- `Microsoft.Extensions.Logging` (`ILogger`) integration.
- Unit test suite for `PipelineFraming` wire protocol verification.
- CI/CD pipeline with GitHub Actions build automation.

---

## [1.1.0] - 2026-08-07

### Added
- **`IDisposable` & `IAsyncDisposable`**: Implemented on `Server`, `Client`, and `SslClientSession` for standard C# `using` / `await using` scope management.
- **`ServerOptions` & `ClientOptions`**: Strongly-typed configuration classes for server and client initialization, compatible with ASP.NET Core `IOptions<T>` binding.
- **`LogAction` & `ErrorAction` Callbacks**: Configurable logging delegates in `ServerOptions` and `ClientOptions` for routing diagnostic messages to custom logging frameworks.
- **`SendToClientAsync`**: Three overloads on `Server` for transmitting frames to a specific client session by connection ID.
- **`MaxRetryAttempts`**: Client option to cap automatic reconnection retries (0 = unlimited).
- **Configurable Rate Limiting**: `MaxAuthAttemptsPerWindow` and `AuthWindowSeconds` on `ServerOptions` now drive the actual rate limiting logic (previously hardcoded).
- **Configurable Frame Size Limit**: `MaxFrameSizeBytes` on `ServerOptions` is now passed through to `PipelineFraming.TryParseFrame` (previously hardcoded to 10 MB).

### Changed
- **Multi-Targeting**: Core libraries now target `net8.0;net10.0`. Sample projects target `net8.0`.
- **NuGet Package Metadata**: Complete `PackageId`, `Authors`, `Description`, `PackageTags`, `PackageLicenseExpression`, `RepositoryUrl`, and `PackageReadmeFile` configured across all core `.csproj` files.
- **`FormatFrame` Optimization**: Refactored to use `Utf8Formatter.TryFormat` directly into destination spans, eliminating `$""` string interpolations.
- **`IsRunning` / `_isClosed` / `_connected` / `_connecting`**: Loop control fields marked `volatile` for thread-safe cross-task reads.
- **`allowSelfSignedCerts` Validation**: Refined to permit only untrusted root chain errors (`RemoteCertificateChainErrors`). Hostname mismatches (`RemoteCertificateNameMismatch`) remain strictly rejected. Emits `[WARNING]` status log.
- **`StartListening` / `StartListeningAsync`**: Now defaults to `Options.Port` instead of hardcoded 20001 when no port parameter is specified.
- **`CertificateHelper`**: Uses `X509CertificateLoader` on .NET 9+ and `new X509Certificate2()` on .NET 8 via `#if NET9_0_OR_GREATER`.

### Fixed
- **Documentation Accuracy**: All four docs (`api-reference.md`, `architecture-and-protocol.md`, `authentication-and-security.md`, `getting-started.md`) rewritten to match actual source code API surfaces.
- **README `.NET` Badge**: Now correctly shows `.NET 8.0 | .NET 10.0`.
- **`InMemoryUserStore` Doc**: Removed false claim about pre-populated demo accounts.
- **SQLitePCLRaw Vulnerability**: Updated `Microsoft.Data.Sqlite` from 9.0.2 to 9.0.7 to resolve `NU1903` (GHSA-2m69-gcr7-jv3q).

### Added (Open Source)
- **MIT License**: [LICENSE](LICENSE) file added.
- **Changelog**: [CHANGELOG.md](CHANGELOG.md) following Keep a Changelog format.

---

## [1.0.0] - 2026-08-07

### Added
- **Zero-Allocation Pipeline Engine**: High-performance socket transport layer built on `.NET System.IO.Pipelines` (`PipeReader` / `PipeWriter`), `ReadOnlySequence<byte>`, and `Utf8Parser`.
- **Wire Protocol Framing**: Pipe-delimited UTF-8 header framing (`[MessageType]|[PayloadLength]|[Args]...\n`) coupled with raw binary payload stream framing.
- **TLS Security & Transport**: Built-in TLS encryption using `SslStream` with self-signed certificate generation support (`CertificateHelper`).
- **Pluggable Authentication**: `IUserStore` interface with concrete implementations:
  - `InMemoryUserStore` for rapid development and mock testing.
  - `JsonFileUserStore` for persistent file-backed user management.
  - `SqliteUserStore` for thread-safe relational database storage.
- **Password Security**: Standard PBKDF2 password hashing implementation (`PasswordHasher`).
- **Resilient Framing Guard**: Integrated payload size caps, tail delimiter guards, and auto-reconnect recovery routines.
- **Sample Projects**:
  - `samples/Basic`: Ping-pong latency telemetry measuring round-trip performance.
  - `samples/Chat`: IRC-style multi-room chat server and interactive CLI client.
- **Developer Documentation**: Complete documentation suite covering setup, architecture, security, and API reference in [`docs/`](docs/).
