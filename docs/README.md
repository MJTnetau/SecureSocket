# SecureSocket Documentation

Welcome to the **SecureSocket** documentation. SecureSocket is a high-performance C# TLS socket framework built on `.NET System.IO.Pipelines`.

## Documentation Index

- **[Getting Started](getting-started.md)**: Quickstart guide for setting up server and client instances, configuring TLS certificates, and sending/receiving messages.
- **[Architecture & Protocol Framing](architecture-and-protocol.md)**: Specification of the UTF-8 pipe-delimited header layout, zero-allocation stream parsing with `System.IO.Pipelines`, FIX-style checksum calculation, and binary payload streaming.
- **[Authentication & Security](authentication-and-security.md)**: Guide on TLS certificates, PBKDF2 password hashing, auth rate-limiting, and `IUserStore` implementations (`InMemoryUserStore`, `JsonFileUserStore`, `SqliteUserStore`).
- **[API Reference](api-reference.md)**: Comprehensive API reference for `SecureSocket.Server`, `SecureSocket.SslClientSession`, `SecureSocket.Client`, events, data structures (`Message2`, `UserIdentifier`), and custom message handlers (`RegisterHandler`).

---

## Quick Navigation

| Document | Description |
| :--- | :--- |
| [Getting Started](getting-started.md) | Setup, initialization, basic sending & receiving. |
| [Architecture & Protocol](architecture-and-protocol.md) | Wire format, memory management, `System.IO.Pipelines`, opcodes. |
| [Authentication & Security](authentication-and-security.md) | TLS certs, SQLite user store, PBKDF2 authentication, rate limits. |
| [API Reference](api-reference.md) | Full class and event specifications for client, server, and common utilities. |
