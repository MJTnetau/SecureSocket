# Authentication & Security Specification

**SecureSocket** provides built-in TLS encryption and an extensible user authentication system with pluggable user stores and PBKDF2 password hashing.

---

## TLS Certificate Setup

All communication in SecureSocket takes place over TLS encrypted sockets (`SslStream`).

> [!IMPORTANT]
> **Separation of Security Roles**:
> - **In-Flight Encryption & Cryptographic Integrity**: Managed entirely by **TLS (`SslStream`)**. TLS encrypts all passwords, user credentials, and application payload data across the wire, ensuring confidentiality and protection against tampering.
> - **Protocol Checksum (`10=XXX|`)**: Serves as a lightweight **framing delivery & sanity check** to confirm that full frame boundaries were received intact before parsing arguments and payloads.

### 1. Generating Development Certificates

For local development and testing, `CertificateHelper` can create self-signed X.509 certificates dynamically in memory:

```csharp
// Generate a self-signed development certificate for CN=localhost
X509Certificate2 cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");

// Instantiate server with certificate
var server = new SecureSocket.Server(cert);
```

### 2. Loading Certificates from File or Certificate Store

In production environments, load your certificate from a PFX file or Windows Certificate Store (`CurrentUser` or `LocalMachine`):

```csharp
// Load certificate from PFX file (password read from CERT_PASSWORD environment variable if omitted)
string certPath = "C:\\certificates\\server.pfx";
string password = Environment.GetEnvironmentVariable("CERT_PASSWORD") ?? "SecretPass";

var server = new SecureSocket.Server(certPath, password);
```

### 3. Client Certificate Validation

By default (`allowSelfSignedCerts = false`), clients strictly validate server certificates against trusted Root CAs. 

For local testing with self-signed development certificates, pass `allowSelfSignedCerts: true`:

```csharp
// Client constructor parameter allowSelfSignedCerts set to true for local testing
var client = new SecureSocket.Client("127.0.0.1", 20001, allowSelfSignedCerts: true);
```

> [!CAUTION]
> **Development vs. Production Certificate Validation Caveats**:
> - When `allowSelfSignedCerts: true`, the client permits untrusted certificate chain errors (`SslPolicyErrors.RemoteCertificateChainErrors`) and emits a `[WARNING]` status log.
> - **Hostname Mismatches (`RemoteCertificateNameMismatch`) and Missing Certificates (`RemoteCertificateNotAvailable`) remain strictly REJECTED** even when `allowSelfSignedCerts: true` is enabled.
> - **Production Deployment**: Always leave `allowSelfSignedCerts: false` (the default) in production environments to ensure complete TLS certificate chain and hostname validation.

---

## User Authentication Framework (`IUserStore`)

Defined in [IUserStore.cs](file:///c:/Dev/SecureSocket/src/SecureSocket.Server/Auth/IUserStore.cs):

```csharp
namespace SecureSocket.Auth;

public interface IUserStore
{
    bool RegisterUser(string email, string password, string? displayName, out string errorMessage);
    bool ValidateUser(string email, string password, out UserIdentifier user, out string errorMessage);
    bool UpdateDisplayName(string userId, string newDisplayName);
    string GetDisplayName(string userId);
}
```

### Built-in User Store Implementations

SecureSocket ships with 3 built-in `IUserStore` implementations:

| Store Class | Namespace | Best Used For | Features |
| :--- | :--- | :--- | :--- |
| **`InMemoryUserStore`** | `SecureSocket.Auth` | Unit tests & rapid prototypes | Fast thread-safe in-memory dictionary store. Starts empty — no disk persistence. |
| **`JsonFileUserStore`** | `SecureSocket.Auth` | Standalone tools & small apps | Persists users to a local `users.json` file. Automatic JSON serialization. |
| **`SqliteUserStore`** | `SecureSocket.Auth` | Production apps & services | Embedded SQLite database (`chat_users.db`). Parameterized SQL queries, indexing, and persistent user tables. |

---

## Password Hashing Security

`PasswordHasher` implements industry-standard **PBKDF2** (Password-Based Key Derivation Function 2) with HMAC-SHA256:

- **Salt**: 128-bit cryptographic random salt per user (`RandomNumberGenerator`).
- **Iterations**: 100,000 PBKDF2 hashing rounds.
- **Hash Output**: 256-bit derived key stored as Base64 string.
- **Constant-Time Verification**: Uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks.

```text
Password + 128-bit Salt ──► PBKDF2 (HMAC-SHA256, 100,000 rounds) ──► Stored Hash
```

---

## Client Authentication Workflow

### Server Configuration with User Store

Pass an `IUserStore` instance into the `Server` constructor:

```csharp
var userStore = new SqliteUserStore("app_users.db");
var server = new SecureSocket.Server(cert, userStore);

server.StartListening(port: 20001);
```

### Client User Registration & Login Requests

Authenticate clients asynchronously after connecting:

```csharp
var client = new SecureSocket.Client("127.0.0.1", 20001, allowSelfSignedCerts: true);
await client.Connect();

// 1. Register a new user account
var (regSuccess, regMsg) = await client.RegisterAsync("alice@example.com", "Password123!", "Alice");
Console.WriteLine($"Registration: {regMsg}");

// 2. Submit login credentials
var (loginSuccess, loginMsg) = await client.LoginAsync("alice@example.com", "Password123!");

if (loginSuccess)
{
    Console.WriteLine($"Authenticated successfully as: {client.User}");
}
else
{
    Console.WriteLine($"Authentication failed: {loginMsg}");
}

// 3. Logout
await client.LogoutAsync();
```

---

## Auth Rate Limiting Guard

The server automatically tracks authentication attempts per connection session ID:
- **Rate Limit Window**: Maximum 5 authentication requests per **10-second window** per connection.
- **Action**: Exceeding the rate limit returns failure response: `"Too many authentication requests. Please wait 10 seconds."`
