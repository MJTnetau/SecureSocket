using System.Collections.Concurrent;

namespace SecureSocket.Auth;

/// <summary>
/// In-memory thread-safe user store intended for rapid prototyping, unit testing, and sample applications.
/// Stores PBKDF2 salted password hashes in RAM.
/// </summary>
public class InMemoryUserStore : IUserStore
{
    private class UserRecord
    {
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>Checks whether a display name is reserved.</summary>
    public static bool IsReservedName(string name) => UserStoreHelper.IsReservedName(name);

    private readonly ConcurrentDictionary<string, UserRecord> _users = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Attempts to sanitize a display name input string.</summary>
    public static bool TrySanitizeDisplayName(string? inputName, string defaultEmail, out string sanitizedName, out string error) =>
        UserStoreHelper.TrySanitizeDisplayName(inputName, defaultEmail, out sanitizedName, out error);

    /// <summary>Registers a user in memory.</summary>
    public bool RegisterUser(string email, string password, string? displayName, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
        {
            errorMessage = "Invalid email address format. Email is required as username.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
        {
            errorMessage = "Password must be at least 4 characters long.";
            return false;
        }

        string cleanEmail = email.Trim().ToLowerInvariant();

        if (!TrySanitizeDisplayName(displayName, cleanEmail, out string name, out errorMessage))
        {
            return false;
        }

        if (_users.Values.Any(u => string.Equals(u.DisplayName, name, StringComparison.OrdinalIgnoreCase)))
        {
            errorMessage = $"Registration failed. Display name '{name}' already exists.";
            return false;
        }

        var record = new UserRecord
        {
            Email = cleanEmail,
            PasswordHash = PasswordHasher.HashPassword(password),
            DisplayName = name
        };

        if (!_users.TryAdd(cleanEmail, record))
        {
            errorMessage = $"Registration failed. Account with email '{cleanEmail}' already exists. Please log in using: /login {cleanEmail} <password>";
            return false;
        }

        return true;
    }

    /// <summary>Validates a user against in-memory user records.</summary>
    public bool ValidateUser(string email, string password, out UserIdentifier user, out string errorMessage)
    {
        user = UserIdentifier.Anonymous;
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "Email and password are required.";
            return false;
        }

        string cleanEmail = email.Trim().ToLowerInvariant();

        if (!_users.TryGetValue(cleanEmail, out var record))
        {
            errorMessage = "User account not found.";
            return false;
        }

        if (!PasswordHasher.VerifyPassword(password, record.PasswordHash))
        {
            errorMessage = "Invalid password.";
            return false;
        }

        user = new UserIdentifier(record.Email, record.DisplayName);
        return true;
    }

    /// <summary>Updates display name for an in-memory user record.</summary>
    public bool UpdateDisplayName(string userId, string newDisplayName)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(newDisplayName))
            return false;

        string cleanEmail = userId.Trim().ToLowerInvariant();
        string cleanName = newDisplayName.Trim();

        if (_users.Values.Any(u => !string.Equals(u.Email, cleanEmail, StringComparison.OrdinalIgnoreCase) && string.Equals(u.DisplayName, cleanName, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (_users.TryGetValue(cleanEmail, out var record))
        {
            record.DisplayName = cleanName;
            return true;
        }
        return false;
    }

    /// <summary>Gets the display name for a user ID.</summary>
    public string GetDisplayName(string userId)

    {
        if (string.IsNullOrWhiteSpace(userId))
            return "Unknown";

        string cleanEmail = userId.Trim().ToLowerInvariant();
        if (_users.TryGetValue(cleanEmail, out var record))
        {
            return record.DisplayName;
        }

        return userId;
    }
}
