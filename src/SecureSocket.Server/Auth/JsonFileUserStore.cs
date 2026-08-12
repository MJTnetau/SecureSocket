using System.Collections.Concurrent;
using System.Text.Json;

namespace SecureSocket.Auth;

/// <summary>
/// Flat-file JSON user store extending InMemoryUserStore with disk persistence (users.json).
/// </summary>
public class JsonFileUserStore : IUserStore
{
    private class JsonUserDto
    {
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    private readonly string _filePath;
    private readonly object _fileLock = new();
    private readonly ConcurrentDictionary<string, JsonUserDto> _users = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of <see cref="JsonFileUserStore"/>.
    /// </summary>
    /// <param name="filePath">Target JSON file path for user storage.</param>
    public JsonFileUserStore(string filePath = "users.json")
    {
        _filePath = Path.GetFullPath(filePath);
        string? dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        LoadFromFile();
    }

    private void LoadFromFile()
    {
        lock (_fileLock)
        {
            if (!File.Exists(_filePath))
                return;

            try
            {
                string json = File.ReadAllText(_filePath);
                var dtos = JsonSerializer.Deserialize<List<JsonUserDto>>(json);
                if (dtos != null)
                {
                    _users.Clear();
                    foreach (var dto in dtos)
                    {
                        if (!string.IsNullOrWhiteSpace(dto.Email))
                        {
                            _users[dto.Email.Trim().ToLowerInvariant()] = dto;
                        }
                    }
                }
            }
            catch
            {
                // Fall back gracefully if file is empty or corrupted
            }
        }
    }

    /// <summary>Registers a user account in the JSON file user store.</summary>
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

        if (!UserStoreHelper.TrySanitizeDisplayName(displayName, cleanEmail, out string name, out errorMessage))
        {
            return false;
        }

        if (_users.Values.Any(u => string.Equals(u.DisplayName, name, StringComparison.OrdinalIgnoreCase)))
        {
            errorMessage = $"Registration failed. Display name '{name}' already exists.";
            return false;
        }

        var dto = new JsonUserDto
        {
            Email = cleanEmail,
            PasswordHash = PasswordHasher.HashPassword(password),
            DisplayName = name,
            CreatedAt = DateTime.UtcNow
        };

        if (!_users.TryAdd(cleanEmail, dto))
        {
            errorMessage = $"Registration failed. Account with email '{cleanEmail}' already exists. Please log in using: /login {cleanEmail} <password>";
            return false;
        }

        SaveToFile();
        return true;
    }

    /// <summary>Validates a user against JSON file records.</summary>
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

        if (!_users.TryGetValue(cleanEmail, out var dto))
        {
            errorMessage = "User account not found.";
            return false;
        }

        if (!PasswordHasher.VerifyPassword(password, dto.PasswordHash))
        {
            errorMessage = "Invalid password.";
            return false;
        }

        user = new UserIdentifier(dto.Email, dto.DisplayName);
        return true;
    }

    /// <summary>Updates display name in the JSON file user store.</summary>
    public bool UpdateDisplayName(string userId, string newDisplayName)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(newDisplayName))
            return false;

        string cleanEmail = userId.Trim().ToLowerInvariant();

        if (!UserStoreHelper.TrySanitizeDisplayName(newDisplayName, cleanEmail, out string cleanName, out _))
        {
            return false;
        }

        if (_users.Values.Any(u => !string.Equals(u.Email, cleanEmail, StringComparison.OrdinalIgnoreCase) && string.Equals(u.DisplayName, cleanName, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (_users.TryGetValue(cleanEmail, out var dto))
        {
            dto.DisplayName = cleanName;
            SaveToFile();
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
        if (_users.TryGetValue(cleanEmail, out var dto))
        {
            return dto.DisplayName;
        }

        return cleanEmail;
    }

    private void SaveToFile()
    {
        lock (_fileLock)
        {
            try
            {
                var list = _users.Values.ToList();
                string json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_filePath, json);
            }
            catch
            {
                // Ignore transient write exceptions
            }
        }
    }
}
