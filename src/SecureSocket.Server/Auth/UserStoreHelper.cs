using System.Text.RegularExpressions;

namespace SecureSocket.Auth;

/// <summary>
/// Provides shared validation and sanitization helpers for <see cref="IUserStore"/> implementations.
/// </summary>
public static class UserStoreHelper
{
    private static readonly HashSet<string> ReservedUsernames = new(StringComparer.OrdinalIgnoreCase)
    {
        "server", "system", "admin", "administrator", "root", "service", "bot", "anonymous"
    };

    /// <summary>
    /// Checks whether a given username or display name is reserved by the system.
    /// </summary>
    public static bool IsReservedName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        string clean = name.Trim();
        if (clean.StartsWith('[') && clean.EndsWith(']')) return true;
        return ReservedUsernames.Contains(clean);
    }

    /// <summary>
    /// Attempts to sanitize and validate a candidate display name.
    /// </summary>
    public static bool TrySanitizeDisplayName(string? inputName, string defaultEmail, out string sanitizedName, out string error)
    {
        error = string.Empty;
        sanitizedName = string.IsNullOrWhiteSpace(inputName) ? defaultEmail.Split('@')[0] : inputName.Trim();

        if (sanitizedName.Length < 2 || sanitizedName.Length > 30)
        {
            error = "Display name must be between 2 and 30 characters long.";
            return false;
        }

        if (!Regex.IsMatch(sanitizedName, @"^[a-zA-Z0-9_\-\s]+$"))
        {
            error = "Display name contains invalid characters. Only letters, numbers, spaces, hyphens, and underscores are allowed.";
            return false;
        }

        if (IsReservedName(sanitizedName))
        {
            error = $"The display name '{sanitizedName}' is reserved by the system.";
            return false;
        }

        return true;
    }
}
