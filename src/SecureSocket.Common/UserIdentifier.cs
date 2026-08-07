namespace SecureSocket;

/// <summary>
/// Represents a public user identity containing only UserId and DisplayName.
/// Does not leak IP addresses, socket descriptors, or server session state.
/// </summary>
public record struct UserIdentifier
{
    /// <summary>
    /// Gets the immutable, unique user ID across the network (e.g. email or user ID).
    /// </summary>
    public string UserId { get; init; }

    /// <summary>
    /// Gets or sets the dynamic display name chosen by the user.
    /// </summary>
    public string DisplayName { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserIdentifier"/> struct.
    /// </summary>
    public UserIdentifier(string userId, string? displayName = null)
    {
        UserId = userId ?? string.Empty;
        DisplayName = string.IsNullOrEmpty(displayName) ? UserId : displayName;
    }

    /// <summary>
    /// Gets an empty/anonymous UserIdentifier.
    /// </summary>
    public static UserIdentifier Anonymous => new UserIdentifier("anonymous", "Anonymous");

    /// <summary>
    /// Gets the official System/Server UserIdentifier reserved for system notices.
    /// </summary>
    public static UserIdentifier System => new UserIdentifier("SYSTEM", "[SERVER]");

    /// <summary>
    /// Converts the user identity to a readable string representation.
    /// </summary>
    public override readonly string ToString()
    {
        if (string.Equals(UserId, DisplayName, StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(DisplayName))
        {
            return UserId;
        }
        return $"{DisplayName} ({UserId})";
    }
}
