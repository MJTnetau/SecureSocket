namespace SecureSocket.Auth;

/// <summary>
/// Defines user authentication and persistence operations on the server.
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// Registers a new user account with a unique email address and password.
    /// </summary>
    /// <param name="email">Unique email address (used as primary UserId).</param>
    /// <param name="password">Plaintext password (will be hashed with PBKDF2).</param>
    /// <param name="displayName">Optional custom display name. Defaults to email prefix if null.</param>
    /// <param name="errorMessage">Out parameter explaining failure reason if registration fails.</param>
    /// <returns>True if registration succeeded; false otherwise.</returns>
    bool RegisterUser(string email, string password, string? displayName, out string errorMessage);

    /// <summary>
    /// Validates user credentials during login.
    /// </summary>
    /// <param name="email">User email address.</param>
    /// <param name="password">Plaintext password to verify.</param>
    /// <param name="user">Out parameter returning UserIdentifier if login succeeded.</param>
    /// <param name="errorMessage">Out parameter explaining failure reason if login fails.</param>
    /// <returns>True if login succeeded; false otherwise.</returns>
    bool ValidateUser(string email, string password, out UserIdentifier user, out string errorMessage);

    /// <summary>
    /// Updates the display name for a given user ID.
    /// </summary>
    bool UpdateDisplayName(string userId, string newDisplayName);

    /// <summary>
    /// Resolves the latest display name for a given user ID.
    /// </summary>
    string GetDisplayName(string userId);
}
