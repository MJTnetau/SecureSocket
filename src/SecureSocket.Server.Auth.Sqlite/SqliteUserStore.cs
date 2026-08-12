using Microsoft.Data.Sqlite;

namespace SecureSocket.Auth;

/// <summary>
/// Recommended production user store backed by an SQLite database file (users.db).
/// Automatically creates the table schema (CREATE TABLE IF NOT EXISTS Users...) on startup.
/// Stores PBKDF2 salted password hashes (HMAC-SHA256, 128-bit salt, 100,000 iterations).
/// </summary>
public class SqliteUserStore : IUserStore
{
    private readonly string _connectionString;
    private readonly SemaphoreSlim _dbLock = new(1, 1);

    /// <summary>
    /// Initializes a new instance of <see cref="SqliteUserStore"/> with target database file path.
    /// </summary>
    /// <param name="dbPath">Database file path (e.g. "users.db" or "Data/users.db").</param>
    public SqliteUserStore(string dbPath = "users.db")
    {
        string fullPath = Path.GetFullPath(dbPath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ConnectionString;

        InitializeDatabaseSchema();
    }

    private void InitializeDatabaseSchema()
    {
        _dbLock.Wait();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            string createTableSql = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Email TEXT PRIMARY KEY NOT NULL,
                    PasswordHash TEXT NOT NULL,
                    DisplayName TEXT NOT NULL,
                    CreatedAt TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS UX_Users_DisplayName ON Users(DisplayName COLLATE NOCASE);";

            using var command = new SqliteCommand(createTableSql, connection);
            command.ExecuteNonQuery();
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <summary>Checks whether a display name is reserved.</summary>
    public static bool IsReservedName(string name) => UserStoreHelper.IsReservedName(name);

    /// <summary>Attempts to sanitize a display name input string.</summary>
    public static bool TrySanitizeDisplayName(string? inputName, string defaultEmail, out string sanitizedName, out string error) =>
        UserStoreHelper.TrySanitizeDisplayName(inputName, defaultEmail, out sanitizedName, out error);

    /// <summary>Registers a new user account with hashed password in SQLite.</summary>
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

        string hash = PasswordHasher.HashPassword(password);
        string createdAt = DateTime.UtcNow.ToString("o");

        _dbLock.Wait();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            // Explicit Duplicate Display Name Check
            string checkNameSql = "SELECT COUNT(*) FROM Users WHERE LOWER(DisplayName) = LOWER(@DisplayName);";
            using (var checkCmd = new SqliteCommand(checkNameSql, connection))
            {
                checkCmd.Parameters.AddWithValue("@DisplayName", name);
                long count = (long)(checkCmd.ExecuteScalar() ?? 0L);
                if (count > 0)
                {
                    errorMessage = $"Registration failed. Display name '{name}' already exists.";
                    return false;
                }
            }

            // Explicit Duplicate Email Check
            string checkSql = "SELECT COUNT(*) FROM Users WHERE Email = @Email;";
            using (var checkCmd = new SqliteCommand(checkSql, connection))
            {
                checkCmd.Parameters.AddWithValue("@Email", cleanEmail);
                long count = (long)(checkCmd.ExecuteScalar() ?? 0L);
                if (count > 0)
                {
                    errorMessage = $"Registration failed. Account with email '{cleanEmail}' already exists. Please log in using: /login {cleanEmail} <password>";
                    return false;
                }
            }

            string insertSql = @"
                INSERT INTO Users (Email, PasswordHash, DisplayName, CreatedAt)
                VALUES (@Email, @PasswordHash, @DisplayName, @CreatedAt);";

            using var command = new SqliteCommand(insertSql, connection);
            command.Parameters.AddWithValue("@Email", cleanEmail);
            command.Parameters.AddWithValue("@PasswordHash", hash);
            command.Parameters.AddWithValue("@DisplayName", name);
            command.Parameters.AddWithValue("@CreatedAt", createdAt);

            command.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // Primary Key constraint
        {
            errorMessage = $"Registration failed. Account with email '{cleanEmail}' already exists. Please log in using: /login {cleanEmail} <password>";
            return false;
        }
        catch (Exception ex)
        {
            errorMessage = $"Database error registering user: {ex.Message}";
            return false;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <summary>Validates a user login request against stored hash.</summary>
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

        _dbLock.Wait();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            string selectSql = "SELECT PasswordHash, DisplayName FROM Users WHERE Email = @Email LIMIT 1;";
            using var command = new SqliteCommand(selectSql, connection);
            command.Parameters.AddWithValue("@Email", cleanEmail);

            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                errorMessage = "User account not found.";
                return false;
            }

            string storedHash = reader.GetString(0);
            string displayName = reader.GetString(1);

            if (!PasswordHasher.VerifyPassword(password, storedHash))
            {
                errorMessage = "Invalid password.";
                return false;
            }

            user = new UserIdentifier(cleanEmail, displayName);
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"Database error validating user: {ex.Message}";
            return false;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <summary>Updates the display name for a registered user.</summary>
    public bool UpdateDisplayName(string userId, string newDisplayName)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(newDisplayName))
            return false;

        string cleanEmail = userId.Trim().ToLowerInvariant();

        if (!TrySanitizeDisplayName(newDisplayName, cleanEmail, out string cleanName, out _))
        {
            return false;
        }

        _dbLock.Wait();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            string checkNameSql = "SELECT COUNT(*) FROM Users WHERE LOWER(DisplayName) = LOWER(@DisplayName) AND LOWER(Email) <> LOWER(@Email);";
            using (var checkCmd = new SqliteCommand(checkNameSql, connection))
            {
                checkCmd.Parameters.AddWithValue("@DisplayName", cleanName);
                checkCmd.Parameters.AddWithValue("@Email", cleanEmail);
                long count = (long)(checkCmd.ExecuteScalar() ?? 0L);
                if (count > 0)
                {
                    return false;
                }
            }

            string updateSql = "UPDATE Users SET DisplayName = @DisplayName WHERE Email = @Email;";
            using var command = new SqliteCommand(updateSql, connection);
            command.Parameters.AddWithValue("@DisplayName", cleanName);
            command.Parameters.AddWithValue("@Email", cleanEmail);

            int rows = command.ExecuteNonQuery();
            return rows > 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <summary>Gets the display name for a given user ID.</summary>
    public string GetDisplayName(string userId)

    {
        if (string.IsNullOrWhiteSpace(userId))
            return "Unknown";

        string cleanEmail = userId.Trim().ToLowerInvariant();

        _dbLock.Wait();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            string selectSql = "SELECT DisplayName FROM Users WHERE Email = @Email LIMIT 1;";
            using var command = new SqliteCommand(selectSql, connection);
            command.Parameters.AddWithValue("@Email", cleanEmail);

            object? result = command.ExecuteScalar();
            if (result != null && result != DBNull.Value)
            {
                return result.ToString() ?? cleanEmail;
            }
        }
        catch
        {
            // Fall back to cleanEmail if DB lookup fails
        }
        finally
        {
            _dbLock.Release();
        }

        return cleanEmail;
    }
}
