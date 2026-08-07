using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureSocket;

/// <summary>
/// Security helper for loading TLS certificates from files, Environment Variables, User Secrets, or X509Store.
/// </summary>
public static class CertificateHelper
{
    /// <summary>
    /// Loads a TLS certificate from a local .pfx/.cer file path or from the Certificate Store (CurrentUser or LocalMachine) by Thumbprint or Subject.
    /// Password can be loaded via User Secrets or Environment Variables.
    /// </summary>
    /// <param name="pathOrThumbprint">Relative/absolute file path or Certificate Store thumbprint/subject.</param>
    /// <param name="password">Optional file password. Recommended to read from User Secrets or Environment Variables.</param>
    /// <returns>Loaded X509Certificate2 instance.</returns>
    public static X509Certificate2 LoadCertificate(string pathOrThumbprint, string? password = null)
    {
        if (string.IsNullOrWhiteSpace(pathOrThumbprint))
        {
            throw new ArgumentNullException(nameof(pathOrThumbprint), "Certificate path, thumbprint, or subject name must be provided.");
        }

        // If password is not passed explicitly, check Environment Variable 'CERT_PASSWORD'
        if (string.IsNullOrEmpty(password))
        {
            password = Environment.GetEnvironmentVariable("CERT_PASSWORD");
        }

        // 1. Check if file exists on disk
        string fullPath = Path.GetFullPath(pathOrThumbprint);
        if (File.Exists(fullPath) || File.Exists(pathOrThumbprint))
        {
            string targetPath = File.Exists(fullPath) ? fullPath : pathOrThumbprint;
            return string.IsNullOrEmpty(password)
#if NET9_0_OR_GREATER
                ? X509CertificateLoader.LoadCertificateFromFile(targetPath)
                : X509CertificateLoader.LoadPkcs12FromFile(targetPath, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
#else
                ? new X509Certificate2(targetPath)
                : new X509Certificate2(targetPath, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
#endif
        }

        // 2. Look in Certificate Store by Thumbprint or Subject Name
        string cleanSearch = pathOrThumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant();

        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            using var store = new X509Store(StoreName.My, location);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Search by Thumbprint first
                var matches = store.Certificates.Find(X509FindType.FindByThumbprint, cleanSearch, validOnly: false);
                if (matches.Count > 0)
                {
                    return matches[0];
                }

                // Search by Subject Name second
                matches = store.Certificates.Find(X509FindType.FindBySubjectName, pathOrThumbprint, validOnly: false);
                if (matches.Count > 0)
                {
                    return matches[0];
                }
            }
            catch
            {
                // Fall back if store access fails
            }
        }

        throw new FileNotFoundException($"Could not find certificate file at '{fullPath}', and no certificate with thumbprint/subject '{pathOrThumbprint}' was found in X509Store.");
    }

    /// <summary>
    /// Generates an in-memory self-signed development TLS certificate for local testing.
    /// </summary>
    /// <param name="subjectName">Subject name for the certificate (e.g. CN=localhost).</param>
    /// <returns>A self-signed X509Certificate2 with exportable private key.</returns>
    public static X509Certificate2 CreateSelfSignedDevelopmentCertificate(string subjectName = "CN=localhost")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(2));
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "devpass"), "devpass", X509KeyStorageFlags.Exportable);
#else
        return new X509Certificate2(cert.Export(X509ContentType.Pfx, "devpass"), "devpass", X509KeyStorageFlags.Exportable);
#endif
    }
}
