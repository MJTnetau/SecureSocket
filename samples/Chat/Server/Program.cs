using SecureSocket;
using SecureSocket.Auth;

namespace Chat.Server;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("=========================================================");
        Console.WriteLine("   SecureSocket - IRC Chat Protocol SERVER Host       ");
        Console.WriteLine("=========================================================\n");

        int port = 20001;

        Console.WriteLine("[1/3] Loading TLS Certificate...");
        var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");

        Console.WriteLine("[2/3] Initializing SqliteUserStore ('chat_users.db')...");
        var userStore = new SqliteUserStore("chat_users.db");

        Console.WriteLine($"[3/3] Starting SecureSocket.Server on port {port}...");
        var server = new SecureSocket.Server(cert, userStore);
        var chatManager = new ChatServerManager(server);

        void UpdateTitle()
        {
            try
            {
                Console.Title = $"Chat Server | Port: {port} | Clients: {server.GetClientCount} | Tick: #{server.GetLastTick:D5}";
            }
            catch
            {
                // Console.Title might throw on non-interactive environments
            }
        }

        server.OnStatusEvent += (s, e) => Console.WriteLine($" [STATUS] {e.StatusMessage}");
        server.OnClientConnectedEvent += (s, e) =>
        {
            Console.WriteLine($" [EVENT] Client #{e.ConnId} Connected! User: {e.User}");
            UpdateTitle();
        };
        server.OnClientDisconnectedEvent += (s, e) =>
        {
            Console.WriteLine($" [EVENT] Client #{e.ConnId} Disconnected.");
            UpdateTitle();
        };

        server.OnTickEvent += (s, e) => UpdateTitle();

        server.StartListening(port: port);
        server.StartTicking(intervalMs: 1000);

        UpdateTitle();
        Console.WriteLine($"\nIRC Chat Server running on port {port}. Telemetry is displayed in Console Title Bar.");
        Console.WriteLine("Type /quit or press CTRL+C to stop.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Command loop: requires explicit /quit or /exit command or Ctrl+C
        while (!cts.IsCancellationRequested && server.IsRunning)
        {
            string? input = Console.ReadLine();
            if (input != null && (input.Equals("/quit", StringComparison.OrdinalIgnoreCase) || input.Equals("/exit", StringComparison.OrdinalIgnoreCase)))
            {
                break;
            }
        }

        server.StopListening();
        Console.WriteLine("Chat Server stopped.");
    }
}
