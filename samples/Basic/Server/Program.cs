using SecureSocket;

namespace Basic.Server;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("=================================================");
        Console.WriteLine("   SecureSocket - Anonymous Basic Ping SERVER  ");
        Console.WriteLine("=================================================\n");

        int port = 20001;

        Console.WriteLine("[1/2] Loading Self-Signed Development TLS Certificate...");
        var cert = CertificateHelper.CreateSelfSignedDevelopmentCertificate("CN=localhost");

        Console.WriteLine($"[2/2] Starting SecureSocket.Server on port {port} (Anonymous Server)...");
        
        var server = new SecureSocket.Server(cert, userStore: null);

        void UpdateTitle()
        {
            try
            {
                Console.Title = $"Basic Server | Port: {port} | Clients: {server.GetClientCount} | Tick: #{server.GetLastTick:D5}";
            }
            catch
            {
                // Console.Title might throw on non-interactive environments
            }
        }

        server.OnStatusEvent += (s, e) => Console.WriteLine($" [STATUS] {e.StatusMessage}");
        server.OnClientConnectedEvent += (s, e) =>
        {
            Console.WriteLine($" [EVENT] Client #{e.ConnId} Connected!");
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
        Console.WriteLine($"\nServer is running on port {port}. Telemetry is displayed in Console Title Bar.");
        Console.WriteLine("Type /quit or press CTRL+C to stop.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        while (!cts.IsCancellationRequested && server.IsRunning)
        {
            string? input = Console.ReadLine();
            if (input != null && (input.Equals("/quit", StringComparison.OrdinalIgnoreCase) || input.Equals("/exit", StringComparison.OrdinalIgnoreCase)))
            {
                break;
            }
        }

        server.StopListening();
        Console.WriteLine("Server stopped.");
    }
}
