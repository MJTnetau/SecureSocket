using System.Collections.Concurrent;
using System.Diagnostics;
using SecureSocket;

namespace Basic.Client;

internal class Program
{
    private static int _currentTick = 0;
    private static double _lastTickIntervalMs = 1000.0;
    private static long _lastTickReceiptTicks = 0;

    private static double _latestLatencyMs = 0;
    private static double _avg10LatencyMs = 0;
    private static readonly Queue<double> _last10Latencies = new();
    private static readonly object _latencyLock = new();

    private static void Main(string[] args) => MainAsync(args).GetAwaiter().GetResult();

    private static async Task MainAsync(string[] args)
    {
        Console.WriteLine("=================================================");
        Console.WriteLine("   SecureSocket - Anonymous Basic Ping CLIENT  ");
        Console.WriteLine("=================================================\n");

        int port = 20001;
        Console.WriteLine($"Connecting to TLS Server at 127.0.0.1:{port} (Anonymous Connection)...");

        var client = new SecureSocket.Client("127.0.0.1", port: port, allowSelfSignedCerts: true);

        void UpdateTitle()
        {
            try
            {
                Console.Title = $"Basic Client | Tick: #{_currentTick:D5} (Interval: {_lastTickIntervalMs:0000.00}ms) | Latency: {_latestLatencyMs:F2}ms (10-Avg: {_avg10LatencyMs:F2}ms)";
            }
            catch
            {
                // Console.Title might throw on non-interactive environments
            }
        }

        client.OnStatusEvent += (s, e) => Console.WriteLine($" [STATUS] {e.StatusMessage}");
        client.OnServerConnectedEvent += (s, e) => Console.WriteLine(" [EVENT] Connected to TLS Server anonymously!");
        
        client.OnPingEvent += (s, e) =>
        {
            if (e.IsPong)
            {
                lock (_latencyLock)
                {
                    _latestLatencyMs = e.LatencyMs;
                    _last10Latencies.Enqueue(e.LatencyMs);
                    if (_last10Latencies.Count > 10)
                    {
                        _last10Latencies.Dequeue();
                    }
                    _avg10LatencyMs = _last10Latencies.Average();
                }
                UpdateTitle();
                Console.WriteLine($" <- Received PONG (Nonce: '{e.Nonce}' | Latency: {e.LatencyMs:F2} ms)");
            }
        };

        client.OnTickEvent += (s, e) =>
        {
            long nowTicks = Stopwatch.GetTimestamp();
            if (_lastTickReceiptTicks > 0)
            {
                _lastTickIntervalMs = (nowTicks - _lastTickReceiptTicks) * 1000.0 / Stopwatch.Frequency;
            }
            _lastTickReceiptTicks = nowTicks;
            _currentTick = e.TickCount;
            UpdateTitle();
        };

        await client.Connect();
        await Task.Delay(300);

        UpdateTitle();
        Console.WriteLine("\n[RUNNING] Anonymous client connected.");
        Console.WriteLine("Telemetry (Tick, Interval, Latency, 10-Avg) is updated live in the Console Title Bar.");
        Console.WriteLine("Type /quit or press CTRL+C to exit.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Background periodic ping sender loop
        _ = Task.Run(async () =>
        {
            int pingCount = 1;
            while (!cts.IsCancellationRequested && client.IsConnected)
            {
                string nonce = $"PING_{pingCount++}_{Guid.NewGuid().ToString("N")[..6]}";
                Console.WriteLine($" -> Sent PING #{pingCount - 1} (Nonce: '{nonce}')...");
                await client.SendPingAsync(nonce);
                await Task.Delay(3000, cts.Token).ContinueWith(_ => { });
            }
        }, cts.Token);

        // Command loop: always displays user prompt before flashing cursor
        while (!cts.IsCancellationRequested && client.IsConnected)
        {
            Console.Write("[Anonymous]> ");
            string? input = Console.ReadLine();
            if (input != null && (input.Equals("/quit", StringComparison.OrdinalIgnoreCase) || input.Equals("/exit", StringComparison.OrdinalIgnoreCase)))
            {
                break;
            }
        }

        cts.Cancel();
        Console.WriteLine("\nDisconnecting anonymous client...");
        client.Close();
        Console.WriteLine("Basic Client Sample finished.");
    }
}
