using System.Diagnostics;
using System.Text;
using SecureSocket;

namespace Chat.Client;

public class ChatMessageItem
{
    public string Sender { get; set; } = string.Empty;
    public string Text { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

internal class Program
{
    private static int _currentTick = 0;
    private static double _lastTickIntervalMs = 1000.0;
    private static long _lastTickReceiptTicks = 0;

    private static double _latestLatencyMs = 0;
    private static double _avg10LatencyMs = 0;
    private static readonly Queue<double> _last10Latencies = new();
    private static readonly object _latencyLock = new();

    private static string _currentChannel = "#general";

    private static readonly object ConsoleLock = new();
    private static int _nameColumnWidth = 20;
    private static readonly List<ChatMessageItem> _messageHistory = new();
    private static readonly StringBuilder _inputBuffer = new();

    private static readonly Dictionary<string, string> ChannelTopics = new(StringComparer.OrdinalIgnoreCase)
    {
        { "#general", "The starter channel for all your chat needs" },
        { "#crypto", "Cryptocurrency, market data, and trading discussion" },
        { "#random", "Casual chat, tech news, and off-topic discussion" }
    };

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    private static void EnableAlternateBuffer()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
                if (GetConsoleMode(handle, out uint mode))
                {
                    SetConsoleMode(handle, mode | 0x0004); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
                }
            }
            Console.Write("\x1b[?1049h\x1b[?25l"); // Enter Alternate Screen Buffer & hide cursor initially
        }
        catch { }
    }

    private static void RestoreMainBuffer()
    {
        try
        {
            Console.Write("\x1b[?1049l\x1b[?25h"); // Exit Alternate Screen Buffer & show cursor
        }
        catch { }
    }

    private static async Task Main(string[] args)
    {
        EnableAlternateBuffer();
        AppDomain.CurrentDomain.ProcessExit += (s, e) => RestoreMainBuffer();

        int port = 20001;
        var client = new SecureSocket.Client("127.0.0.1", port: port, allowSelfSignedCerts: true);

        void UpdateTitle()
        {
            try
            {
                string userLabel = string.IsNullOrEmpty(client.User.DisplayName) ? "Anonymous" : client.User.DisplayName;
                Console.Title = $"Chat Client [{userLabel} @ {_currentChannel}] | Tick: #{_currentTick:D5} (Interval: {_lastTickIntervalMs:0000.00}ms) | Ping: {_latestLatencyMs:F2}ms (10-Avg: {_avg10LatencyMs:F2}ms)";
            }
            catch
            {
                // Console.Title might throw on non-interactive environments
            }
        }

        // Attach telemetry handlers
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

        // Attach client log handler so connection attempts & retries display on screen (filtering raw protocol frame logs)
        client.Log += (s, e) =>
        {
            if (e.Message.Contains("Received frame:", StringComparison.OrdinalIgnoreCase) ||
                e.Message.Contains("Sent frame:", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            AddChatMessage("Log", e.Message, client);
        };

        // Attach client IRC protocol handlers
        RegisterChatHandlers(client);

        AddChatMessage("System", "Starting Chat Client...", client);
        AddChatMessage("System", "To chat, log in with: /login <email> <password> or /register <email> <password> <name>", client);
        AddChatMessage("System", "Type /help for a list of available commands.", client);

        // Connect asynchronously without blocking initial TUI rendering
        _ = client.Connect();

        using var cts = new CancellationTokenSource();

        // Background periodic ping loop for connection sanity & latency telemetry
        _ = Task.Run(async () =>
        {
            int pingCount = 1;
            while (!cts.IsCancellationRequested && client.IsConnected)
            {
                await client.SendPingAsync($"PING_{pingCount++}");
                await Task.Delay(3000, cts.Token).ContinueWith(_ => { });
            }
        }, cts.Token);

        while (!cts.IsCancellationRequested)
        {
            string? input = await ReadInputLineAsync(client, cts.Token);
            if (string.IsNullOrWhiteSpace(input)) continue;

            if (input.Equals("/quit", StringComparison.OrdinalIgnoreCase) || input.Equals("/exit", StringComparison.OrdinalIgnoreCase))
                break;

            if (input.Equals("/help", StringComparison.OrdinalIgnoreCase))
            {
                AddHelpMessages(client);
                continue;
            }

            if (input.StartsWith("/register ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 4);
                if (parts.Length >= 4)
                {
                    AddChatMessage("System", $"Registering '{parts[1]}' as '{parts[3]}'...", client);
                    var (success, message) = await client.RegisterAsync(parts[1], parts[2], parts[3]);
                    if (success)
                    {
                        AddChatMessage("CONFIRM", message, client);
                    }
                    else
                    {
                        AddChatMessage("ERROR", message, client);
                    }
                    UpdateTitle();
                }
                else
                {
                    AddChatMessage("USAGE", "/register <email> <pass> <display_name>", client);
                }
            }
            else if (input.StartsWith("/login ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 3);
                if (parts.Length >= 3)
                {
                    AddChatMessage("System", $"Logging in user '{parts[1]}'...", client);
                    var (success, message) = await client.LoginAsync(parts[1], parts[2]);
                    if (success)
                    {
                        UpdateTitle();
                        // Auto-join #general channel on login success
                        await client.SendMessageAsync((MessageType)ChatMessageType.ChatToChannel, _currentChannel, string.Empty);
                    }
                    else
                    {
                        AddChatMessage("ERROR", message, client);
                        UpdateTitle();
                    }
                }
                else
                {
                    AddChatMessage("USAGE", "/login <email> <pass>", client);
                }
            }
            else if (input.Equals("/logout", StringComparison.OrdinalIgnoreCase))
            {
                await client.LogoutAsync();
                _currentChannel = "#general";
                UpdateTitle();
                AddChatMessage("System", "Logged out successfully. You are now anonymous.", client);
            }
            else if (input.StartsWith("/join ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 2);
                if (parts.Length >= 2)
                {
                    _currentChannel = parts[1].StartsWith('#') ? parts[1] : "#" + parts[1];
                    UpdateTitle();
                    await client.SendMessageAsync((MessageType)ChatMessageType.ChatToChannel, _currentChannel, string.Empty);
                }
            }
            else if (input.StartsWith("/say ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 3);
                if (parts.Length == 2)
                {
                    await client.SendMessageAsync((MessageType)ChatMessageType.ChatToChannel, _currentChannel, parts[1]);
                }
                else if (parts.Length >= 3)
                {
                    string chan = parts[1].StartsWith('#') ? parts[1] : "#" + parts[1];
                    await client.SendMessageAsync((MessageType)ChatMessageType.ChatToChannel, chan, parts[2]);
                }
                else
                {
                    AddChatMessage("USAGE", "/say <message> OR /say <#channel> <message>", client);
                }
            }
            else if (input.StartsWith("/msg ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 3);
                if (parts.Length >= 3)
                {
                    await client.SendMessageAsync((MessageType)ChatMessageType.ChatToUser, parts[1], parts[2]);
                }
                else
                {
                    AddChatMessage("USAGE", "/msg <user_id_or_email_or_name> <message>", client);
                }
            }
            else if (input.Equals("/ping", StringComparison.OrdinalIgnoreCase))
            {
                await client.SendPingAsync($"MANUAL_PING_{Guid.NewGuid().ToString("N")[..4]}");
            }
            else if (input.Equals("/channels", StringComparison.OrdinalIgnoreCase))
            {
                await client.SendMessageAsync((MessageType)ChatMessageType.ChatListChan);
            }
            else if (input.StartsWith("/users", StringComparison.OrdinalIgnoreCase))
            {
                var parts = input.Split(' ', 2);
                string targetChan = parts.Length > 1 ? parts[1] : _currentChannel;
                await client.SendMessageAsync((MessageType)ChatMessageType.ChatListUsers, targetChan);
            }
            else
            {
                // Send message to current active channel
                await client.SendMessageAsync((MessageType)ChatMessageType.ChatToChannel, _currentChannel, input);
            }
        }

        cts.Cancel();
        client.Close();
        RestoreMainBuffer();
        Console.WriteLine("Chat client closed.");
    }

    private static int _lastWindowWidth = -1;
    private static int _lastWindowHeight = -1;
    private static readonly List<string> _commandHistory = new();
    private static int _historyIndex = -1;

    private static void AddChatMessage(string sender, string text, SecureSocket.Client client)
    {
        lock (ConsoleLock)
        {
            _messageHistory.Add(new ChatMessageItem { Sender = sender, Text = text, Timestamp = DateTime.UtcNow });
            RedrawScreen(client);
        }
    }

    private static void ClearScreenAndScrollback()
    {
        try
        {
            // ANSI Escape Codes: \x1b[3J (Clear Scrollback Buffer), \x1b[2J (Clear Viewport), \x1b[H (Home)
            Console.Write("\x1b[3J\x1b[2J\x1b[H");
            Console.Clear();
        }
        catch
        {
            try { Console.Clear(); } catch { }
        }
    }

    private static void RedrawScreen(SecureSocket.Client client, bool forceClear = false)
    {
        lock (ConsoleLock)
        {
            try
            {
                int width = 80;
                int height = 24;

                try
                {
                    if (!Console.IsOutputRedirected && Console.WindowWidth > 0)
                    {
                        width = Console.WindowWidth;
                        height = Console.WindowHeight;
                    }
                }
                catch
                {
                    // Fallback
                }

                if (width != _lastWindowWidth || height != _lastWindowHeight || forceClear)
                {
                    _lastWindowWidth = width;
                    _lastWindowHeight = height;
                    try
                    {
                        if (OperatingSystem.IsWindows() && !Console.IsOutputRedirected)
                        {
                            Console.BufferWidth = width;
                            Console.BufferHeight = height;
                        }
                    }
                    catch { }
                    ClearScreenAndScrollback();
                }

                Console.CursorVisible = false;

                // Prompt user label setup
                string userLabel = (client.User.UserId == UserIdentifier.Anonymous.UserId || client.User.UserId.StartsWith("conn_", StringComparison.OrdinalIgnoreCase))
                    ? "Anonymous"
                    : client.User.DisplayName;

                string promptSender = userLabel.Length > _nameColumnWidth ? userLabel[.._nameColumnWidth] : userLabel;
                string promptPrefix = $"{promptSender.PadLeft(_nameColumnWidth)} > ";
                string promptFull = promptPrefix + _inputBuffer.ToString();
                if (promptFull.Length > width - 1) promptFull = promptFull[..(width - 1)];
                promptFull = promptFull.PadRight(width - 1);

                // Case 1: Height == 1 (Priority 1: Only Input Prompt)
                if (height <= 1)
                {
                    Console.SetCursorPosition(0, 0);
                    Console.Write(promptFull);
                    int cCol = Math.Min(width - 2, promptPrefix.Length + _inputBuffer.Length);
                    Console.SetCursorPosition(cCol, 0);
                    Console.CursorVisible = true;
                    return;
                }

                // Case 2: Height == 2 (Priority 2: 1 Chat Line + Input Prompt)
                if (height == 2)
                {
                    Console.SetCursorPosition(0, 0);
                    if (_messageHistory.Count > 0)
                    {
                        var lastMsg = _messageHistory[^1];
                        string nPart = lastMsg.Sender.Length > _nameColumnWidth ? lastMsg.Sender[.._nameColumnWidth] : lastMsg.Sender;
                        string line = $"{nPart.PadLeft(_nameColumnWidth)} | {lastMsg.Text}";
                        if (line.Length > width - 1) line = line[..(width - 1)];
                        Console.Write(line.PadRight(width - 1));
                    }
                    else
                    {
                        string emptyLeft = (new string(' ', _nameColumnWidth) + " | ");
                        if (emptyLeft.Length > width - 1) emptyLeft = emptyLeft[..(width - 1)];
                        Console.Write(emptyLeft.PadRight(width - 1));
                    }

                    Console.SetCursorPosition(0, 1);
                    Console.Write(promptFull);
                    int cCol = Math.Min(width - 2, promptPrefix.Length + _inputBuffer.Length);
                    Console.SetCursorPosition(cCol, 1);
                    Console.CursorVisible = true;
                    return;
                }

                // Case 3: Height == 3 (Priority 3: Top Header + 1 Chat Line + Input Prompt)
                if (height == 3)
                {
                    // Row 0: Top Header
                    Console.SetCursorPosition(0, 0);
                    string topic = ChannelTopics.TryGetValue(_currentChannel, out var t) ? t : "Dynamic public chat room";
                    string headerText = $"{_currentChannel} - {topic}";
                    if (headerText.Length > width - 1) headerText = headerText[..(width - 1)];
                    Console.Write(headerText.PadRight(width - 1));

                    // Row 1: Chat Line
                    Console.SetCursorPosition(0, 1);
                    if (_messageHistory.Count > 0)
                    {
                        var lastMsg = _messageHistory[^1];
                        string nPart = lastMsg.Sender.Length > _nameColumnWidth ? lastMsg.Sender[.._nameColumnWidth] : lastMsg.Sender;
                        string line = $"{nPart.PadLeft(_nameColumnWidth)} | {lastMsg.Text}";
                        if (line.Length > width - 1) line = line[..(width - 1)];
                        Console.Write(line.PadRight(width - 1));
                    }
                    else
                    {
                        string emptyLeft = (new string(' ', _nameColumnWidth) + " | ");
                        if (emptyLeft.Length > width - 1) emptyLeft = emptyLeft[..(width - 1)];
                        Console.Write(emptyLeft.PadRight(width - 1));
                    }

                    // Row 2: Input Prompt
                    Console.SetCursorPosition(0, 2);
                    Console.Write(promptFull);
                    int cCol = Math.Min(width - 2, promptPrefix.Length + _inputBuffer.Length);
                    Console.SetCursorPosition(cCol, 2);
                    Console.CursorVisible = true;
                    return;
                }

                // Case 4: Height >= 4 (Full Standard TUI Layout with Dividers)
                // Row 0: Sticky Header
                Console.SetCursorPosition(0, 0);
                string topTopic = ChannelTopics.TryGetValue(_currentChannel, out var topicStr) ? topicStr : "Dynamic public chat room";
                string head = $"{_currentChannel} - {topTopic}";
                if (head.Length > width - 1) head = head[..(width - 1)];
                Console.Write(head.PadRight(width - 1));

                // Row 1: Top Divider (Full Width)
                Console.SetCursorPosition(0, 1);
                string divider = new string('-', width - 1);
                Console.Write(divider);

                // Rows 2 to Height - 3: Middle Viewport
                int bodyHeight = height - 4;
                int totalMsg = _messageHistory.Count;
                int startIndex = Math.Max(0, totalMsg - bodyHeight);
                int visibleCount = Math.Min(bodyHeight, totalMsg - startIndex);

                var visibleMsgs = _messageHistory.Skip(startIndex).Take(visibleCount).ToList();
                int blankRows = bodyHeight - visibleMsgs.Count;

                string blankLeft = new string(' ', _nameColumnWidth) + " | ";
                if (blankLeft.Length > width - 1) blankLeft = blankLeft[..(width - 1)];
                string blankRowPadded = blankLeft.PadRight(width - 1);

                int rowOffset = 2;

                // Render blank viewport rows
                for (int i = 0; i < blankRows; i++)
                {
                    Console.SetCursorPosition(0, rowOffset++);
                    Console.Write(blankRowPadded);
                }

                // Render visible chat messages
                foreach (var item in visibleMsgs)
                {
                    Console.SetCursorPosition(0, rowOffset++);
                    string namePart = item.Sender.Length > _nameColumnWidth ? item.Sender[.._nameColumnWidth] : item.Sender;
                    string leftCol = namePart.PadLeft(_nameColumnWidth);
                    string lineText = $"{leftCol} | {item.Text}";
                    if (lineText.Length > width - 1) lineText = lineText[..(width - 1)];
                    Console.Write(lineText.PadRight(width - 1));
                }

                // Row Height - 2: Bottom Divider (Full Width)
                Console.SetCursorPosition(0, height - 2);
                Console.Write(divider);

                // Row Height - 1: Sticky Input Prompt
                Console.SetCursorPosition(0, height - 1);
                Console.Write(promptFull);

                // Place cursor at position after input buffer
                int cursorCol = Math.Min(width - 2, promptPrefix.Length + _inputBuffer.Length);
                int cursorRow = height - 1;
                Console.SetCursorPosition(cursorCol, cursorRow);
                Console.CursorVisible = true;
            }
            catch
            {
                // Fallback for non-interactive environments
            }
        }
    }

    private static async Task<string?> ReadInputLineAsync(SecureSocket.Client client, CancellationToken cancellationToken)
    {
        _inputBuffer.Clear();
        _historyIndex = _commandHistory.Count;
        RedrawScreen(client);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                int curW = Console.WindowWidth;
                int curH = Console.WindowHeight;

                if (curW != _lastWindowWidth || curH != _lastWindowHeight)
                {
                    RedrawScreen(client);
                }

                if (Console.KeyAvailable)
                {
                    var keyInfo = Console.ReadKey(intercept: true);

                    if (keyInfo.Key == ConsoleKey.Enter)
                    {
                        string result = _inputBuffer.ToString();
                        _inputBuffer.Clear();
                        if (!string.IsNullOrWhiteSpace(result))
                        {
                            _commandHistory.Add(result);
                        }
                        _historyIndex = _commandHistory.Count;
                        RedrawScreen(client);
                        return result;
                    }
                    else if (keyInfo.Key == ConsoleKey.UpArrow)
                    {
                        if (_commandHistory.Count > 0 && _historyIndex > 0)
                        {
                            _historyIndex--;
                            _inputBuffer.Clear();
                            _inputBuffer.Append(_commandHistory[_historyIndex]);
                            RedrawScreen(client);
                        }
                    }
                    else if (keyInfo.Key == ConsoleKey.DownArrow)
                    {
                        if (_commandHistory.Count > 0)
                        {
                            if (_historyIndex < _commandHistory.Count - 1)
                            {
                                _historyIndex++;
                                _inputBuffer.Clear();
                                _inputBuffer.Append(_commandHistory[_historyIndex]);
                                RedrawScreen(client);
                            }
                            else if (_historyIndex == _commandHistory.Count - 1)
                            {
                                _historyIndex = _commandHistory.Count;
                                _inputBuffer.Clear();
                                RedrawScreen(client);
                            }
                        }
                    }
                    else if (keyInfo.Key == ConsoleKey.Backspace)
                    {
                        if (_inputBuffer.Length > 0)
                        {
                            _inputBuffer.Remove(_inputBuffer.Length - 1, 1);
                            RedrawScreen(client);
                        }
                    }
                    else if (keyInfo.Key == ConsoleKey.Escape)
                    {
                        _inputBuffer.Clear();
                        _historyIndex = _commandHistory.Count;
                        RedrawScreen(client);
                    }
                    else if (!char.IsControl(keyInfo.KeyChar))
                    {
                        _inputBuffer.Append(keyInfo.KeyChar);
                        RedrawScreen(client);
                    }
                }
                else
                {
                    await Task.Delay(20, cancellationToken).ContinueWith(_ => { });
                }
            }
            catch
            {
                await Task.Delay(50, cancellationToken).ContinueWith(_ => { });
            }
        }

        return null;
    }

    private static void AddHelpMessages(SecureSocket.Client client)
    {
        AddChatMessage("Help", "Available IRC Console Commands:", client);
        AddChatMessage("Help", "  /register <email> <pass> <name>  - Register new account", client);
        AddChatMessage("Help", "  /login <email> <pass>           - Log in to account", client);
        AddChatMessage("Help", "  /logout                          - Log out to anonymous state", client);
        AddChatMessage("Help", "  /join <#channel>                 - Join channel (e.g. /join #crypto)", client);
        AddChatMessage("Help", "  /say <message>                   - Broadcast message to current channel", client);
        AddChatMessage("Help", "  /msg <user> <message>            - Send private message", client);
        AddChatMessage("Help", "  /channels                        - List active server channels", client);
        AddChatMessage("Help", "  /users <#channel>                - List users in channel", client);
        AddChatMessage("Help", "  /quit                            - Exit chat client", client);
    }

    private static void RegisterChatHandlers(SecureSocket.Client client)
    {
        // Channel messages
        client.RegisterHandler((MessageType)ChatMessageType.ChatToChannel, (msg) =>
        {
            string channel = msg.GetArgument(0);
            string senderDisplayName = msg.GetArgument(1);
            string chatText = msg.GetArgument(2);

            if (string.Equals(senderDisplayName, UserIdentifier.System.UserId, StringComparison.OrdinalIgnoreCase) || string.Equals(senderDisplayName, "SERVER", StringComparison.OrdinalIgnoreCase))
            {
                AddChatMessage("System", chatText, client);
            }
            else
            {
                AddChatMessage(senderDisplayName, chatText, client);
            }
        });

        // Private messages
        client.RegisterHandler((MessageType)ChatMessageType.ChatToUser, (msg) =>
        {
            string senderUserId = msg.GetArgument(0);
            string senderDisplayName = msg.GetArgument(1);
            string chatText = msg.GetArgument(2);

            AddChatMessage($"[PM:{senderDisplayName}]", chatText, client);
        });

        // Active Channels List
        client.RegisterHandler((MessageType)ChatMessageType.ChatListChan, (msg) =>
        {
            string channels = msg.GetArgument(0);
            AddChatMessage("CHANNELS", channels, client);
        });

        // Active Users List
        client.RegisterHandler((MessageType)ChatMessageType.ChatListUsers, (msg) =>
        {
            string channel = msg.GetArgument(0);
            string users = msg.GetArgument(1);
            AddChatMessage($"USERS:{channel}", users, client);
        });

        // Server Error Messages
        client.RegisterHandler(MessageType.ERROR, (msg) =>
        {
            string errCode = msg.GetArgument(0);
            string errDetail = msg.GetArgument(1);
            AddChatMessage($"ERROR:{errCode}", errDetail, client);
        });
    }
}
