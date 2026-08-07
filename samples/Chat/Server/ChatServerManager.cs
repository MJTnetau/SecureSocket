using System.Collections.Concurrent;
using SecureSocket;

namespace Chat.Server;

public class ChatServerManager
{
    private readonly SecureSocket.Server _server;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<int, SslClientSession>> _channels = new(StringComparer.OrdinalIgnoreCase);

    public ChatServerManager(SecureSocket.Server server)
    {
        _server = server ?? throw new ArgumentNullException(nameof(server));
        _server.OnClientDisconnectedEvent += OnClientDisconnected;
        RegisterHandlers();
    }

    private void OnClientDisconnected(object? sender, ClientDisconnectEventArgs e)
    {
        foreach (var channelDict in _channels.Values)
        {
            channelDict.TryRemove(e.ConnId, out _);
        }
    }

    private void RegisterHandlers()
    {
        _server.RegisterHandler((MessageType)ChatMessageType.ChatToServer, OnChatToServer);
        _server.RegisterHandler((MessageType)ChatMessageType.ChatToUser, OnChatToUser);
        _server.RegisterHandler((MessageType)ChatMessageType.ChatToChannel, OnChatToChannel);
        _server.RegisterHandler((MessageType)ChatMessageType.ChatListChan, OnChatListChannels);
        _server.RegisterHandler((MessageType)ChatMessageType.ChatListUsers, OnChatListUsers);
    }

    private async Task OnChatToServer(SslClientSession sender, Message2 msg)
    {
        if (!sender.IsAuthenticated)
        {
            await sender.SendAsync(MessageType.ERROR, "AUTH_REQUIRED", "Access denied. You must log in to chat with the server.");
            return;
        }
        string text = msg.GetArgument(0);
        Console.WriteLine($"[CHAT SERVER LOG] From {sender.User}: {text}");
    }

    private async Task OnChatToUser(SslClientSession sender, Message2 msg)
    {
        if (!sender.IsAuthenticated)
        {
            await sender.SendAsync(MessageType.ERROR, "AUTH_REQUIRED", "Access denied. You must log in to send private messages.");
            return;
        }

        string targetUserId = msg.GetArgument(0);
        string text = msg.GetArgument(1);

        bool delivered = false;
        foreach (var clientSession in _server.Clients.Values)
        {
            if (string.Equals(clientSession.User.UserId, targetUserId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(clientSession.User.DisplayName, targetUserId, StringComparison.OrdinalIgnoreCase))
            {
                await clientSession.SendAsync((MessageType)ChatMessageType.ChatToUser, sender.User.UserId, sender.User.DisplayName, text);
                delivered = true;
                break;
            }
        }

        if (!delivered)
        {
            await sender.SendAsync(MessageType.ERROR, "USER_NOT_FOUND", $"User '{targetUserId}' is not connected.");
        }
    }

    private async Task OnChatToChannel(SslClientSession sender, Message2 msg)
    {
        if (!sender.IsAuthenticated)
        {
            await sender.SendAsync(MessageType.ERROR, "AUTH_REQUIRED", "Access denied. You must log in to join or speak in channels. Use: /login <email> <password> or /register <email> <password> <display_name>");
            return;
        }

        string channel = msg.GetArgument(0);
        string text = msg.GetArgument(1);

        if (!channel.StartsWith('#')) channel = "#" + channel;

        var channelSessions = _channels.GetOrAdd(channel, _ => new ConcurrentDictionary<int, SslClientSession>());
        bool isFirstJoin = !channelSessions.ContainsKey(sender.ConnId);
        channelSessions[sender.ConnId] = sender;

        // If user is joining channel for the first time, send welcome message!
        if (isFirstJoin)
        {
            string welcomeMsg = $"Welcome {sender.User.DisplayName} ({sender.User.UserId})! This is {channel}. Type /channels for active channels or /users {channel} for member list.";
            await sender.SendAsync((MessageType)ChatMessageType.ChatToChannel, channel, UserIdentifier.System.UserId, welcomeMsg);
        }

        // Broadcast message to all channel members
        if (!string.IsNullOrWhiteSpace(text))
        {
            foreach (var session in channelSessions.Values)
            {
                await session.SendAsync((MessageType)ChatMessageType.ChatToChannel, channel, sender.User.DisplayName, text);
            }
        }
    }

    private async Task OnChatListChannels(SslClientSession sender, Message2 msg)
    {
        if (!sender.IsAuthenticated)
        {
            await sender.SendAsync(MessageType.ERROR, "AUTH_REQUIRED", "Access denied. You must log in to view active channels.");
            return;
        }

        string channelListStr = _channels.Count > 0 ? string.Join(',', _channels.Keys) : "#general,#crypto,#random";
        await sender.SendAsync((MessageType)ChatMessageType.ChatListChan, channelListStr);
    }

    private async Task OnChatListUsers(SslClientSession sender, Message2 msg)
    {
        if (!sender.IsAuthenticated)
        {
            await sender.SendAsync(MessageType.ERROR, "AUTH_REQUIRED", "Access denied. You must log in to view member lists.");
            return;
        }

        string channel = msg.GetArgument(0);
        if (!channel.StartsWith('#')) channel = "#" + channel;

        if (_channels.TryGetValue(channel, out var sessions))
        {
            string userListStr = string.Join(',', sessions.Values.Select(s => $"{s.User.DisplayName} ({s.User.UserId})"));
            await sender.SendAsync((MessageType)ChatMessageType.ChatListUsers, channel, userListStr);
        }
        else
        {
            await sender.SendAsync((MessageType)ChatMessageType.ChatListUsers, channel, "No active users in channel.");
        }
    }
}
