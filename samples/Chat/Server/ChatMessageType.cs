namespace Chat.Server;

public enum ChatMessageType : int
{
    Chat = 80,
    ChatToServer = 81,
    ChatToUser = 82,
    ChatToChannel = 83,
    ChatListChan = 84,
    ChatListUsers = 85
}
