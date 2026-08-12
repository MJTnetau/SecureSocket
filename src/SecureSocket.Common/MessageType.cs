#pragma warning disable CS1591

namespace SecureSocket;

/// <summary>
/// Defines message types used in core socket communication.
/// Supports clean casting from custom application opcodes (e.g. Chat = 80).
/// </summary>

public enum MessageType : int
{
    // Illegal range (00-09)
    Illegal_0 = 0,
    Illegal_1 = 1,
    Illegal_2 = 2,
    Illegal_3 = 3,
    Illegal_4 = 4,
    Illegal_5 = 5,
    Illegal_6 = 6,
    Illegal_7 = 7,
    Illegal_8 = 8,
    Illegal_9 = 9,

    // Connectivity & Heartbeat (10-19)
    Ping = 10,
    Pong = 11,
    Tick = 12,

    // User Accounts & Authentication (20-29)
    UserRegister = 20,
    RegisterResp = 21,
    UserLogin = 22,
    LoginResp = 23,
    UserLogout = 24,

    // System Control & Errors (90-99)
    EMPTY = 90,
    ERROR = 91,
    SystemNotice = 92,
    UNKNOWN = 99
}

/// <summary>
/// Helper extensions for <see cref="MessageType"/>.
/// </summary>
public static class MessageTypeExtensions
{
    /// <summary>
    /// Converts an integer or string representation to a <see cref="MessageType"/>.
    /// </summary>
    public static MessageType ToMessageType(this string s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return MessageType.UNKNOWN;

        if (int.TryParse(s, out int intVal))
        {
            return (MessageType)intVal;
        }

        if (Enum.TryParse(typeof(MessageType), s, true, out object? result) && result is MessageType mt)
        {
            return mt;
        }

        return MessageType.UNKNOWN;
    }

    /// <summary>
    /// Checks whether the message type is in the illegal range (0 through 9).
    /// </summary>
    public static bool IsIllegalMessageType(this MessageType mt)
    {
        int val = (int)mt;
        return val >= 0 && val <= 9;
    }
}
