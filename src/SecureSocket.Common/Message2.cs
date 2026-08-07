using System.Text;

namespace SecureSocket;

/// <summary>
/// Represents a parsed message frame in SecureSocket.
/// </summary>
public class Message2
{
    /// <summary>
    /// Gets or sets the message type opcode.
    /// </summary>
    public MessageType MsgType { get; set; }

    /// <summary>
    /// Gets or sets the byte length of the payload framing.
    /// </summary>
    public int MsgLength { get; set; }

    /// <summary>
    /// Gets or sets positional string arguments.
    /// </summary>
    public string[] Arguments { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets raw unencoded binary payload bytes (optional).
    /// </summary>
    public ReadOnlyMemory<byte> BinaryPayload { get; set; } = ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Gets or sets the public sender user identity (UserId and DisplayName).
    /// Contains zero IP address or private socket descriptor information.
    /// </summary>
    public UserIdentifier SenderUser { get; set; } = UserIdentifier.Anonymous;

    /// <summary>
    /// Gets or sets the FIX-style 8-bit checksum value.
    /// </summary>
    public int Checksum { get; set; }

    /// <summary>
    /// Gets a single string argument at the specified index or empty string if out of bounds.
    /// </summary>
    public string GetArgument(int index)
    {
        if (Arguments != null && index >= 0 && index < Arguments.Length)
        {
            return Arguments[index];
        }
        return string.Empty;
    }

    /// <summary>
    /// Converts the message into a human-readable log string.
    /// Format: [MsgType] Sender >> Arg0|Arg1... [Binary bytes]
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(MsgType.ToString());
        sb.Append(" [");
        sb.Append((int)MsgType);
        sb.Append("]");

        if (!string.IsNullOrEmpty(SenderUser.UserId))
        {
            sb.Append("-");
            sb.Append(SenderUser.ToString());
        }

        sb.Append(">> ");

        if (Arguments != null && Arguments.Length > 0)
        {
            if (MsgType == MessageType.UserLogin || MsgType == MessageType.UserRegister)
            {
                var safeArgs = (string[])Arguments.Clone();
                if (safeArgs.Length > 1)
                {
                    safeArgs[1] = "***";
                }
                sb.Append(string.Join('|', safeArgs));
            }
            else
            {
                sb.Append(string.Join('|', Arguments));
            }
        }

        if (!BinaryPayload.IsEmpty)
        {
            sb.Append($" [{BinaryPayload.Length} Binary Bytes]");
        }

        return sb.ToString();
    }
}
