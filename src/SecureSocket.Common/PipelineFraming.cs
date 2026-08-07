using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace SecureSocket;

/// <summary>
/// High-performance, zero-allocation System.IO.Pipelines wire framing parser and formatter.
/// Wire format: MessageType|PayloadLength|ArgsCount|Arg0|Arg1|...|BinaryPayload|10=Checksum|
/// </summary>
public static class PipelineFraming
{
    private static readonly byte PipeByte = (byte)'|';

    /// <summary>
    /// Calculates a FIX-style 8-bit checksum ((sum of byte values) % 256).
    /// </summary>
    public static int ComputeChecksum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            sum += bytes[i];
        }
        return (int)(sum % 256);
    }

    /// <summary>
    /// Formats an outgoing message frame into a byte array for transmission over the socket.
    /// Uses Utf8Formatter for direct byte formatting to eliminate string interpolations and temporary allocations.
    /// </summary>
    public static byte[] FormatFrame(MessageType msgType, string[]? arguments = null, ReadOnlySpan<byte> binaryPayload = default)
    {
        arguments ??= Array.Empty<string>();
        int argsCount = arguments.Length;

        // 1. Prepare UTF-8 encoded arguments
        Span<byte> numBuf = stackalloc byte[16];
        string[] encodedArgs = argsCount > 0 ? new string[argsCount] : Array.Empty<string>();
        int argsUtf8Length = 0;
        for (int i = 0; i < argsCount; i++)
        {
            encodedArgs[i] = Uri.EscapeDataString(arguments[i] ?? string.Empty);
            argsUtf8Length += Encoding.UTF8.GetByteCount(encodedArgs[i]);
        }

        // ArgsCount header length: digits + '|'
        Utf8Formatter.TryFormat(argsCount, numBuf, out int argsCountDigits);
        int argsCountHeaderLength = argsCountDigits + 1;

        // Args section length: argsCountHeader + each argument followed by '|'
        int argsSectionLength = argsCountHeaderLength + argsUtf8Length + argsCount;

        // Checksum tag length: "10=" (3) + 3 digits (3) + "|" (1) = 7 bytes
        int payloadLength = argsSectionLength + binaryPayload.Length + 7;

        // Prefix header length: msgType digits + '|' + payloadLength digits + '|'
        Utf8Formatter.TryFormat((int)msgType, numBuf, out int msgTypeDigits);
        Utf8Formatter.TryFormat(payloadLength, numBuf, out int payloadLenDigits);
        int prefixLength = msgTypeDigits + 1 + payloadLenDigits + 1;

        // Single buffer allocation for final outgoing frame payload
        byte[] frame = new byte[prefixLength + payloadLength];
        int offset = 0;

        // 1. Write prefix header ("MessageType|PayloadLength|")
        Utf8Formatter.TryFormat((int)msgType, frame.AsSpan(offset), out int bw);
        offset += bw;
        frame[offset++] = PipeByte;

        Utf8Formatter.TryFormat(payloadLength, frame.AsSpan(offset), out bw);
        offset += bw;
        frame[offset++] = PipeByte;

        int payloadStartOffset = offset;

        // 2. Write ArgsCount header ("ArgsCount|")
        Utf8Formatter.TryFormat(argsCount, frame.AsSpan(offset), out bw);
        offset += bw;
        frame[offset++] = PipeByte;

        // 3. Write encoded arguments and trailing pipes
        for (int i = 0; i < argsCount; i++)
        {
            offset += Encoding.UTF8.GetBytes(encodedArgs[i], 0, encodedArgs[i].Length, frame, offset);
            frame[offset++] = PipeByte;
        }

        // 4. Copy binary payload
        if (binaryPayload.Length > 0)
        {
            binaryPayload.CopyTo(frame.AsSpan(offset));
            offset += binaryPayload.Length;
        }

        // 5. Calculate checksum over payload section (from payloadStartOffset up to current offset)
        ReadOnlySpan<byte> payloadToChecksum = frame.AsSpan(payloadStartOffset, offset - payloadStartOffset);
        int checksumVal = ComputeChecksum(payloadToChecksum);

        // 6. Append checksum tag: "10=XXX|"
        frame[offset++] = (byte)'1';
        frame[offset++] = (byte)'0';
        frame[offset++] = (byte)'=';
        Utf8Formatter.TryFormat(checksumVal, frame.AsSpan(offset), out _, new System.Buffers.StandardFormat('D', 3));
        offset += 3;
        frame[offset++] = PipeByte;

        return frame;
    }

    /// <summary>
    /// Attempts to parse a single complete message frame from a ReadOnlySequence buffer.
    /// Uses zero-allocation Utf8Parser for primitive integers and ArrayPool for span access.
    /// </summary>
    /// <param name="buffer">The incoming pipe reader buffer.</param>
    /// <param name="message">The parsed Message2 object if successful.</param>
    /// <param name="maxFrameSizeBytes">Maximum allowed frame payload size in bytes. Defaults to 10 MB.</param>
    /// <returns>True if a frame was successfully parsed; false if incomplete.</returns>
    public static bool TryParseFrame(ref ReadOnlySequence<byte> buffer, out Message2? message, int maxFrameSizeBytes = 10 * 1024 * 1024)
    {
        message = null;
        if (buffer.IsEmpty)
            return false;

        var reader = new SequenceReader<byte>(buffer);

        // 1. Parse MessageType opcode up to first '|'
        if (!reader.TryReadTo(out ReadOnlySpan<byte> msgTypeSpan, PipeByte, advancePastDelimiter: true))
        {
            return false;
        }

        if (!Utf8Parser.TryParse(msgTypeSpan, out int msgTypeId, out _))
        {
            throw new InvalidOperationException($"Invalid protocol frame: MessageType opcode is not a valid UTF-8 integer ({Encoding.UTF8.GetString(msgTypeSpan)}).");
        }

        // 2. Parse PayloadLength up to second '|'
        if (!reader.TryReadTo(out ReadOnlySpan<byte> lengthSpan, PipeByte, advancePastDelimiter: true))
        {
            return false;
        }

        if (!Utf8Parser.TryParse(lengthSpan, out int payloadLength, out _))
        {
            throw new InvalidOperationException($"Invalid protocol frame: PayloadLength is not a valid UTF-8 integer ({Encoding.UTF8.GetString(lengthSpan)}).");
        }

        if (payloadLength < 7)
        {
            throw new InvalidOperationException($"Invalid protocol frame: PayloadLength ({payloadLength}) is shorter than minimum checksum tag length (7).");
        }

        // Upper safety bound guard (configurable frame limit)
        if (payloadLength > maxFrameSizeBytes)
        {
            throw new InvalidOperationException($"Protocol framing error: PayloadLength ({payloadLength} bytes) exceeds maximum frame limit of {maxFrameSizeBytes / (1024 * 1024)} MB.");
        }

        // 3. Ensure we have the full payload in the buffer
        if (reader.Remaining < payloadLength)
        {
            return false; // Incomplete packet, wait for more stream bytes
        }

        // Slice payload sequence
        ReadOnlySequence<byte> payloadSequence = buffer.Slice(reader.Position, payloadLength);

        // Avoid allocation: use single-segment span directly, or rent buffer from ArrayPool if multi-segment
        byte[]? rented = null;
        ReadOnlySpan<byte> payloadSpan;

        if (payloadSequence.IsSingleSegment)
        {
            payloadSpan = payloadSequence.FirstSpan;
        }
        else
        {
            rented = ArrayPool<byte>.Shared.Rent(payloadLength);
            payloadSequence.CopyTo(rented);
            payloadSpan = rented.AsSpan(0, payloadLength);
        }

        try
        {
            // 4. Verify checksum tag "10=XXX|" at the end of the payload
            if (payloadSpan.Length < 7 || payloadSpan[^1] != PipeByte)
            {
                throw new InvalidOperationException("Protocol checksum error: Frame payload missing closing pipe delimiter '|'.");
            }

            int checksumTagStart = payloadSpan.Length - 7;
            string checksumTagStr = Encoding.UTF8.GetString(payloadSpan.Slice(checksumTagStart, 7));

            if (!checksumTagStr.StartsWith("10=") || !checksumTagStr.EndsWith("|"))
            {
                throw new InvalidOperationException($"Protocol checksum error: Invalid checksum tag format '{checksumTagStr}'. Expected '10=XXX|'.");
            }

            if (!int.TryParse(checksumTagStr.AsSpan(3, 3), out int expectedChecksum))
            {
                throw new InvalidOperationException($"Protocol checksum error: Invalid checksum value in '{checksumTagStr}'.");
            }

            // Calculate checksum over payload content before the checksum tag
            ReadOnlySpan<byte> contentToVerify = payloadSpan.Slice(0, checksumTagStart);
            int calculatedChecksum = ComputeChecksum(contentToVerify);

            if (calculatedChecksum != expectedChecksum)
            {
                throw new InvalidOperationException($"Protocol checksum mismatch: Calculated {calculatedChecksum:D3}, Expected {expectedChecksum:D3}. Frame corrupt.");
            }

            // 5. Parse ArgsCount and Arguments
            string[] args = Array.Empty<string>();
            byte[] binaryPayload = Array.Empty<byte>();

            // Read ArgsCount up to next '|'
            int firstPipe = -1;
            for (int i = 0; i < contentToVerify.Length; i++)
            {
                if (contentToVerify[i] == PipeByte)
                {
                    firstPipe = i;
                    break;
                }
            }

            if (firstPipe > 0 && Utf8Parser.TryParse(contentToVerify.Slice(0, firstPipe), out int argsCount, out _))
            {
                int currentOffset = firstPipe + 1;

                if (argsCount > 0)
                {
                    args = new string[argsCount];
                    for (int a = 0; a < argsCount; a++)
                    {
                        int nextPipe = -1;
                        for (int i = currentOffset; i < contentToVerify.Length; i++)
                        {
                            if (contentToVerify[i] == PipeByte)
                            {
                                nextPipe = i;
                                break;
                            }
                        }

                        if (nextPipe >= currentOffset)
                        {
                            string rawArg = Encoding.UTF8.GetString(contentToVerify.Slice(currentOffset, nextPipe - currentOffset));
                            args[a] = Uri.UnescapeDataString(rawArg);
                            currentOffset = nextPipe + 1;
                        }
                        else
                        {
                            args[a] = string.Empty;
                        }
                    }
                }

                // Remaining bytes after arguments section is binary payload
                int remainingBinaryLength = contentToVerify.Length - currentOffset;
                if (remainingBinaryLength > 0)
                {
                    binaryPayload = contentToVerify.Slice(currentOffset, remainingBinaryLength).ToArray();
                }
            }

            // Construct parsed message
            message = new Message2
            {
                MsgType = (MessageType)msgTypeId,
                MsgLength = payloadLength,
                Arguments = args,
                BinaryPayload = binaryPayload,
                Checksum = calculatedChecksum
            };

            // Advance buffer slice past the entire frame header + payload
            buffer = buffer.Slice(reader.Position).Slice(payloadLength);
            return true;
        }
        finally
        {
            if (rented != null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }
}
