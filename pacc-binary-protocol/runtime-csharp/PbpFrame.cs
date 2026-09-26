using System;

namespace Potatotv.Pbp;

/// <summary>
/// PBP 消息帧：固定 30 字节帧头 + 载荷 + 可选 32 字节签名。
///
/// <pre>
///   偏移  长度  字段
///   0     2     Magic        0x5042 "PB"
///   2     1     Version
///   3     1     Flags        bit0 加密 / bit1 压缩 / bit2 差分 / bit3 签名
///   4     2     MessageID    uint16
///   6     4     Sequence     uint32
///   10    8     Timestamp    int64 毫秒
///   18    8     SessionID    uint64
///   26    4     PayloadLen   uint32
///   30    N     Payload
///   30+N  32    Signature    HMAC-SHA256（Flags bit3 置位时存在）
/// </pre>
///
/// <p>多字节字段一律小端，唯一例外是开头的 2 字节 Magic：按 'P','B' 顺序写。
/// 载荷长度放在帧头，是为了让"新客户端多发了字段"变成可跳过的尾巴，而不是解析错位。</p>
/// </summary>
public sealed class PbpFrame
{
    /// <summary>Magic "PB"。</summary>
    public const int Magic = 0x5042;

    /// <summary>当前协议版本。</summary>
    public const int ProtocolVersion = 1;

    /// <summary>还能解析的最旧版本。</summary>
    public const int MinVersion = 1;

    public const int HeaderSize = 30;

    public const int SignatureSize = 32;

    public const int FlagEncrypted = 0x01;

    public const int FlagCompressed = 0x02;

    public const int FlagDelta = 0x04;

    public const int FlagSigned = 0x08;

    /// <summary>已知标志位掩码；其余位为保留位，置位即视为协议不认识。</summary>
    private const int KnownFlags = FlagEncrypted | FlagCompressed | FlagDelta | FlagSigned;

    /// <summary>载荷长度硬上限：真按帧头声明的长度分配就等于把内存交给对端控制。</summary>
    public const int MaxPayloadSize = 16 * 1024 * 1024;

    private const int OffMagic = 0;
    private const int OffVersion = 2;
    private const int OffFlags = 3;
    private const int OffMessageId = 4;
    private const int OffSequence = 6;
    private const int OffTimestamp = 10;
    private const int OffSessionId = 18;
    private const int OffPayloadLen = 26;

    private readonly byte[] payload;
    private readonly byte[] signature;

    public PbpFrame(int version, int flags, int messageId, uint sequence, long timestampMs,
                    ulong sessionId, byte[]? payload, byte[]? signature)
    {
        Version = version;
        Flags = flags;
        MessageId = messageId;
        Sequence = sequence;
        TimestampMs = timestampMs;
        SessionId = sessionId;
        this.payload = payload == null ? Array.Empty<byte>() : (byte[])payload.Clone();
        this.signature = signature == null ? Array.Empty<byte>() : (byte[])signature.Clone();
    }

    public int Version { get; }

    public int Flags { get; }

    public int MessageId { get; }

    public uint Sequence { get; }

    public long TimestampMs { get; }

    public ulong SessionId { get; }

    public byte[] Payload => (byte[])payload.Clone();

    public byte[] Signature => (byte[])signature.Clone();

    /// <summary>构造一条无签名帧（sessionId 与 sequence 默认 0）。</summary>
    public static PbpFrame Of(int messageId, long timestampMs, byte[] payload) =>
        new PbpFrame(ProtocolVersion, 0, messageId, 0, timestampMs, 0, payload, null);

    public bool Signed => (Flags & FlagSigned) != 0;

    public bool Compressed => (Flags & FlagCompressed) != 0;

    public bool Delta => (Flags & FlagDelta) != 0;

    /// <summary>返回置位指定标志的副本；只允许置已知标志位。</summary>
    public PbpFrame WithFlag(int flag)
    {
        if (flag == 0)
        {
            return this;
        }
        if ((flag & ~KnownFlags) != 0 || flag == FlagEncrypted)
        {
            throw new PbpException(PbpErrorCode.UnsupportedFlag,
                "不能置位未实现的标志: 0x" + flag.ToString("x"));
        }
        return new PbpFrame(Version, Flags | flag, MessageId, Sequence, TimestampMs, SessionId, payload, signature);
    }

    /// <summary>载荷长度，等于 <see cref="Payload"/> 的长度。</summary>
    public int PayloadLength => payload.Length;

    /// <summary>
    /// 返回带签名的副本：置位 <c>FLAG_SIGNED</c> 并写入 32 字节签名。
    ///
    /// <p>签名覆盖 <see cref="SigningInput"/>，其中帧头是按已置位形态计算的，
    /// 因此签名方与验签方拿到的是同一串字节。</p>
    /// </summary>
    public PbpFrame WithSignature(byte[] sig)
    {
        if (sig == null || sig.Length != SignatureSize)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "签名必须是 " + SignatureSize + " 字节，实际 " + (sig == null ? "null" : sig.Length.ToString()));
        }
        return new PbpFrame(Version, Flags | FlagSigned, MessageId, Sequence, TimestampMs, SessionId, payload, sig);
    }

    /// <summary>HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。</summary>
    public byte[] SigningInput()
    {
        int payloadLen = payload.Length;
        byte[] outBytes = new byte[HeaderSize + payloadLen];
        PutHeader(outBytes, Flags | FlagSigned, payloadLen);
        Array.Copy(payload, 0, outBytes, HeaderSize, payloadLen);
        return outBytes;
    }

    /// <summary>序列化为完整帧字节；签名是否存在由 <c>FLAG_SIGNED</c> 决定。</summary>
    public byte[] Encode()
    {
        ValidateFlags(Flags);
        if (Version != ProtocolVersion)
        {
            throw new PbpException(PbpErrorCode.BadVersion,
                "本运行时只支持版本 " + ProtocolVersion + "，不能编码版本 " + Version);
        }
        int payloadLen = payload.Length;
        if (payloadLen > MaxPayloadSize)
        {
            throw new PbpException(PbpErrorCode.BadLength, "载荷长度超上限: " + payloadLen);
        }
        bool isSigned = Signed;
        if (isSigned && signature.Length != SignatureSize)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "帧头声明已签名，但签名长度为 " + signature.Length);
        }
        if (!isSigned && signature.Length != 0)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "带了签名字节但 FLAG_SIGNED 未置位");
        }

        byte[] outBytes = new byte[HeaderSize + payloadLen + (isSigned ? SignatureSize : 0)];
        PutHeader(outBytes, Flags, payloadLen);
        Array.Copy(payload, 0, outBytes, HeaderSize, payloadLen);
        if (isSigned)
        {
            Array.Copy(signature, 0, outBytes, HeaderSize + payloadLen, SignatureSize);
        }
        return outBytes;
    }

    /// <summary>解析完整帧；任何长度或标志位不符都抛 <see cref="PbpException"/>。</summary>
    public static PbpFrame Parse(byte[] raw)
    {
        if (raw == null || raw.Length < HeaderSize)
        {
            throw new PbpException(PbpErrorCode.Truncated,
                "帧长度不足 " + HeaderSize + " 字节: " + (raw == null ? "null" : raw.Length.ToString()));
        }
        int magic = ((raw[OffMagic] & 0xFF) << 8) | (raw[OffMagic + 1] & 0xFF);
        if (magic != Magic)
        {
            throw new PbpException(PbpErrorCode.BadMagic, "Magic 不是 \"PB\": 0x" + magic.ToString("x"));
        }
        int version = raw[OffVersion] & 0xFF;
        if (version < MinVersion)
        {
            throw new PbpException(PbpErrorCode.BadVersion,
                "协议版本过旧: " + version + "（最低支持 " + MinVersion + "）");
        }
        if (version > ProtocolVersion)
        {
            throw new PbpException(PbpErrorCode.BadVersion,
                "协议版本过新: " + version + "（本运行时最高支持 " + ProtocolVersion + "）");
        }
        int flags = raw[OffFlags] & 0xFF;
        ValidateFlags(flags);

        uint payloadLen = GetUInt32(raw, OffPayloadLen);
        if (payloadLen > MaxPayloadSize)
        {
            throw new PbpException(PbpErrorCode.BadLength, "载荷长度超上限: " + payloadLen);
        }
        int expected = HeaderSize + (int)payloadLen + ((flags & FlagSigned) != 0 ? SignatureSize : 0);
        if (raw.Length != expected)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "帧长与 PayloadLen 不符: 实际 " + raw.Length + "，按声明应为 " + expected);
        }

        byte[] parsedPayload = new byte[payloadLen];
        Array.Copy(raw, HeaderSize, parsedPayload, 0, (int)payloadLen);
        byte[] parsedSignature = (flags & FlagSigned) != 0
            ? Slice(raw, HeaderSize + (int)payloadLen, SignatureSize)
            : Array.Empty<byte>();
        return new PbpFrame(version, flags, GetUInt16(raw, OffMessageId), GetUInt32(raw, OffSequence),
            GetInt64(raw, OffTimestamp), GetUInt64(raw, OffSessionId), parsedPayload, parsedSignature);
    }

    /// <summary>拒绝尚未实现的标志位。</summary>
    private static void ValidateFlags(int flags)
    {
        if ((flags & FlagEncrypted) != 0)
        {
            throw new PbpException(PbpErrorCode.UnsupportedFlag,
                "当前版本未实现加密标志位 0x" + FlagEncrypted.ToString("x"));
        }
        int unknown = flags & ~KnownFlags;
        if (unknown != 0)
        {
            throw new PbpException(PbpErrorCode.UnsupportedFlag,
                "保留标志位被置位: 0x" + unknown.ToString("x"));
        }
    }

    private void PutHeader(byte[] outBytes, int flags, int payloadLen)
    {
        // Magic 是 ASCII 标记，按可读顺序写 'P','B'；帧头其余多字节字段才是小端。
        outBytes[OffMagic] = (byte)(Magic >> 8);
        outBytes[OffMagic + 1] = (byte)(Magic & 0xFF);
        outBytes[OffVersion] = (byte)Version;
        outBytes[OffFlags] = (byte)flags;
        PutUInt16(outBytes, OffMessageId, MessageId);
        PutUInt32(outBytes, OffSequence, Sequence);
        PutInt64(outBytes, OffTimestamp, TimestampMs);
        PutUInt64(outBytes, OffSessionId, SessionId);
        PutUInt32(outBytes, OffPayloadLen, (uint)payloadLen);
    }

    // ------------------------------------------------------------ 小端读写

    private static void PutUInt16(byte[] b, int off, int v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
    }

    private static void PutUInt32(byte[] b, int off, uint v)
    {
        for (int i = 0; i < 4; i++)
        {
            b[off + i] = (byte)(v >> (i * 8));
        }
    }

    private static void PutUInt64(byte[] b, int off, ulong v)
    {
        for (int i = 0; i < 8; i++)
        {
            b[off + i] = (byte)(v >> (i * 8));
        }
    }

    private static void PutInt64(byte[] b, int off, long v) => PutUInt64(b, off, unchecked((ulong)v));

    private static int GetUInt16(byte[] b, int off) => (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);

    private static uint GetUInt32(byte[] b, int off)
    {
        uint v = 0;
        for (int i = 0; i < 4; i++)
        {
            v |= (uint)(b[off + i] & 0xFF) << (i * 8);
        }
        return v;
    }

    private static ulong GetUInt64(byte[] b, int off)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++)
        {
            v |= (ulong)(b[off + i] & 0xFF) << (i * 8);
        }
        return v;
    }

    private static long GetInt64(byte[] b, int off) => unchecked((long)GetUInt64(b, off));

    private static byte[] Slice(byte[] src, int offset, int length)
    {
        byte[] outBytes = new byte[length];
        Array.Copy(src, offset, outBytes, 0, length);
        return outBytes;
    }
}