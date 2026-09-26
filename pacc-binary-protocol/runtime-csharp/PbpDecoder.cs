using System;
using System.Collections.Generic;
using System.Text;

namespace Potatotv.Pbp;

/// <summary>
/// PBP 二进制解码器。
///
/// <p>与 <see cref="PbpEncoder"/> 严格镜像：同样的字段顺序、同样的类型宽度。</p>
///
/// <p>所有读取都做边界检查，越界一律抛 <see cref="PbpException"/> 而不是返回默认值 ——
/// 输入来自网络，静默截断会把"攻击者截断了载荷"变成"对端发了个全零消息"。</p>
/// </summary>
public sealed class PbpDecoder
{
    /// <summary>集合元素个数上界：挡住伪造长度的循环消耗。</summary>
    private const int MaxCollectionSize = 1 << 20;

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    private readonly byte[] buf;
    private readonly int limit;
    private int pos;

    public PbpDecoder(byte[] buf)
        : this(buf, 0, buf.Length)
    {
    }

    public PbpDecoder(byte[] buf, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset + length > buf.Length)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "解码窗口越界: offset=" + offset + " length=" + length + " capacity=" + buf.Length);
        }
        this.buf = buf;
        pos = offset;
        limit = offset + length;
    }

    /// <summary>尚未读取的字节数。</summary>
    public int Remaining => limit - pos;

    public bool HasRemaining => pos < limit;

    /// <summary>已消费的字节数（相对解码窗口起点）。</summary>
    public int Position => pos;

    /// <summary>丢弃剩余字节（向前兼容：读完自己认识的字段，尾巴丢掉）。</summary>
    public void SkipRemaining() => pos = limit;

    // ------------------------------------------------------------ 标量

    public bool ReadBool()
    {
        byte b = ReadRaw();
        if (b != 0 && b != 1)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "bool 字段只能是 0/1，读到 " + b);
        }
        return b == 1;
    }

    public int ReadInt8() => (sbyte)ReadRaw();

    public int ReadUInt8() => ReadRaw();

    public int ReadInt16()
    {
        int lo = ReadRaw();
        int hi = ReadRaw();
        return (short)((hi << 8) | lo);
    }

    public int ReadUInt16()
    {
        int lo = ReadRaw();
        int hi = ReadRaw();
        return (hi << 8) | lo;
    }

    public int ReadInt32()
    {
        uint z = (uint)ReadVarInt();
        return unchecked((int)((z >> 1) ^ (uint)(-(int)(z & 1))));
    }

    public uint ReadUInt32()
    {
        ulong v = ReadVarInt();
        if (v > 0xFFFF_FFFFUL)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "uint32 溢出: " + v);
        }
        return (uint)v;
    }

    public long ReadInt64()
    {
        ulong z = ReadVarInt();
        return unchecked((long)((z >> 1) ^ (ulong)(-(long)(z & 1))));
    }

    /// <summary>返回无符号值。</summary>
    public ulong ReadUInt64() => ReadVarInt();

    public int ReadEnum()
    {
        uint v = ReadUInt32();
        if (v > int.MaxValue)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "enum 值溢出: " + v);
        }
        return (int)v;
    }

    public float ReadFloat32()
    {
        int bits = ReadRaw()
            | (ReadRaw() << 8)
            | (ReadRaw() << 16)
            | (ReadRaw() << 24);
        return BitConverter.Int32BitsToSingle(bits);
    }

    public double ReadFloat64()
    {
        long bits = 0;
        for (int i = 0; i < 8; i++)
        {
            bits |= (long)ReadRaw() << (i * 8);
        }
        return BitConverter.Int64BitsToDouble(bits);
    }

    // ------------------------------------------------------------ 变长

    public string ReadString()
    {
        int length = ReadLength();
        string s = DecodeUtf8(pos, length);
        pos += length;
        return s;
    }

    public byte[] ReadBytes()
    {
        int length = ReadLength();
        byte[] outBytes = new byte[length];
        Array.Copy(buf, pos, outBytes, 0, length);
        pos += length;
        return outBytes;
    }

    // ------------------------------------------------------------ 可空字段

    /// <summary>读取 <paramref name="fieldCount"/> 个连续可空字段的存在位图，低位对应更靠前的字段。</summary>
    public bool[] ReadPresence(int fieldCount)
    {
        if (fieldCount < 0)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "可空字段数为负: " + fieldCount);
        }
        int byteCount = (fieldCount + 7) / 8;
        bool[] present = new bool[fieldCount];
        for (int i = 0; i < byteCount; i++)
        {
            int bits = ReadRaw();
            for (int bit = 0; bit < 8; bit++)
            {
                int idx = i * 8 + bit;
                if (idx < fieldCount)
                {
                    present[idx] = (bits & (1 << bit)) != 0;
                }
            }
        }
        return present;
    }

    public string? ReadOptionalString() => ReadPresence(1)[0] ? ReadString() : null;

    public byte[]? ReadOptionalBytes() => ReadPresence(1)[0] ? ReadBytes() : null;

    public T? ReadOptionalMessage<T>(Func<T> factory) where T : class, IPbpMessage =>
        ReadPresence(1)[0] ? ReadMessage(factory) : null;

    // ------------------------------------------------------------ 消息与集合

    public T ReadMessage<T>(Func<T> factory) where T : IPbpMessage
    {
        T msg = factory();
        msg.Decode(this);
        return msg;
    }

    public List<T> ReadMessageList<T>(Func<T> factory) where T : IPbpMessage
    {
        int count = ReadCount("list");
        List<T> list = new List<T>(count);
        for (int i = 0; i < count; i++)
        {
            list.Add(ReadMessage(factory));
        }
        return list;
    }

    public List<string> ReadStringList() => ReadList(static dec => dec.ReadString());

    /// <summary>
    /// 通用列表。元素个数上界单独设限：不能拿"每元素至少 1 字节"去卡，
    /// 因为无字段的嵌套消息合法地编码成 0 字节。
    /// </summary>
    public List<T> ReadList<T>(Func<PbpDecoder, T> elementReader)
    {
        int count = ReadCount("list");
        List<T> list = new List<T>(count);
        for (int i = 0; i < count; i++)
        {
            list.Add(elementReader(this));
        }
        return list;
    }

    public Dictionary<K, V> ReadMap<K, V>(Func<PbpDecoder, K> keyReader, Func<PbpDecoder, V> valueReader)
        where K : notnull
    {
        int count = ReadCount("map");
        Dictionary<K, V> map = new Dictionary<K, V>(count);
        for (int i = 0; i < count; i++)
        {
            K key = keyReader(this);
            V value = valueReader(this);
            map[key] = value;
        }
        return map;
    }

    public Dictionary<string, V> ReadStringMap<V>(Func<PbpDecoder, V> valueReader) =>
        ReadMap(static dec => dec.ReadString(), valueReader);

    // ------------------------------------------------------------ 落地

    private byte ReadRaw()
    {
        if (pos >= limit)
        {
            throw new PbpException(PbpErrorCode.Truncated, "读取越界: 位置 " + pos + " 已达上限 " + limit);
        }
        return buf[pos++];
    }

    /// <summary>VarInt 解码，最多 10 字节；超过 10 字节或第 10 字节溢出 64 位一律拒绝。</summary>
    private ulong ReadVarInt()
    {
        ulong value = 0;
        for (int i = 0; i < PbpEncoder.MaxVarIntBytes; i++)
        {
            byte b = ReadRaw();
            if (i == 9 && (b & 0xFE) != 0)
            {
                throw new PbpException(PbpErrorCode.BadVarInt, "VarInt 第 10 字节溢出 64 位");
            }
            value |= (ulong)(b & 0x7F) << (i * 7);
            if ((b & 0x80) == 0)
            {
                return value;
            }
        }
        throw new PbpException(PbpErrorCode.BadVarInt, "VarInt 超过 10 字节");
    }

    private int ReadLength()
    {
        ulong length = ReadVarInt();
        if (length > (ulong)Remaining)
        {
            throw new PbpException(PbpErrorCode.Truncated,
                "变长字段声明长度 " + length + " 超出剩余 " + Remaining + " 字节");
        }
        return (int)length;
    }

    private int ReadCount(string what)
    {
        ulong count = ReadVarInt();
        if (count > MaxCollectionSize)
        {
            throw new PbpException(PbpErrorCode.BadFormat, what + " 元素个数越界: " + count);
        }
        return (int)count;
    }

    /// <summary>严格 UTF-8 解码：非法字节序列直接失败。</summary>
    private string DecodeUtf8(int offset, int length)
    {
        try
        {
            return StrictUtf8.GetString(buf, offset, length);
        }
        catch (DecoderFallbackException e)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "字符串字段不是合法 UTF-8", e);
        }
    }
}