using System;
using System.Collections.Generic;
using System.Text;

namespace Potatotv.Pbp;

/// <summary>
/// PBP 二进制编码器。
///
/// <p>字段按 MDL 定义顺序写入、不带标签：省掉每个字段 1-2 字节的标签开销，代价是
/// 编解码双方必须持有同一份字段顺序定义，且新字段只能加在末尾。</p>
///
/// <p>多字节定长字段一律小端；VarInt 按无符号处理，所以负数 ZigZag 之后才能得到短编码。</p>
/// </summary>
public sealed class PbpEncoder
{
    /// <summary>VarInt 最多 10 字节（每 7 位一组，64 位需要 10 组）。</summary>
    public const int MaxVarIntBytes = 10;

    private readonly List<byte> buf = new List<byte>(64);

    /// <summary>已写入的字节数。</summary>
    public int Size => buf.Count;

    /// <summary>复制出当前已写入的字节。</summary>
    public byte[] ToByteArray() => buf.ToArray();

    /// <summary>清空缓冲区以便复用。</summary>
    public void Reset() => buf.Clear();

    // ------------------------------------------------------------ 标量

    public PbpEncoder WriteBool(bool v) => WriteRaw(v ? (byte)1 : (byte)0);

    public PbpEncoder WriteInt8(int v)
    {
        RequireRange(v, sbyte.MinValue, sbyte.MaxValue, "int8");
        return WriteRaw((byte)v);
    }

    public PbpEncoder WriteUInt8(int v)
    {
        RequireRange(v, 0, 0xFF, "uint8");
        return WriteRaw((byte)v);
    }

    public PbpEncoder WriteInt16(int v)
    {
        RequireRange(v, short.MinValue, short.MaxValue, "int16");
        return WriteRaw((byte)v).WriteRaw((byte)(v >> 8));
    }

    public PbpEncoder WriteUInt16(int v)
    {
        RequireRange(v, 0, 0xFFFF, "uint16");
        return WriteRaw((byte)v).WriteRaw((byte)(v >> 8));
    }

    /// <summary>int32 走 ZigZag + VarInt（负数不会占满 10 字节）。</summary>
    public PbpEncoder WriteInt32(int v)
    {
        WriteVarInt(unchecked((ulong)(uint)((v << 1) ^ (v >> 31))));
        return this;
    }

    /// <summary>uint32 走 VarInt。</summary>
    public PbpEncoder WriteUInt32(uint v)
    {
        WriteVarInt(v);
        return this;
    }

    /// <summary>int64 走 ZigZag + VarInt。</summary>
    public PbpEncoder WriteInt64(long v)
    {
        WriteVarInt(unchecked((ulong)((v << 1) ^ (v >> 63))));
        return this;
    }

    /// <summary>uint64 走 VarInt，原始位模式即无符号值。</summary>
    public PbpEncoder WriteUInt64(ulong v)
    {
        WriteVarInt(v);
        return this;
    }

    public PbpEncoder WriteEnum(int v)
    {
        if (v < 0)
        {
            throw BadFormat("enum 值不能为负: " + v);
        }
        WriteVarInt((ulong)v);
        return this;
    }

    public PbpEncoder WriteFloat32(float v)
    {
        int bits = BitConverter.SingleToInt32Bits(v);
        return WriteRaw((byte)bits)
            .WriteRaw((byte)(bits >> 8))
            .WriteRaw((byte)(bits >> 16))
            .WriteRaw((byte)(bits >> 24));
    }

    public PbpEncoder WriteFloat64(double v)
    {
        long bits = BitConverter.DoubleToInt64Bits(v);
        for (int i = 0; i < 8; i++)
        {
            WriteRaw((byte)(bits >> (i * 8)));
        }
        return this;
    }

    // ------------------------------------------------------------ 变长

    /// <summary>UTF-8 字符串：VarInt 字节长度 + 数据。null 必须走 <see cref="WriteOptionalString"/>。</summary>
    public PbpEncoder WriteString(string s)
    {
        if (s == null)
        {
            throw BadFormat("string 字段为 null，可空字段请用 WriteOptionalString");
        }
        byte[] b = Encoding.UTF8.GetBytes(s);
        WriteVarInt((ulong)b.Length);
        return WriteRaw(b, 0, b.Length);
    }

    public PbpEncoder WriteBytes(byte[] b)
    {
        if (b == null)
        {
            throw BadFormat("bytes 字段为 null，可空字段请用 WriteOptionalBytes");
        }
        WriteVarInt((ulong)b.Length);
        return WriteRaw(b, 0, b.Length);
    }

    // ------------------------------------------------------------ 可空字段

    /// <summary>
    /// 写入一段连续可空字段的存在位图。
    ///
    /// <p>位图必须写在所有对应字段的值之前，低位对应更靠前的字段。</p>
    /// </summary>
    public PbpEncoder WritePresence(params bool[] present)
    {
        int byteCount = (present.Length + 7) / 8;
        for (int i = 0; i < byteCount; i++)
        {
            int bits = 0;
            for (int bit = 0; bit < 8; bit++)
            {
                int idx = i * 8 + bit;
                if (idx < present.Length && present[idx])
                {
                    bits |= 1 << bit;
                }
            }
            WriteRaw((byte)bits);
        }
        return this;
    }

    public PbpEncoder WriteOptionalString(string? s)
    {
        WritePresence(s != null);
        return s == null ? this : WriteString(s);
    }

    public PbpEncoder WriteOptionalBytes(byte[]? b)
    {
        WritePresence(b != null);
        return b == null ? this : WriteBytes(b);
    }

    public PbpEncoder WriteOptionalMessage(IPbpMessage? m)
    {
        WritePresence(m != null);
        return m == null ? this : WriteMessage(m);
    }

    // ------------------------------------------------------------ 消息与集合

    /// <summary>嵌套消息内联编码，不加长度前缀：字段顺序即边界，由最外层帧的 PayloadLen 兜底。</summary>
    public PbpEncoder WriteMessage(IPbpMessage m)
    {
        if (m == null)
        {
            throw BadFormat("嵌套消息为 null，可空字段请用 WriteOptionalMessage");
        }
        m.Encode(this);
        return this;
    }

    public PbpEncoder WriteMessageList(IEnumerable<IPbpMessage> list)
    {
        if (list == null)
        {
            throw BadFormat("消息列表为 null");
        }
        List<IPbpMessage> items = new List<IPbpMessage>(list);
        WriteVarInt((ulong)items.Count);
        foreach (IPbpMessage m in items)
        {
            m.Encode(this);
        }
        return this;
    }

    public PbpEncoder WriteStringList(IEnumerable<string> list) =>
        WriteList(list, static (enc, s) => enc.WriteString(s));

    /// <summary>通用列表：元素为标量时用 <c>(enc, v) =&gt; enc.WriteInt64(v)</c> 这类回调传入。</summary>
    public PbpEncoder WriteList<T>(IEnumerable<T> list, Action<PbpEncoder, T> elementWriter)
    {
        if (list == null)
        {
            throw BadFormat("列表为 null");
        }
        List<T> items = new List<T>(list);
        WriteVarInt((ulong)items.Count);
        foreach (T e in items)
        {
            elementWriter(this, e);
        }
        return this;
    }

    /// <summary>通用映射：键值对按迭代顺序写入，两侧需使用有序映射才能保证字节一致。</summary>
    public PbpEncoder WriteMap<K, V>(IDictionary<K, V> map,
                                     Action<PbpEncoder, K> keyWriter,
                                     Action<PbpEncoder, V> valueWriter)
    {
        if (map == null)
        {
            throw BadFormat("map 为 null");
        }
        WriteVarInt((ulong)map.Count);
        foreach (KeyValuePair<K, V> e in map)
        {
            keyWriter(this, e.Key);
            valueWriter(this, e.Value);
        }
        return this;
    }

    /// <summary>键固定为 string 的映射。</summary>
    public PbpEncoder WriteStringMap<V>(IDictionary<string, V> map, Action<PbpEncoder, V> valueWriter) =>
        WriteMap(map, static (enc, k) => enc.WriteString(k), valueWriter);

    // ------------------------------------------------------------ 长度预估（纯预分配提示）

    public static int VarIntSize(ulong v)
    {
        int n = 1;
        while ((v & ~0x7FUL) != 0)
        {
            v >>= 7;
            n++;
        }
        return n;
    }

    public static int BoolSize() => 1;

    public static int Int8Size() => 1;

    public static int Uint8Size() => 1;

    public static int Int16Size() => 2;

    public static int Uint16Size() => 2;

    public static int Int32Size(int v) => VarIntSize(unchecked((ulong)(uint)((v << 1) ^ (v >> 31))));

    public static int Uint32Size(uint v) => VarIntSize(v);

    public static int Int64Size(long v) => VarIntSize(unchecked((ulong)((v << 1) ^ (v >> 63))));

    public static int Uint64Size(ulong v) => VarIntSize(v);

    public static int EnumSize(int v) => VarIntSize((ulong)v);

    public static int Float32Size() => 4;

    public static int Float64Size() => 8;

    public static int StringSize(string? s) =>
        s == null ? 0 : VarIntSize((ulong)Encoding.UTF8.GetByteCount(s)) + Encoding.UTF8.GetByteCount(s);

    public static int BytesSize(byte[]? b) => b == null ? 0 : VarIntSize((ulong)b.Length) + b.Length;

    public static int PresenceSize(int fieldCount) => (fieldCount + 7) / 8;

    public static int OptionalStringSize(string? s) => 1 + StringSize(s);

    public static int OptionalBytesSize(byte[]? b) => 1 + BytesSize(b);

    public static int MessageSize(IPbpMessage? m) => m == null ? 0 : m.EncodedSize();

    public static int OptionalMessageSize(IPbpMessage? m) => 1 + MessageSize(m);

    public static int MessageListSize(IEnumerable<IPbpMessage>? list)
    {
        if (list == null)
        {
            return 0;
        }
        int size = 0;
        int count = 0;
        foreach (IPbpMessage m in list)
        {
            size += m.EncodedSize();
            count++;
        }
        return VarIntSize((ulong)count) + size;
    }

    public static int StringListSize(IEnumerable<string>? list)
    {
        if (list == null)
        {
            return 0;
        }
        int size = 0;
        int count = 0;
        foreach (string s in list)
        {
            size += StringSize(s);
            count++;
        }
        return VarIntSize((ulong)count) + size;
    }

    public static int ListSize<T>(IEnumerable<T>? list, Func<T, int> elementSize)
    {
        if (list == null)
        {
            return 0;
        }
        int size = 0;
        int count = 0;
        foreach (T e in list)
        {
            size += elementSize(e);
            count++;
        }
        return VarIntSize((ulong)count) + size;
    }

    public static int MapSize<K, V>(IDictionary<K, V>? map, Func<K, int> keySize, Func<V, int> valueSize)
    {
        if (map == null)
        {
            return 0;
        }
        int size = VarIntSize((ulong)map.Count);
        foreach (KeyValuePair<K, V> e in map)
        {
            size += keySize(e.Key) + valueSize(e.Value);
        }
        return size;
    }

    public static int StringMapSize<V>(IDictionary<string, V>? map, Func<V, int> valueSize) =>
        MapSize(map, static k => StringSize(k), valueSize);

    // ------------------------------------------------------------ 落地

    private PbpEncoder WriteRaw(byte b)
    {
        buf.Add(b);
        return this;
    }

    private PbpEncoder WriteRaw(byte[] src, int offset, int length)
    {
        for (int i = 0; i < length; i++)
        {
            buf.Add(src[offset + i]);
        }
        return this;
    }

    private void WriteVarInt(ulong value)
    {
        while ((value & ~0x7FUL) != 0)
        {
            buf.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        buf.Add((byte)(value & 0x7F));
    }

    private static void RequireRange(long v, long min, long max, string type)
    {
        if (v < min || v > max)
        {
            throw BadFormat(type + " 越界: " + v);
        }
    }

    private static PbpException BadFormat(string message) => new PbpException(PbpErrorCode.BadFormat, message);
}