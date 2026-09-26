using System;
using System.Collections.Generic;

namespace Potatotv.Pbp;

/// <summary>
/// 差分编码的公共工具：字段比较与基线拷贝。
///
/// <p>生成的 EncodeDelta/ApplyDelta 只写"哪个字段变了"，比较与深拷贝的细节集中在这里，
/// 避免每个生成类各写一份。</p>
///
/// <p>比较分两条路：标量/字符串/字节数组直接比较值；嵌套消息、列表、映射按"同一套
/// 编码调用写出来的字节"比较——它们的相等性与字段顺序、元素顺序天然一致。</p>
/// </summary>
public static class PbpDelta
{
    /// <summary>两个字段是否不同：把同一套 writer 调用分别写进临时编码器，比字节。</summary>
    public static bool Differs(Action<PbpEncoder> current, Action<PbpEncoder> previous)
    {
        PbpEncoder a = new PbpEncoder();
        PbpEncoder b = new PbpEncoder();
        current(a);
        previous(b);
        return !BytesEqual(a.ToByteArray(), b.ToByteArray());
    }

    /// <summary>字节数组相等（长度与逐字节）。</summary>
    public static bool BytesEqual(byte[]? a, byte[]? b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }
        if (a == null || b == null || a.Length != b.Length)
        {
            return false;
        }
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>深拷贝消息（编解码往返）；null 原样返回。</summary>
    public static T? Copy<T>(T? message, Func<T> factory) where T : class, IPbpMessage
    {
        if (message is null)
        {
            return null;
        }
        T clone = factory();
        clone.Decode(new PbpDecoder(PbpCodec.PayloadOf(message)));
        return clone;
    }

    /// <summary>深拷贝消息列表（列表字段在生成代码里默认非空）。</summary>
    public static List<T> CopyList<T>(IReadOnlyList<T> list, Func<T> factory) where T : class, IPbpMessage
    {
        List<T> clone = new List<T>(list.Count);
        foreach (T element in list)
        {
            clone.Add(Copy(element, factory)!);
        }
        return clone;
    }

    /// <summary>深拷贝消息映射的值（映射字段在生成代码里默认非空）。</summary>
    public static Dictionary<K, V> CopyMap<K, V>(IDictionary<K, V> map, Func<V> factory)
        where K : notnull
        where V : class, IPbpMessage
    {
        Dictionary<K, V> clone = new Dictionary<K, V>(map.Count);
        foreach (KeyValuePair<K, V> entry in map)
        {
            clone[entry.Key] = Copy(entry.Value, factory)!;
        }
        return clone;
    }
}