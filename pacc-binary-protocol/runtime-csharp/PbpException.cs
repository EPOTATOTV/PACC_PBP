using System;

namespace Potatotv.Pbp;

/// <summary>失败原因分类，与 Java 侧 <c>PbpException.Code</c> 一一对应。</summary>
public enum PbpErrorCode
{
    /// <summary>帧头 magic 不是 "PB"。</summary>
    BadMagic,

    /// <summary>协议版本不认识。</summary>
    BadVersion,

    /// <summary>标志位要求了当前版本尚未实现的能力。</summary>
    UnsupportedFlag,

    /// <summary>数据本身合法，但用到了当前实现在该格式上明确的子集之外的能力。</summary>
    Unsupported,

    /// <summary>声明长度与实际字节数不符。</summary>
    BadLength,

    /// <summary>签名校验不通过。</summary>
    TagMismatch,

    /// <summary>数据在读完之前就结束了。</summary>
    Truncated,

    /// <summary>VarInt 超过 10 字节或编码非法。</summary>
    BadVarInt,

    /// <summary>字段内容不符合定义（如 UTF-8 非法、集合长度超限）。</summary>
    BadFormat,
}

/// <summary>
/// PBP 编解码与帧解析异常。
///
/// <p>带 <see cref="Code"/> 是为了让调用方能区分「对端说了听不懂的话」和「对端在攻击我」：
/// magic/version 不符多半是协议不匹配或旧版本残留，tag 不匹配与长度不符则是明确的篡改信号。</p>
/// </summary>
public sealed class PbpException : Exception
{
    public PbpException(PbpErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    public PbpException(PbpErrorCode code, string message, Exception? innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    public PbpErrorCode Code { get; }
}