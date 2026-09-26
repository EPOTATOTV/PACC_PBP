//! PBP 编解码与帧解析错误。
//!
//! 分枚举值而不是一律 `String`，是为了让调用方能区分「对端说了听不懂的话」和
//! 「对端在攻击我」：magic/version 不符多半是协议不匹配或旧版本残留，
//! [`PbpError::TagMismatch`] 与长度不符则是明确的篡改信号。

use std::fmt;

/// 失败原因分类，与 `runtime-java` 的 `PbpException.Code` 一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbpError {
    /// 帧头 magic 不是 "PB"。
    BadMagic,
    /// 协议版本不认识。
    BadVersion,
    /// 标志位要求了当前版本尚未实现的能力。
    UnsupportedFlag,
    /// 数据本身合法，但用到了子集之外的能力（如 zstd 的 Huffman literals）。
    Unsupported,
    /// 声明长度与实际字节数不符。
    BadLength,
    /// 签名校验不通过。
    TagMismatch,
    /// 数据在读完之前就结束了。
    Truncated,
    /// VarInt 超过 10 字节或编码非法。
    BadVarint,
    /// 字段内容不符合定义（如 UTF-8 非法、集合长度超限）。
    BadFormat,
}

impl fmt::Display for PbpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            PbpError::BadMagic => "帧头 magic 不是 \"PB\"",
            PbpError::BadVersion => "协议版本不认识",
            PbpError::UnsupportedFlag => "标志位要求了未实现的能力",
            PbpError::Unsupported => "用到了 zstd 子集之外的能力",
            PbpError::BadLength => "声明长度与实际字节数不符",
            PbpError::TagMismatch => "签名校验不通过",
            PbpError::Truncated => "数据在读完之前就结束了",
            PbpError::BadVarint => "VarInt 编码非法",
            PbpError::BadFormat => "字段内容不符合定义",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PbpError {}

/// 本 crate 统一的返回类型。
pub type Result<T> = std::result::Result<T, PbpError>;