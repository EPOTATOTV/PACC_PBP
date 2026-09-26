//! PBP 消息帧：固定 30 字节帧头 + 载荷 + 可选 32 字节签名。
//!
//! ```text
//!   偏移  长度  字段
//!   0     2     Magic        0x5042 "PB"
//!   2     1     Version      协议版本，当前 1
//!   3     1     Flags        bit0 加密 / bit1 压缩 / bit2 差分 / bit3 签名
//!   4     2     MessageID    uint16
//!   6     4     Sequence     uint32
//!   10    8     Timestamp    int64 毫秒
//!   18    8     SessionID    uint64
//!   26    4     PayloadLen   uint32
//!   30    N     Payload
//!   30+N  32    Signature    HMAC-SHA256（Flags bit3 置位时存在）
//! ```
//!
//! 多字节字段一律小端，唯一例外是开头的 2 字节 Magic：它是 ASCII 标记，按 'P','B'
//! 顺序写（即字节 0x50、0x42），不像数值字段那样小端展开成 0x42、0x50。
//!
//! 本模块只负责布局与长度校验，不碰密码学：签名计算与验证走 [`crate::crypto`]，
//! 这样帧解析可以在没有密钥的场景（如抓包分析）下单独使用。

use crate::error::{PbpError, Result};

/// Magic "PB"。
pub const MAGIC: u16 = 0x5042;
/// 当前协议版本。
pub const VERSION: u8 = 1;
/// 还能解析的最旧版本；解析接受区间 [MIN_VERSION, VERSION] 内任意版本，编码永远输出当前版本。
pub const MIN_VERSION: u8 = 1;

pub const HEADER_SIZE: usize = 30;
pub const SIGNATURE_SIZE: usize = 32;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_COMPRESSED: u8 = 0x02;
pub const FLAG_DELTA: u8 = 0x04;
pub const FLAG_SIGNED: u8 = 0x08;

/// 已知标志位掩码；其余位为保留位，置位即视为协议不认识。
const KNOWN_FLAGS: u8 = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_DELTA | FLAG_SIGNED;

/// 载荷长度硬上限：帧头的 PayloadLen 是 uint32，真按它分配就等于把内存交给对端控制。
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// PBP 消息帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbpFrame {
    pub version: u8,
    pub flags: u8,
    pub message_id: u16,
    pub sequence: u32,
    pub timestamp_ms: i64,
    pub session_id: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl PbpFrame {
    pub const MAGIC: u16 = MAGIC;
    pub const VERSION: u8 = VERSION;
    pub const MIN_VERSION: u8 = MIN_VERSION;
    pub const HEADER_SIZE: usize = HEADER_SIZE;
    pub const SIGNATURE_SIZE: usize = SIGNATURE_SIZE;
    pub const MAX_PAYLOAD_SIZE: usize = MAX_PAYLOAD_SIZE;
    pub const FLAG_ENCRYPTED: u8 = FLAG_ENCRYPTED;
    pub const FLAG_COMPRESSED: u8 = FLAG_COMPRESSED;
    pub const FLAG_DELTA: u8 = FLAG_DELTA;
    pub const FLAG_SIGNED: u8 = FLAG_SIGNED;

    pub fn new(
        version: u8,
        flags: u8,
        message_id: u16,
        sequence: u32,
        timestamp_ms: i64,
        session_id: u64,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        PbpFrame { version, flags, message_id, sequence, timestamp_ms, session_id, payload, signature }
    }

    /// 构造一条无签名帧（sessionId 与 sequence 默认 0，由需要它们的上层显式覆盖）。
    pub fn of(message_id: u16, timestamp_ms: i64, payload: Vec<u8>) -> Self {
        PbpFrame::new(VERSION, 0, message_id, 0, timestamp_ms, 0, payload, Vec::new())
    }

    pub fn signed(&self) -> bool {
        self.flags & FLAG_SIGNED != 0
    }

    /// 载荷是否已压缩。
    pub fn compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    /// 载荷是否为差分编码。
    pub fn delta(&self) -> bool {
        self.flags & FLAG_DELTA != 0
    }

    /// 返回置位指定标志的副本；只允许置已知标志位。
    pub fn with_flag(mut self, flag: u8) -> Result<Self> {
        if flag == 0 {
            return Ok(self);
        }
        if flag & !KNOWN_FLAGS != 0 || flag == FLAG_ENCRYPTED {
            return Err(PbpError::UnsupportedFlag);
        }
        self.flags |= flag;
        Ok(self)
    }

    pub fn payload_length(&self) -> usize {
        self.payload.len()
    }

    /// 返回带签名的副本：置位 FLAG_SIGNED 并写入 32 字节签名。
    ///
    /// 签名覆盖 [`PbpFrame::signing_input`]，其中帧头是按 FLAG_SIGNED 已置位的形态
    /// 计算的，因此签名方与验签方拿到的是同一串字节。
    pub fn with_signature(mut self, signature: &[u8]) -> Result<Self> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(PbpError::BadLength);
        }
        self.flags |= FLAG_SIGNED;
        self.signature = signature.to_vec();
        Ok(self)
    }

    /// HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。
    ///
    /// 签名必须覆盖帧头而不是只盖载荷，否则 messageId / timestamp / sessionId 都能被
    /// 中间人改写而验签照样通过。
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        self.put_header(&mut out, self.flags | FLAG_SIGNED, self.payload.len());
        out.extend_from_slice(&self.payload);
        out
    }

    /// 序列化为完整帧字节；签名是否存在由 FLAG_SIGNED 决定。
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_flags(self.flags)?;
        if self.version != VERSION {
            return Err(PbpError::BadVersion);
        }
        let payload_len = self.payload.len();
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(PbpError::BadLength);
        }
        let is_signed = self.signed();
        if is_signed && self.signature.len() != SIGNATURE_SIZE {
            return Err(PbpError::BadLength);
        }
        if !is_signed && !self.signature.is_empty() {
            return Err(PbpError::BadFormat);
        }

        let mut out = Vec::with_capacity(HEADER_SIZE + payload_len + if is_signed { SIGNATURE_SIZE } else { 0 });
        self.put_header(&mut out, self.flags, payload_len);
        out.extend_from_slice(&self.payload);
        if is_signed {
            out.extend_from_slice(&self.signature);
        }
        Ok(out)
    }

    /// 解析完整帧；任何长度或标志位不符都返回错误。
    pub fn parse(raw: &[u8]) -> Result<PbpFrame> {
        if raw.len() < HEADER_SIZE {
            return Err(PbpError::Truncated);
        }
        let magic = ((raw[0] as u16) << 8) | (raw[1] as u16);
        if magic != MAGIC {
            return Err(PbpError::BadMagic);
        }
        let version = raw[2];
        if version < MIN_VERSION || version > VERSION {
            return Err(PbpError::BadVersion);
        }
        let flags = raw[3];
        validate_flags(flags)?;

        let payload_len = read_u32(raw, 26) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(PbpError::BadLength);
        }
        let expected = HEADER_SIZE + payload_len + if flags & FLAG_SIGNED != 0 { SIGNATURE_SIZE } else { 0 };
        if raw.len() != expected {
            return Err(PbpError::BadLength);
        }

        let payload = raw[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();
        let signature = if flags & FLAG_SIGNED != 0 {
            raw[HEADER_SIZE + payload_len..expected].to_vec()
        } else {
            Vec::new()
        };

        Ok(PbpFrame {
            version,
            flags,
            message_id: u16::from_le_bytes([raw[4], raw[5]]),
            sequence: read_u32(raw, 6),
            timestamp_ms: i64::from_le_bytes(raw[10..18].try_into().unwrap()),
            session_id: u64::from_le_bytes(raw[18..26].try_into().unwrap()),
            payload,
            signature,
        })
    }

    fn put_header(&self, out: &mut Vec<u8>, flags: u8, payload_len: usize) {
        // Magic 是 ASCII 标记，按可读顺序写 'P','B'；帧头其余多字节字段才是小端。
        out.push((MAGIC >> 8) as u8);
        out.push(MAGIC as u8);
        out.push(self.version);
        out.push(flags);
        out.extend_from_slice(&self.message_id.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    }
}

/// 拒绝尚未实现的标志位。
///
/// 加密位仍然是"未实现"：载荷加密不在帧层，这个位一旦被置位就显式失败——把
/// "对端以为已经加密"的载荷当明文解析是最危险的失败方式。
fn validate_flags(flags: u8) -> Result<()> {
    if flags & FLAG_ENCRYPTED != 0 {
        return Err(PbpError::UnsupportedFlag);
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(PbpError::UnsupportedFlag);
    }
    Ok(())
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    (b[off] as u32)
        | ((b[off + 1] as u32) << 8)
        | ((b[off + 2] as u32) << 16)
        | ((b[off + 3] as u32) << 24)
}