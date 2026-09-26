// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

use crate::codec::PbpCodec;
use crate::decoder::PbpDecoder;
use crate::encoder::PbpEncoder;
use crate::error::PbpError;
use crate::error::Result;
use crate::frame::PbpFrame;
use crate::message::PbpMessage;

/// PBP 消息 `PaccEnvelope`（`0x2001`，0x2000-0x2FFF 双向）。
///
/// 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。
///
/// 签名不在载荷里：置位帧头 `FLAG_SIGNED`，32 字节 HMAC-SHA256 放在帧尾，
/// 覆盖面是「帧头 + 载荷」整串字节（见 `signing_input`）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PaccEnvelope {
    /// MDL 字段 1 `type`。
    pub type_: String,
    /// MDL 字段 2 `ts_ms`。
    pub ts_ms: i64,
    /// MDL 字段 3 `nonce`。
    pub nonce: String,
    /// MDL 字段 4 `session_id`。
    pub session_id: String,
    /// MDL 字段 5 `pteid`。
    pub pteid: String,
    /// MDL 字段 6 `payload_json`。
    pub payload_json: String,
    /// MDL 字段 7 `sig_version`。
    pub sig_version: u8,

    /// 帧尾签名，载荷里没有这个字段。
    pub signature: Vec<u8>,
}

impl PaccEnvelope {
    /// MDL 里声明的消息 ID。
    pub const MESSAGE_ID: u16 = 0x2001;

    /// 以空值构造（等价于 `Default`）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 以当前值为初值开一个新构造器（例如改完字段要重新签名）。
    pub fn to_builder(&self) -> Self {
        self.clone()
    }

    /// MDL 字段 1 `type`。
    pub fn set_type_(mut self, value: impl Into<String>) -> Self {
        self.type_ = value.into();
        self
    }

    /// MDL 字段 2 `ts_ms`。
    pub fn set_ts_ms(mut self, value: i64) -> Self {
        self.ts_ms = value;
        self
    }

    /// MDL 字段 3 `nonce`。
    pub fn set_nonce(mut self, value: impl Into<String>) -> Self {
        self.nonce = value.into();
        self
    }

    /// MDL 字段 4 `session_id`。
    pub fn set_session_id(mut self, value: impl Into<String>) -> Self {
        self.session_id = value.into();
        self
    }

    /// MDL 字段 5 `pteid`。
    pub fn set_pteid(mut self, value: impl Into<String>) -> Self {
        self.pteid = value.into();
        self
    }

    /// MDL 字段 6 `payload_json`。
    pub fn set_payload_json(mut self, value: impl Into<String>) -> Self {
        self.payload_json = value.into();
        self
    }

    /// MDL 字段 7 `sig_version`。
    pub fn set_sig_version(mut self, value: u8) -> Self {
        self.sig_version = value;
        self
    }

    /// 帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。
    pub fn set_signature(mut self, hex: &str) -> Result<Self> {
        self.signature = crate::crypto::hex_decode(hex).ok_or(PbpError::BadFormat)?;
        Ok(self)
    }

    /// 帧尾签名的原始字节。
    pub fn set_signature_bytes(mut self, value: Vec<u8>) -> Self {
        self.signature = value;
        self
    }

    /// 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。
    pub fn to_byte_array(&self) -> Result<Vec<u8>> {
        let frame = PbpCodec::frame_of(self, self.ts_ms)?;
        let frame = if self.signature.len() == PbpFrame::SIGNATURE_SIZE {
            frame.with_signature(&self.signature)?
        } else if self.signature.is_empty() {
            frame
        } else {
            return Err(PbpError::BadLength);
        };
        frame.encode()
    }

    /// HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok(PbpCodec::frame_of(self, self.ts_ms)?.signing_input())
    }

    /// 解析完整帧；帧结构非法或消息 ID 不符一律返回错误。
    /// 置位 FLAG_COMPRESSED 的帧先解压再解码载荷。
    pub fn parse_from(raw: &[u8]) -> Result<Self> {
        let frame = PbpFrame::parse(raw)?;
        if frame.message_id != Self::MESSAGE_ID {
            return Err(PbpError::BadFormat);
        }
        let payload = PbpCodec::payload_of_frame(&frame)?;
        let mut msg = Self::default();
        msg.decode(&mut PbpDecoder::new(&payload))?;
        msg.signature = frame.signature.clone();
        Ok(msg)
    }

    /// 帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。
    pub fn signature_hex(&self) -> String {
        crate::crypto::hex_encode(&self.signature)
    }

}

impl PbpMessage for PaccEnvelope {
    fn message_id(&self) -> u16 {
        Self::MESSAGE_ID
    }

    fn encode(&self, enc: &mut PbpEncoder) {
        enc.write_string(&self.type_);
        enc.write_int64(self.ts_ms);
        enc.write_string(&self.nonce);
        enc.write_string(&self.session_id);
        enc.write_string(&self.pteid);
        enc.write_string(&self.payload_json);
        enc.write_uint8(self.sig_version);
    }

    /// 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    /// 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点。
    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()> {
        self.type_ = dec.read_string()?;
        self.ts_ms = dec.read_int64()?;
        self.nonce = dec.read_string()?;
        self.session_id = dec.read_string()?;
        self.pteid = dec.read_string()?;
        self.payload_json = dec.read_string()?;
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        self.sig_version = if dec.remaining() > 0 { dec.read_uint8()? } else { 0 };
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 0usize;
        size += PbpEncoder::string_size(&self.type_);
        size += PbpEncoder::int64_size(self.ts_ms);
        size += PbpEncoder::string_size(&self.nonce);
        size += PbpEncoder::string_size(&self.session_id);
        size += PbpEncoder::string_size(&self.pteid);
        size += PbpEncoder::string_size(&self.payload_json);
        size += PbpEncoder::uint8_size();
        size
    }
}