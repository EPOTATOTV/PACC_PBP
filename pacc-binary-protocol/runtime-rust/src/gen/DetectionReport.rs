// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

use crate::codec::PbpCodec;
use crate::decoder::PbpDecoder;
use crate::delta::PbpDelta;
use crate::delta::PbpDeltaMessage;
use crate::encoder::PbpEncoder;
use crate::error::PbpError;
use crate::error::Result;
use crate::frame::PbpFrame;
use crate::gen::ApmSnapshot;
use crate::gen::DetectionEvent;
use crate::message::PbpMessage;

/// PBP 消息 `DetectionReport`（`0x0103`，0x0100-0x0FFF 客户端 → 服务端）。
///
/// 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。
///
/// 实现了 [`crate::delta::PbpDeltaMessage`]：可经 [`crate::delta::PbpDeltaChain`] 发差分帧。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionReport {
    /// MDL 字段 1 `pteid`。
    pub pteid: String,
    /// MDL 字段 2 `timestamp`。
    pub timestamp: i64,
    /// MDL 字段 3 `client_version`。
    pub client_version: String,
    /// MDL 字段 4 `platform`。
    pub platform: String,
    /// MDL 字段 5 `events`。
    pub events: Vec<DetectionEvent>,
    /// MDL 字段 6 `apm`。
    pub apm: Option<ApmSnapshot>,
    /// MDL 字段 7 `signature`。
    pub signature: Vec<u8>,
}

impl DetectionReport {
    /// MDL 里声明的消息 ID。
    pub const MESSAGE_ID: u16 = 0x0103;

    /// 可空字段个数，用于定位载荷里的存在性位图。
    pub const OPTIONAL_FIELD_COUNT: usize = 1;

    /// 以空值构造（等价于 `Default`）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 以当前值为初值开一个新构造器（例如改完字段要重新签名）。
    pub fn to_builder(&self) -> Self {
        self.clone()
    }

    /// MDL 字段 1 `pteid`。
    pub fn set_pteid(mut self, value: impl Into<String>) -> Self {
        self.pteid = value.into();
        self
    }

    /// MDL 字段 2 `timestamp`。
    pub fn set_timestamp(mut self, value: i64) -> Self {
        self.timestamp = value;
        self
    }

    /// MDL 字段 3 `client_version`。
    pub fn set_client_version(mut self, value: impl Into<String>) -> Self {
        self.client_version = value.into();
        self
    }

    /// MDL 字段 4 `platform`。
    pub fn set_platform(mut self, value: impl Into<String>) -> Self {
        self.platform = value.into();
        self
    }

    /// MDL 字段 5 `events`。
    pub fn set_events(mut self, value: Vec<DetectionEvent>) -> Self {
        self.events = value;
        self
    }

    /// 追加一个 `events` 元素。
    pub fn add_events(mut self, value: DetectionEvent) -> Self {
        self.events.push(value);
        self
    }

    /// MDL 字段 6 `apm`。
    pub fn set_apm(mut self, value: Option<ApmSnapshot>) -> Self {
        self.apm = value;
        self
    }

    /// MDL 字段 7 `signature`。
    pub fn set_signature(mut self, value: Vec<u8>) -> Self {
        self.signature = value;
        self
    }

    /// 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。
    pub fn to_byte_array(&self) -> Result<Vec<u8>> {
        let frame = PbpCodec::frame_of(self, 0)?;
        frame.encode()
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
        Ok(msg)
    }

}

impl PbpMessage for DetectionReport {
    fn message_id(&self) -> u16 {
        Self::MESSAGE_ID
    }

    fn encode(&self, enc: &mut PbpEncoder) {
        enc.write_string(&self.pteid);
        enc.write_int64(self.timestamp);
        enc.write_string(&self.client_version);
        enc.write_string(&self.platform);
        enc.write_message_list(&self.events);
        enc.write_optional_message(&self.apm);
        enc.write_bytes(&self.signature);
    }

    /// 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    /// 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点。
    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()> {
        self.pteid = dec.read_string()?;
        self.timestamp = dec.read_int64()?;
        self.client_version = dec.read_string()?;
        self.platform = dec.read_string()?;
        self.events = dec.read_message_list::<DetectionEvent>()?;
        self.apm = dec.read_optional_message::<ApmSnapshot>()?;
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        self.signature = if dec.remaining() > 0 { dec.read_bytes()? } else { Vec::new() };
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 0usize;
        size += PbpEncoder::string_size(&self.pteid);
        size += PbpEncoder::int64_size(self.timestamp);
        size += PbpEncoder::string_size(&self.client_version);
        size += PbpEncoder::string_size(&self.platform);
        size += PbpEncoder::message_list_size(&self.events);
        size += PbpEncoder::optional_message_size(&self.apm);
        size += PbpEncoder::bytes_size(&self.signature);
        size
    }
}

impl PbpDeltaMessage<DetectionReport> for DetectionReport {
    /// 相对基线只写变化的字段：存在位图 + 按字段序的变化值。
    fn encode_delta(&self, enc: &mut PbpEncoder, previous: &DetectionReport) {
        let changed: [bool; 7] = [
            self.pteid != previous.pteid,
            self.timestamp != previous.timestamp,
            self.client_version != previous.client_version,
            self.platform != previous.platform,
            PbpDelta::differs(|x| { x.write_message_list(&self.events); }, |x| { x.write_message_list(&previous.events); }),
            PbpDelta::differs(|x| { x.write_optional_message(&self.apm); }, |x| { x.write_optional_message(&previous.apm); }),
            self.signature != previous.signature,
        ];
        enc.write_presence(&changed);
        if changed[0] {
            enc.write_string(&self.pteid);
        }
        if changed[1] {
            enc.write_int64(self.timestamp);
        }
        if changed[2] {
            enc.write_string(&self.client_version);
        }
        if changed[3] {
            enc.write_string(&self.platform);
        }
        if changed[4] {
            enc.write_message_list(&self.events);
        }
        if changed[5] {
            enc.write_optional_message(&self.apm);
        }
        if changed[6] {
            enc.write_bytes(&self.signature);
        }
    }

    /// 未变化的字段从基线拷贝，变化的字段按位图读入；传入的基线对象不会被改动。
    fn apply_delta(&mut self, dec: &mut PbpDecoder<'_>, previous: &DetectionReport) -> Result<()> {
        let present = dec.read_presence(7)?;
        self.pteid = if present[0] { dec.read_string()? } else { previous.pteid.clone() };
        self.timestamp = if present[1] { dec.read_int64()? } else { previous.timestamp };
        self.client_version = if present[2] { dec.read_string()? } else { previous.client_version.clone() };
        self.platform = if present[3] { dec.read_string()? } else { previous.platform.clone() };
        self.events = if present[4] { dec.read_message_list::<DetectionEvent>()? } else { PbpDelta::copy_list(&previous.events)? };
        self.apm = if present[5] { dec.read_optional_message::<ApmSnapshot>()? } else { PbpDelta::copy_option(previous.apm.as_ref())? };
        self.signature = if present[6] { dec.read_bytes()? } else { previous.signature.clone() };
        Ok(())
    }
}