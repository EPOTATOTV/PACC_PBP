// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

use crate::decoder::PbpDecoder;
use crate::encoder::PbpEncoder;
use crate::error::Result;
use crate::message::PbpMessage;

/// PBP 消息 `DetectionEvent`，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
///
/// 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectionEvent {
    /// MDL 字段 1 `event_type`。
    pub event_type: i32,
    /// MDL 字段 2 `confidence`。
    pub confidence: f32,
    /// MDL 字段 3 `timestamp`。
    pub timestamp: i64,
    /// MDL 字段 4 `evidence`。
    pub evidence: Vec<(String, Vec<u8>)>,
    /// MDL 字段 5 `detail`。
    pub detail: Option<String>,
}

impl DetectionEvent {
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

    /// MDL 字段 1 `event_type`。
    pub fn set_event_type(mut self, value: i32) -> Self {
        self.event_type = value;
        self
    }

    /// MDL 字段 2 `confidence`。
    pub fn set_confidence(mut self, value: f32) -> Self {
        self.confidence = value;
        self
    }

    /// MDL 字段 3 `timestamp`。
    pub fn set_timestamp(mut self, value: i64) -> Self {
        self.timestamp = value;
        self
    }

    /// MDL 字段 4 `evidence`。
    pub fn set_evidence(mut self, value: Vec<(String, Vec<u8>)>) -> Self {
        self.evidence = value;
        self
    }

    /// 写入一个 `evidence` 键值对。
    pub fn put_evidence(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.evidence.push((key.into(), value));
        self
    }

    /// MDL 字段 5 `detail`。
    pub fn set_detail(mut self, value: Option<String>) -> Self {
        self.detail = value;
        self
    }

}

impl PbpMessage for DetectionEvent {
    fn message_id(&self) -> u16 {
        0
    }

    fn encode(&self, enc: &mut PbpEncoder) {
        enc.write_int32(self.event_type);
        enc.write_float32(self.confidence);
        enc.write_int64(self.timestamp);
        enc.write_map(&self.evidence, |e, k| e.write_string(k), |e, v| e.write_bytes(v));
        enc.write_optional_string(&self.detail);
    }

    /// 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    /// 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点。
    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()> {
        self.event_type = dec.read_int32()?;
        self.confidence = dec.read_float32()?;
        self.timestamp = dec.read_int64()?;
        self.evidence = dec.read_map(|d| d.read_string(), |d| d.read_bytes())?;
        self.detail = dec.read_optional_string()?;
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 0usize;
        size += PbpEncoder::int32_size(self.event_type);
        size += PbpEncoder::float32_size();
        size += PbpEncoder::int64_size(self.timestamp);
        size += PbpEncoder::string_map_size(&self.evidence, |v| PbpEncoder::bytes_size(v));
        size += PbpEncoder::optional_string_size(&self.detail);
        size
    }
}