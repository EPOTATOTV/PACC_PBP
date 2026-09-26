// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

use crate::decoder::PbpDecoder;
use crate::encoder::PbpEncoder;
use crate::error::Result;
use crate::message::PbpMessage;

/// PBP 消息 `ApmSnapshot`，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
///
/// 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApmSnapshot {
    /// MDL 字段 1 `cpu_usage`。
    pub cpu_usage: f32,
    /// MDL 字段 2 `memory_usage_kb`。
    pub memory_usage_kb: i32,
    /// MDL 字段 3 `fps`。
    pub fps: f32,
    /// MDL 字段 4 `detection_latency_ms`。
    pub detection_latency_ms: i32,
    /// MDL 字段 5 `active_rules`。
    pub active_rules: i32,
    /// MDL 字段 6 `custom_metrics`。
    pub custom_metrics: Vec<(String, f32)>,
}

impl ApmSnapshot {
    /// 以空值构造（等价于 `Default`）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 以当前值为初值开一个新构造器（例如改完字段要重新签名）。
    pub fn to_builder(&self) -> Self {
        self.clone()
    }

    /// MDL 字段 1 `cpu_usage`。
    pub fn set_cpu_usage(mut self, value: f32) -> Self {
        self.cpu_usage = value;
        self
    }

    /// MDL 字段 2 `memory_usage_kb`。
    pub fn set_memory_usage_kb(mut self, value: i32) -> Self {
        self.memory_usage_kb = value;
        self
    }

    /// MDL 字段 3 `fps`。
    pub fn set_fps(mut self, value: f32) -> Self {
        self.fps = value;
        self
    }

    /// MDL 字段 4 `detection_latency_ms`。
    pub fn set_detection_latency_ms(mut self, value: i32) -> Self {
        self.detection_latency_ms = value;
        self
    }

    /// MDL 字段 5 `active_rules`。
    pub fn set_active_rules(mut self, value: i32) -> Self {
        self.active_rules = value;
        self
    }

    /// MDL 字段 6 `custom_metrics`。
    pub fn set_custom_metrics(mut self, value: Vec<(String, f32)>) -> Self {
        self.custom_metrics = value;
        self
    }

    /// 写入一个 `custom_metrics` 键值对。
    pub fn put_custom_metrics(mut self, key: impl Into<String>, value: f32) -> Self {
        self.custom_metrics.push((key.into(), value));
        self
    }

}

impl PbpMessage for ApmSnapshot {
    fn message_id(&self) -> u16 {
        0
    }

    fn encode(&self, enc: &mut PbpEncoder) {
        enc.write_float32(self.cpu_usage);
        enc.write_int32(self.memory_usage_kb);
        enc.write_float32(self.fps);
        enc.write_int32(self.detection_latency_ms);
        enc.write_int32(self.active_rules);
        enc.write_map(&self.custom_metrics, |e, k| e.write_string(k), |e, v| e.write_float32(*v));
    }

    /// 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    /// 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点。
    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()> {
        self.cpu_usage = dec.read_float32()?;
        self.memory_usage_kb = dec.read_int32()?;
        self.fps = dec.read_float32()?;
        self.detection_latency_ms = dec.read_int32()?;
        self.active_rules = dec.read_int32()?;
        self.custom_metrics = dec.read_map(|d| d.read_string(), |d| d.read_float32())?;
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 0usize;
        size += PbpEncoder::float32_size();
        size += PbpEncoder::int32_size(self.memory_usage_kb);
        size += PbpEncoder::float32_size();
        size += PbpEncoder::int32_size(self.detection_latency_ms);
        size += PbpEncoder::int32_size(self.active_rules);
        size += PbpEncoder::string_map_size(&self.custom_metrics, |_v| PbpEncoder::float32_size());
        size
    }
}