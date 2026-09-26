//! 载荷 ↔ 帧的组装层。
//!
//! 把「消息编码 → 压缩策略 → 帧装配」和「帧解析 → 解压」这两条固定链路收敛到一处，
//! 生成代码的 `to_byte_array / parse_from / signing_input` 都走它。压缩决策是<b>载荷的
//! 确定性函数</b>：任何一端拿字段重新编码一遍都能得到同一串待签字节，所以验签端不需要
//! 保留原始压缩载荷，也不会出现"编码端压了、验签端没压"的两侧不一致。
//!
//! 策略：载荷超过 [`COMPRESS_THRESHOLD`] 才尝试压缩，压完比原文小才启用。

use crate::encoder::PbpEncoder;
use crate::error::Result;
use crate::frame::{PbpFrame, MAX_PAYLOAD_SIZE};
use crate::message::PbpMessage;
use crate::zstd::PbpZstd;

/// 触发压缩尝试的载荷长度。
pub const COMPRESS_THRESHOLD: usize = 1024;

/// 编解码组装层。
pub struct PbpCodec;

impl PbpCodec {
    /// 编码消息载荷（不含帧头）。
    pub fn payload_of<M: PbpMessage>(message: &M) -> Vec<u8> {
        let mut encoder = PbpEncoder::with_capacity(message.encoded_size().max(64));
        message.encode(&mut encoder);
        encoder.into_bytes()
    }

    /// 按策略尝试压缩。返回压缩后的载荷与"是否启用压缩"。
    ///
    /// 不值得压缩时原样返回入参，调用方用返回的布尔判断是否置 FLAG_COMPRESSED，
    /// 避免"内容恰好一样长但其实是两份数据"这类误判。
    pub fn maybe_compress(payload: Vec<u8>) -> Result<(Vec<u8>, bool)> {
        if payload.len() <= COMPRESS_THRESHOLD {
            return Ok((payload, false));
        }
        let packed = PbpZstd::compress(&payload)?;
        if packed.len() < payload.len() {
            Ok((packed, true))
        } else {
            Ok((payload, false))
        }
    }

    /// 组装整帧：需要压缩时置 FLAG_COMPRESSED。
    pub fn frame_of<M: PbpMessage>(message: &M, timestamp_ms: i64) -> Result<PbpFrame> {
        let payload = PbpCodec::payload_of(message);
        let (packed, compressed) = PbpCodec::maybe_compress(payload)?;
        let mut frame = PbpFrame::of(message.message_id(), timestamp_ms, packed);
        if compressed {
            frame = frame.with_flag(PbpFrame::FLAG_COMPRESSED)?;
        }
        Ok(frame)
    }

    /// 取出帧载荷：声明压缩就解压。
    ///
    /// 解压上限取载荷长度上限（16MB），既是"解压不能超过原文规模约定"的护栏，
    /// 也是解压炸弹的拦截点。
    pub fn payload_of_frame(frame: &PbpFrame) -> Result<Vec<u8>> {
        if !frame.compressed() {
            return Ok(frame.payload.clone());
        }
        PbpZstd::decompress(&frame.payload, MAX_PAYLOAD_SIZE)
    }
}