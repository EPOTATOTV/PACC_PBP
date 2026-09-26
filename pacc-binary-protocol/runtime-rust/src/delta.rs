//! 差分编码的公共工具与差分链。
//!
//! 生成的 `encode_delta / apply_delta` 只写"哪个字段变了"，比较与深拷贝的细节集中在
//! [`PbpDelta`]，避免每个生成类各写一份。
//!
//! 比较分两条路：标量/字符串/字节数组直接比较值；嵌套消息、列表、映射按"同一套
//! 编码调用写出来的字节"比较——它们的相等性与字段顺序、元素顺序天然一致。

use crate::codec::PbpCodec;
use crate::decoder::PbpDecoder;
use crate::encoder::PbpEncoder;
use crate::error::{PbpError, Result};
use crate::frame::PbpFrame;
use crate::message::PbpMessage;

/// 支持差分编码的消息：`encode_delta` 只写与基线不同的字段，`apply_delta` 先用基线
/// 补齐、再覆盖变化的部分。位图与值的布局是「存在位图（ceil(N/8) 字节）+ 按字段序的
/// 变化值」。
///
/// 带 signed 选项的消息不生成差分方法：帧尾签名与差分基线是两套状态，混用时
/// "签名覆盖的载荷"与"基线对应的载荷"很容易对不上。
pub trait PbpDeltaMessage<T> {
    /// 相对基线编码差异：位图 + 变化字段的值。
    fn encode_delta(&self, enc: &mut PbpEncoder, previous: &T);

    /// 用基线补齐未变化的字段，再读入变化的字段；不会改动传入的基线对象。
    fn apply_delta(&mut self, dec: &mut PbpDecoder<'_>, previous: &T) -> Result<()>;
}

/// 差分工具的命名空间（与 Java 的 `PbpDelta` 静态方法对齐）。
pub struct PbpDelta;

impl PbpDelta {
    /// 两个字段是否不同：把同一套 writer 调用分别写进临时编码器，比字节。
    pub fn differs<A, B>(current: A, previous: B) -> bool
    where
        A: FnOnce(&mut PbpEncoder),
        B: FnOnce(&mut PbpEncoder),
    {
        let mut a = PbpEncoder::with_capacity(32);
        current(&mut a);
        let mut b = PbpEncoder::with_capacity(32);
        previous(&mut b);
        a.into_bytes() != b.into_bytes()
    }

    /// 深拷贝消息（编解码往返）。
    pub fn copy<T: PbpMessage + Default>(message: &T) -> Result<T> {
        let payload = PbpCodec::payload_of(message);
        let mut clone = T::default();
        clone.decode(&mut PbpDecoder::new(&payload))?;
        Ok(clone)
    }

    /// 深拷贝消息列表；空列表原样返回。
    pub fn copy_list<T: PbpMessage + Default>(list: &[T]) -> Result<Vec<T>> {
        let mut clone = Vec::with_capacity(list.len());
        for element in list {
            clone.push(PbpDelta::copy(element)?);
        }
        Ok(clone)
    }

    /// 深拷贝可空消息；`None` 原样返回，配合可空字段使用。
    pub fn copy_option<T: PbpMessage + Default>(message: Option<&T>) -> Result<Option<T>> {
        match message {
            None => Ok(None),
            Some(value) => Ok(Some(PbpDelta::copy(value)?)),
        }
    }

    /// 深拷贝消息映射的值；键按 [`Clone`] 复制。
    pub fn copy_map_entries<K: Clone, V: PbpMessage + Default>(map: &[(K, V)]) -> Result<Vec<(K, V)>> {
        let mut clone = Vec::with_capacity(map.len());
        for (key, value) in map {
            clone.push((key.clone(), PbpDelta::copy(value)?));
        }
        Ok(clone)
    }
}

/// 连续差分上限（设计文档 §3.10.2）。
pub const MAX_CONSECUTIVE: usize = 10;

/// 一条消息 ID 上的差分链：发送侧决定"发完整还是发差分"，接收侧按标志位回放。
///
/// 每条消息一条链实例，按"一条连接一个方向"使用：里面存着基线与计数，非线程安全。
pub struct PbpDeltaChain<T> {
    message_id: u16,
    previous: Option<T>,
    consecutive: usize,
}

impl<T> PbpDeltaChain<T>
where
    T: PbpMessage + PbpDeltaMessage<T> + Clone + Default,
{
    pub fn new(message_id: u16) -> Self {
        PbpDeltaChain { message_id, previous: None, consecutive: 0 }
    }

    /// 已连续发出的 / 收到的差分条数。
    pub fn consecutive(&self) -> usize {
        self.consecutive
    }

    /// 丢弃基线，下一条必定发完整消息（重连、丢帧后的复位点）。
    pub fn reset(&mut self) {
        self.previous = None;
        self.consecutive = 0;
    }

    /// 发送侧：按规则选择完整或差分，并把当前消息深拷贝为新基线。
    pub fn encode(&mut self, current: &T, timestamp_ms: i64) -> Result<PbpFrame> {
        let use_delta = self.previous.is_some() && self.consecutive < MAX_CONSECUTIVE;
        let payload = if use_delta {
            let mut encoder = PbpEncoder::with_capacity((current.encoded_size() / 2 + 8).max(64));
            current.encode_delta(&mut encoder, self.previous.as_ref().unwrap());
            encoder.into_bytes()
        } else {
            PbpCodec::payload_of(current)
        };
        let (packed, compressed) = PbpCodec::maybe_compress(payload)?;
        let mut frame = PbpFrame::of(self.message_id, timestamp_ms, packed);
        if use_delta {
            frame = frame.with_flag(PbpFrame::FLAG_DELTA)?;
        }
        if compressed {
            frame = frame.with_flag(PbpFrame::FLAG_COMPRESSED)?;
        }
        self.previous = Some(PbpDelta::copy(current)?);
        self.consecutive = if use_delta { self.consecutive + 1 } else { 0 };
        Ok(frame)
    }

    /// 接收侧：完整消息直接解码，差分消息在基线上回放。
    ///
    /// 没有基线时收到差分、或连续差分超过上限，都按协议错误拒绝——这两种情况说明
    /// 对端状态与本端不一致，继续解会把错位的数据当有效消息用。
    pub fn decode(&mut self, frame_bytes: &[u8]) -> Result<T> {
        let frame = PbpFrame::parse(frame_bytes)?;
        if frame.message_id != self.message_id {
            return Err(PbpError::BadFormat);
        }
        let mut message = T::default();
        if frame.delta() {
            if self.previous.is_none() {
                return Err(PbpError::BadFormat);
            }
            if self.consecutive >= MAX_CONSECUTIVE {
                return Err(PbpError::BadFormat);
            }
            let payload = PbpCodec::payload_of_frame(&frame)?;
            message.apply_delta(&mut PbpDecoder::new(&payload), self.previous.as_ref().unwrap())?;
        } else {
            let payload = PbpCodec::payload_of_frame(&frame)?;
            message.decode(&mut PbpDecoder::new(&payload))?;
        }
        self.previous = Some(PbpDelta::copy(&message)?);
        self.consecutive = if frame.delta() { self.consecutive + 1 } else { 0 };
        Ok(message)
    }
}