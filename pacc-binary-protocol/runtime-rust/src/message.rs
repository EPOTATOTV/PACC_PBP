//! 可编码的 PBP 消息。
//!
//! 字段按定义顺序写入、按同一顺序读出，编解码双方靠同一份 MDL 约定顺序，
//! 所以编码里没有字段标签。代价是新字段只能加在末尾、且不能改动已有字段的类型。
//!
//! 实现类由 `tools/pbpgen` 从 `mdl/*.mdl` 生成，不要手写。

use crate::decoder::PbpDecoder;
use crate::encoder::PbpEncoder;
use crate::error::Result;

/// 一条可编解码的 PBP 消息。
pub trait PbpMessage: Sized {
    /// MDL 里声明的消息 ID；嵌套类型（无 ID）返回 0。
    fn message_id(&self) -> u16;

    /// 把自身字段按定义顺序写入编码器。
    fn encode(&self, enc: &mut PbpEncoder);

    /// 按定义顺序从解码器读回字段。
    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()>;

    /// 编码后的字节数，用于预分配缓冲区。
    fn encoded_size(&self) -> usize;
}