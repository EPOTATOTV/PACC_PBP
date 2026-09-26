//! PACC 二进制协议（PBP）Rust 运行时。
//!
//! 与 `runtime-java` 逐行对齐语义：字段按 MDL 编号升序、不带标签写入载荷，
//! 多字节定长字段一律小端（帧头开头的 2 字节 Magic 例外，按 'P','B' 可读顺序写）。
//! 所有越界/非法输入一律返回 [`PbpError`]，不静默截断——载荷来自网络，静默截断
//! 会把"对端截断了"变成"对端发了个全零消息"。
//!
//! 零第三方依赖：HMAC-SHA256（[`crypto`]）与 zstd 子集（[`zstd`] / [`fse`]）都在本
//! crate 内自实现；`gen` 下的消息类型由 `tools/pbpgen` 从 `mdl/*.mdl` 生成。

pub mod codec;
pub mod crypto;
pub mod decoder;
pub mod delta;
pub mod encoder;
pub mod error;
pub mod frame;
pub mod fse;
pub mod gen;
pub mod message;
pub mod zstd;

pub use codec::PbpCodec;
pub use decoder::PbpDecoder;
pub use delta::{PbpDelta, PbpDeltaChain, PbpDeltaMessage};
pub use encoder::PbpEncoder;
pub use error::{PbpError, Result};
pub use frame::PbpFrame;
pub use message::PbpMessage;
pub use zstd::PbpZstd;