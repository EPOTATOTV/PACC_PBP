//! PBP 二进制解码器。
//!
//! 与 [`crate::encoder::PbpEncoder`] 严格镜像：同样的字段顺序、同样的类型宽度。
//!
//! 所有读取都做边界检查，越界一律返回 [`PbpError`] 而不是默认值——输入来自网络，
//! 静默截断会把"攻击者截断了载荷"变成"对端发了个全零消息"，后者在日志上完全看不出来。

use crate::error::{PbpError, Result};
use crate::message::PbpMessage;

/// 集合元素个数上界：挡住伪造长度的循环消耗，正常载荷远远够用。
const MAX_COLLECTION_SIZE: u64 = 1 << 20;

/// 定长字段与变长字段共享的字节游标，带解码窗口。
#[derive(Debug, Clone)]
pub struct PbpDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> PbpDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        PbpDecoder { buf, pos: 0, limit: buf.len() }
    }

    pub fn with_window(buf: &'a [u8], offset: usize, length: usize) -> Result<Self> {
        if offset + length > buf.len() {
            return Err(PbpError::BadLength);
        }
        Ok(PbpDecoder { buf, pos: offset, limit: offset + length })
    }

    /// 尚未读取的字节数。
    pub fn remaining(&self) -> usize {
        self.limit - self.pos
    }

    pub fn has_remaining(&self) -> bool {
        self.pos < self.limit
    }

    /// 已消费的字节数（相对解码窗口起点）。
    pub fn position(&self) -> usize {
        self.pos
    }

    /// 丢弃剩余字节：新客户端追加了字段、旧服务端不认识时读完自己的字段把尾巴丢掉即可。
    pub fn skip_remaining(&mut self) {
        self.pos = self.limit;
    }

    // ------------------------------------------------------------ 标量

    pub fn read_bool(&mut self) -> Result<bool> {
        let b = self.read_raw()?;
        if b != 0 && b != 1 {
            return Err(PbpError::BadFormat);
        }
        Ok(b == 1)
    }

    pub fn read_int8(&mut self) -> Result<i8> {
        Ok(self.read_raw()? as i8)
    }

    pub fn read_uint8(&mut self) -> Result<u8> {
        self.read_raw()
    }

    pub fn read_int16(&mut self) -> Result<i16> {
        let lo = self.read_raw()? as u16;
        let hi = self.read_raw()? as u16;
        Ok(((hi << 8) | lo) as i16)
    }

    pub fn read_uint16(&mut self) -> Result<u16> {
        let lo = self.read_raw()? as u16;
        let hi = self.read_raw()? as u16;
        Ok((hi << 8) | lo)
    }

    pub fn read_int32(&mut self) -> Result<i32> {
        let zz = self.read_varint()? as u32;
        Ok(((zz >> 1) as i32) ^ -((zz & 1) as i32))
    }

    pub fn read_uint32(&mut self) -> Result<u32> {
        let v = self.read_varint()?;
        if v > 0xFFFF_FFFF {
            return Err(PbpError::BadFormat);
        }
        Ok(v as u32)
    }

    pub fn read_int64(&mut self) -> Result<i64> {
        let z = self.read_varint()?;
        Ok(((z >> 1) as i64) ^ -((z & 1) as i64))
    }

    /// 返回 u64 的原始位模式。
    pub fn read_uint64(&mut self) -> Result<u64> {
        self.read_varint()
    }

    pub fn read_enum(&mut self) -> Result<u32> {
        self.read_uint32()
    }

    pub fn read_float32(&mut self) -> Result<f32> {
        let mut bits = 0u32;
        for i in 0..4 {
            bits |= (self.read_raw()? as u32) << (i * 8);
        }
        Ok(f32::from_bits(bits))
    }

    pub fn read_float64(&mut self) -> Result<f64> {
        let mut bits = 0u64;
        for i in 0..8 {
            bits |= (self.read_raw()? as u64) << (i * 8);
        }
        Ok(f64::from_bits(bits))
    }

    // ------------------------------------------------------------ 变长

    pub fn read_string(&mut self) -> Result<String> {
        let length = self.read_length()?;
        let slice = &self.buf[self.pos..self.pos + length];
        let text = std::str::from_utf8(slice).map_err(|_| PbpError::BadFormat)?.to_string();
        self.pos += length;
        Ok(text)
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.read_length()?;
        let out = self.buf[self.pos..self.pos + length].to_vec();
        self.pos += length;
        Ok(out)
    }

    // ------------------------------------------------------------ 可空字段

    /// 读取 `field_count` 个连续可空字段的存在位图（低位对应更靠前的字段）。
    pub fn read_presence(&mut self, field_count: usize) -> Result<Vec<bool>> {
        let byte_count = (field_count + 7) / 8;
        let mut present = vec![false; field_count];
        for i in 0..byte_count {
            let bits = self.read_raw()? as u32;
            for bit in 0..8 {
                let idx = i * 8 + bit;
                if idx < field_count {
                    present[idx] = (bits & (1 << bit)) != 0;
                }
            }
        }
        Ok(present)
    }

    pub fn read_optional_string(&mut self) -> Result<Option<String>> {
        Ok(if self.read_presence(1)?[0] { Some(self.read_string()?) } else { None })
    }

    pub fn read_optional_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(if self.read_presence(1)?[0] { Some(self.read_bytes()?) } else { None })
    }

    pub fn read_optional_message<T: PbpMessage + Default>(&mut self) -> Result<Option<T>> {
        Ok(if self.read_presence(1)?[0] { Some(self.read_message()?) } else { None })
    }

    // ------------------------------------------------------------ 消息与集合

    pub fn read_message<T: PbpMessage + Default>(&mut self) -> Result<T> {
        let mut msg = T::default();
        msg.decode(self)?;
        Ok(msg)
    }

    pub fn read_message_list<T: PbpMessage + Default>(&mut self) -> Result<Vec<T>> {
        let count = self.read_count()?;
        let mut list = Vec::with_capacity(count);
        for _ in 0..count {
            list.push(self.read_message()?);
        }
        Ok(list)
    }

    pub fn read_string_list(&mut self) -> Result<Vec<String>> {
        self.read_list(|dec| dec.read_string())
    }

    /// 通用列表。
    ///
    /// 元素个数上界单独设限：不能拿"每元素至少 1 字节"去卡，因为无字段的嵌套消息
    /// 合法地编码成 0 字节，那样会误杀正常载荷。
    pub fn read_list<T, F: FnMut(&mut PbpDecoder<'a>) -> Result<T>>(&mut self, mut read_element: F) -> Result<Vec<T>> {
        let count = self.read_count()?;
        let mut list = Vec::with_capacity(count);
        for _ in 0..count {
            list.push(read_element(self)?);
        }
        Ok(list)
    }

    /// 通用映射。键固定为 string 时用 [`PbpDecoder::read_string_map`]。
    pub fn read_map<K, V, FK, FV>(&mut self, mut read_key: FK, mut read_value: FV) -> Result<Vec<(K, V)>>
    where
        FK: FnMut(&mut PbpDecoder<'a>) -> Result<K>,
        FV: FnMut(&mut PbpDecoder<'a>) -> Result<V>,
    {
        let count = self.read_count()?;
        let mut map = Vec::with_capacity(count);
        for _ in 0..count {
            let key = read_key(self)?;
            let value = read_value(self)?;
            map.push((key, value));
        }
        Ok(map)
    }

    /// 键固定为 string 的映射，按线上顺序存放（便于比对与复现）。
    pub fn read_string_map<V, F: FnMut(&mut PbpDecoder<'a>) -> Result<V>>(&mut self, mut read_value: F) -> Result<Vec<(String, V)>> {
        let count = self.read_count()?;
        let mut map = Vec::with_capacity(count);
        for _ in 0..count {
            let key = self.read_string()?;
            let value = read_value(self)?;
            map.push((key, value));
        }
        Ok(map)
    }

    // ------------------------------------------------------------ 落地

    fn read_raw(&mut self) -> Result<u8> {
        if self.pos >= self.limit {
            return Err(PbpError::Truncated);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// VarInt 解码，最多 10 字节；超过 10 字节或第 10 字节溢出 64 位一律拒绝。
    fn read_varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..crate::encoder::MAX_VARINT_BYTES {
            let b = self.read_raw()?;
            if i == 9 && (b & 0xFE) != 0 {
                return Err(PbpError::BadVarint);
            }
            value |= ((b & 0x7F) as u64) << (i * 7);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(PbpError::BadVarint)
    }

    fn read_length(&mut self) -> Result<usize> {
        let length = self.read_varint()?;
        if length > self.remaining() as u64 {
            return Err(PbpError::Truncated);
        }
        Ok(length as usize)
    }

    fn read_count(&mut self) -> Result<usize> {
        let count = self.read_varint()?;
        if count > MAX_COLLECTION_SIZE {
            return Err(PbpError::BadFormat);
        }
        Ok(count as usize)
    }
}