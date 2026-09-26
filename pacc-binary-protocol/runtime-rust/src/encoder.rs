//! PBP 二进制编码器。
//!
//! 字段按 MDL 定义顺序写入、不带标签：省掉每个字段 1-2 字节的标签开销，代价是编解码
//! 双方必须持有同一份字段顺序定义，且新字段只能加在末尾。
//!
//! 所有多字节定长字段一律小端，与帧头保持一致；跨语言实现不需要再记两套字节序。
//! Rust 的整型宽度已经框住取值范围，所以标量写入不需要额外的越界检查（Java 侧
//! 用 `int` 承载 `int8/uint8/...` 才需要 `requireRange`）。

use crate::message::PbpMessage;

/// VarInt 最多 10 字节（每 7 位一组，64 位需要 10 组）。
pub const MAX_VARINT_BYTES: usize = 10;

/// 可增长输出缓冲：够用即可，编码前无法可靠预测长度。
#[derive(Debug, Clone, Default)]
pub struct PbpEncoder {
    buf: Vec<u8>,
}

impl PbpEncoder {
    /// 默认容量，与 Java 侧一致。
    pub fn new() -> Self {
        PbpEncoder::with_capacity(64)
    }

    pub fn with_capacity(initial_capacity: usize) -> Self {
        PbpEncoder { buf: Vec::with_capacity(initial_capacity.max(16)) }
    }

    /// 已写入的字节数。
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// 已写入字节的视图。
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// 取走写入的字节，长度正好等于 [`PbpEncoder::len`]。
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// 清空缓冲区以便复用；容量保留。
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    // ------------------------------------------------------------ 标量

    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
    }

    pub fn write_int8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }

    pub fn write_uint8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_int16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_uint16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// int32 走 ZigZag + VarInt（负数不会占满 10 字节）。
    pub fn write_int32(&mut self, v: i32) {
        let z = (v.wrapping_shl(1) ^ (v >> 31)) as u32;
        self.write_varint(z as u64);
    }

    /// uint32 走 VarInt。
    pub fn write_uint32(&mut self, v: u32) {
        self.write_varint(v as u64);
    }

    /// int64 走 ZigZag + VarInt。
    pub fn write_int64(&mut self, v: i64) {
        let z = (v.wrapping_shl(1) ^ (v >> 63)) as u64;
        self.write_varint(z);
    }

    /// uint64 走 VarInt，u64 的原始位模式即无符号值。
    pub fn write_uint64(&mut self, v: u64) {
        self.write_varint(v);
    }

    /// 枚举在线上是 VarInt 编码的非负整数（MDL 已保证非负）。
    pub fn write_enum(&mut self, v: u32) {
        self.write_varint(v as u64);
    }

    pub fn write_float32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    pub fn write_float64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    // ------------------------------------------------------------ 变长

    /// UTF-8 字符串：VarInt 字节长度 + 数据。
    pub fn write_string(&mut self, s: &str) {
        let b = s.as_bytes();
        self.write_varint(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.write_varint(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    // ------------------------------------------------------------ 可空字段

    /// 写入一段连续可空字段的存在位图。
    ///
    /// 位图各字节的低位对应更靠前的字段。位图必须写在所有对应字段的值之前，
    /// 所以调用方要把这一批可空字段的存在性一次性传进来。
    /// 单个可空字段的位图正好是 1 字节，与"存在性字节"形式逐字节等价。
    pub fn write_presence(&mut self, present: &[bool]) {
        let byte_count = (present.len() + 7) / 8;
        for i in 0..byte_count {
            let mut bits: u8 = 0;
            for bit in 0..8 {
                let idx = i * 8 + bit;
                if idx < present.len() && present[idx] {
                    bits |= 1 << bit;
                }
            }
            self.buf.push(bits);
        }
    }

    pub fn write_optional_string(&mut self, s: &Option<String>) {
        self.write_presence(&[s.is_some()]);
        if let Some(value) = s {
            self.write_string(value);
        }
    }

    pub fn write_optional_bytes(&mut self, b: &Option<Vec<u8>>) {
        self.write_presence(&[b.is_some()]);
        if let Some(value) = b {
            self.write_bytes(value);
        }
    }

    pub fn write_optional_message<T: PbpMessage>(&mut self, m: &Option<T>) {
        self.write_presence(&[m.is_some()]);
        if let Some(value) = m {
            self.write_message(value);
        }
    }

    // ------------------------------------------------------------ 消息与集合

    /// 嵌套消息内联编码，不加长度前缀：字段顺序即边界，由最外层帧的 PayloadLen 兜底。
    pub fn write_message<T: PbpMessage>(&mut self, m: &T) {
        m.encode(self);
    }

    pub fn write_message_list<T: PbpMessage>(&mut self, list: &[T]) {
        self.write_varint(list.len() as u64);
        for m in list {
            m.encode(self);
        }
    }

    pub fn write_string_list(&mut self, list: &[String]) {
        self.write_varint(list.len() as u64);
        for s in list {
            self.write_string(s);
        }
    }

    /// 通用列表：元素为标量时用 `|e, v| e.write_int64(*v)` 这类闭包传入。
    pub fn write_list<T, F: FnMut(&mut PbpEncoder, &T)>(&mut self, list: &[T], mut write: F) {
        self.write_varint(list.len() as u64);
        for e in list {
            write(self, e);
        }
    }

    /// 通用映射：键值对按切片顺序写入，两侧需使用同一顺序才能保证字节一致。
    pub fn write_map<K, V, FK, FV>(&mut self, map: &[(K, V)], mut write_key: FK, mut write_value: FV)
    where
        FK: FnMut(&mut PbpEncoder, &K),
        FV: FnMut(&mut PbpEncoder, &V),
    {
        self.write_varint(map.len() as u64);
        for (k, v) in map {
            write_key(self, k);
            write_value(self, v);
        }
    }

    /// 键固定为 string 的映射（MDL 里绝大多数 map 都是这种）。
    pub fn write_string_map<V, F: FnMut(&mut PbpEncoder, &V)>(&mut self, map: &[(String, V)], mut write_value: F) {
        self.write_varint(map.len() as u64);
        for (k, v) in map {
            self.write_string(k);
            write_value(self, v);
        }
    }

    // ------------------------------------------------------------ 长度预估（纯预分配提示）

    pub fn varint_size(v: u64) -> usize {
        let mut n = 1;
        let mut value = v;
        while (value & !0x7F) != 0 {
            value >>= 7;
            n += 1;
        }
        n
    }

    pub fn bool_size() -> usize {
        1
    }

    pub fn int8_size() -> usize {
        1
    }

    pub fn uint8_size() -> usize {
        1
    }

    pub fn int16_size() -> usize {
        2
    }

    pub fn uint16_size() -> usize {
        2
    }

    pub fn int32_size(v: i32) -> usize {
        PbpEncoder::varint_size(((v.wrapping_shl(1) ^ (v >> 31)) as u32) as u64)
    }

    pub fn uint32_size(v: u32) -> usize {
        PbpEncoder::varint_size(v as u64)
    }

    pub fn int64_size(v: i64) -> usize {
        PbpEncoder::varint_size((v.wrapping_shl(1) ^ (v >> 63)) as u64)
    }

    pub fn uint64_size(v: u64) -> usize {
        PbpEncoder::varint_size(v)
    }

    pub fn enum_size(v: u32) -> usize {
        PbpEncoder::varint_size(v as u64)
    }

    pub fn float32_size() -> usize {
        4
    }

    pub fn float64_size() -> usize {
        8
    }

    pub fn string_size(s: &str) -> usize {
        PbpEncoder::varint_size(s.len() as u64) + s.len()
    }

    pub fn bytes_size(b: &[u8]) -> usize {
        PbpEncoder::varint_size(b.len() as u64) + b.len()
    }

    pub fn presence_size(field_count: usize) -> usize {
        (field_count + 7) / 8
    }

    pub fn optional_string_size(s: &Option<String>) -> usize {
        1 + s.as_ref().map_or(0, |v| PbpEncoder::string_size(v))
    }

    pub fn optional_bytes_size(b: &Option<Vec<u8>>) -> usize {
        1 + b.as_ref().map_or(0, |v| PbpEncoder::bytes_size(v))
    }

    pub fn message_size<T: PbpMessage>(m: &T) -> usize {
        m.encoded_size()
    }

    pub fn optional_message_size<T: PbpMessage>(m: &Option<T>) -> usize {
        1 + m.as_ref().map_or(0, |v| v.encoded_size())
    }

    pub fn message_list_size<T: PbpMessage>(list: &[T]) -> usize {
        let mut size = PbpEncoder::varint_size(list.len() as u64);
        for m in list {
            size += m.encoded_size();
        }
        size
    }

    pub fn string_list_size(list: &[String]) -> usize {
        let mut size = PbpEncoder::varint_size(list.len() as u64);
        for s in list {
            size += PbpEncoder::string_size(s);
        }
        size
    }

    pub fn string_map_size<V, F: Fn(&V) -> usize>(map: &[(String, V)], value_size: F) -> usize {
        let mut size = PbpEncoder::varint_size(map.len() as u64);
        for (k, v) in map {
            size += PbpEncoder::string_size(k) + value_size(v);
        }
        size
    }

    pub fn map_size<K, V, FK, FV>(map: &[(K, V)], key_size: FK, value_size: FV) -> usize
    where
        FK: Fn(&K) -> usize,
        FV: Fn(&V) -> usize,
    {
        let mut size = PbpEncoder::varint_size(map.len() as u64);
        for (k, v) in map {
            size += key_size(k) + value_size(v);
        }
        size
    }

    // ------------------------------------------------------------ 落地

    /// VarInt：每字节低 7 位有效、最高位表示续接。
    fn write_varint(&mut self, value: u64) {
        let mut v = value;
        while (v & !0x7F) != 0 {
            self.buf.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        self.buf.push((v & 0x7F) as u8);
    }
}