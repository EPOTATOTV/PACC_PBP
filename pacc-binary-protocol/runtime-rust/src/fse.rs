//! zstd 子集（RFC 8878）用到的熵编码与比特流原语。
//!
//! 逐行对齐 `runtime-java` 的 `ZstdFse.java`：编码侧只输出「原始 literals +
//! 预定义 FSE 序列表」，解码侧在此之上额外认 Raw / RLE 块。不认 Huffman literals、
//! FSE_Compressed 表、字典与内容校验和，遇到就显式失败。
//!
//! 常量与算法都来自 RFC 8878：序列码表是 §3.1.1.3.2.1.1 的表 16/17，预定义分布是
//! §3.1.1.3.2.2 的三张表，FSE 表构造是 §4.1.1。
//!
//! 位流约定：编码侧按「先写的位在低位」把比特流正向写入字节数组；解码侧从最后一个字节
//! 的最高有效位开始反向读取，读到结束标记位后的 0 填充为止。反读时先读到的位是字段的
//! 高位，所以 [`BitReader::read_bits`] 的取值是「按读取顺序高位在前」。

use crate::error::{PbpError, Result};

// ------------------------------------------------------------ 序列码表

/// 字面量长度码的额外位数（RFC 8878 表 16）。
pub const LL_BITS: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16,
];

/// 匹配长度码的额外位数（RFC 8878 表 17）。
pub const ML_BITS: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

pub const LL_MAX_CODE: usize = LL_BITS.len() - 1;
pub const ML_MAX_CODE: usize = ML_BITS.len() - 1;
/// 预定义偏移分布只到码 28，更大的偏移必须走自定义表，子集里不支持。
pub const OF_MAX_CODE_DEFAULT: usize = 28;

/// 由「上一段的基线 + 上一段的跨度」累加出码表基线：码表的定义就是按取值范围首尾相接，
/// 累加式写法不会出现手抄错一位的经典事故。
pub fn build_base(bits: &[u32], first: i32) -> Vec<i32> {
    let mut base = vec![0i32; bits.len()];
    base[0] = first;
    for i in 1..bits.len() {
        base[i] = base[i - 1] + if bits[i - 1] == 0 { 1 } else { 1i32 << bits[i - 1] };
    }
    base
}

/// 偏移码的基线：码 0/1 用于 repeat 偏移，码 ≥2 时基线是 2^code - 3。
pub fn of_base(code: usize) -> i32 {
    if code < 2 {
        code as i32
    } else {
        (1i32 << code) - 3
    }
}

/// 偏移码的额外位数等于码值本身。
pub fn of_bits(code: usize) -> u32 {
    code as u32
}

/// 32 位值的最高有效位下标；入参为 0 时结果无意义（调用点都在已校验的分支里）。
pub fn high_bit(v: i32) -> i32 {
    31 - (v as u32).leading_zeros() as i32
}

// ------------------------------------------------------------ 预定义分布

/// 字面量长度码的预定义分布（RFC §3.1.1.3.2.2.1，精度 6）。
pub const LL_DEFAULT_NORM: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1,
    -1, -1, -1,
];

/// 匹配长度码的预定义分布（RFC §3.1.1.3.2.2.2，精度 6）。
pub const ML_DEFAULT_NORM: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2,
    2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
];

/// 偏移码的预定义分布（RFC §3.1.1.3.2.2.3，精度 5，最大码 28）。
pub const OF_DEFAULT_NORM: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

pub const LL_DEFAULT_LOG: u32 = 6;
pub const ML_DEFAULT_LOG: u32 = 6;
pub const OF_DEFAULT_LOG: u32 = 5;

// ------------------------------------------------------------ 比特流写入

/// 比特流写入器：按「先写的位在低位」累积，字节小端落到缓冲。
pub struct BitWriter {
    buf: Vec<u8>,
    acc: i64,
    acc_bits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { buf: Vec::with_capacity(64), acc: 0, acc_bits: 0 }
    }

    /// 写入 `n` 位（取 `value` 的低 n 位）；单次最多 32 位。
    pub fn add_bits(&mut self, value: i64, n: u32) {
        debug_assert!(n <= 32);
        if n == 0 {
            return;
        }
        let mask: i64 = (1i64 << n) - 1;
        self.acc |= (value & mask) << self.acc_bits;
        self.acc_bits += n;
        while self.acc_bits >= 8 {
            self.buf.push(self.acc as u8);
            self.acc >>= 8;
            self.acc_bits -= 8;
        }
    }

    /// 收尾：写结束标记位（单个 1），把剩余位补零成整字节。
    pub fn finish(mut self) -> Vec<u8> {
        self.add_bits(1, 1);
        if self.acc_bits > 0 {
            self.buf.push(self.acc as u8);
        }
        self.buf
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        BitWriter::new()
    }
}

// ------------------------------------------------------------ 比特流读取

/// 比特流读取器：从指定区间的末字节开始反向读取。
pub struct BitReader<'a> {
    src: &'a [u8],
    min_bit: i64,
    pos: i64,
}

impl<'a> BitReader<'a> {
    pub fn new(src: &'a [u8], offset: usize, length: usize) -> Result<Self> {
        if length == 0 {
            return Err(PbpError::BadFormat);
        }
        if offset + length > src.len() {
            return Err(PbpError::Truncated);
        }
        let last = src[offset + length - 1];
        if last == 0 {
            return Err(PbpError::BadFormat);
        }
        let min_bit = (offset as i64) * 8;
        let pos = ((offset + length - 1) as i64) * 8 + high_bit(last as i32) as i64 - 1;
        Ok(BitReader { src, min_bit, pos })
    }

    /// 读取 `n` 位；先读到的位是高位。位流已被读空时返回错误，避免把补零当有效数据。
    pub fn read_bits(&mut self, n: u32) -> Result<i32> {
        if n == 0 {
            return Ok(0);
        }
        if self.pos - n as i64 + 1 < self.min_bit {
            return Err(PbpError::BadFormat);
        }
        let mut v: i32 = 0;
        for _ in 0..n {
            let byte = self.src[(self.pos >> 3) as usize];
            v = (v << 1) | ((byte as i32 >> (self.pos & 7)) & 1);
            self.pos -= 1;
        }
        Ok(v)
    }

    /// 位流是否已被恰好读完（RFC 要求序列位流必须精确消费）。
    pub fn consumed_all(&self) -> bool {
        self.pos < self.min_bit
    }
}

// ------------------------------------------------------------ 解码表

/// FSE 解码表：每个状态给出符号、下一状态的额外位数与基线。
#[derive(Debug, Clone)]
pub struct DTable {
    pub log: u32,
    pub symbols: Vec<i32>,
    pub nb_bits: Vec<u32>,
    pub new_states: Vec<i32>,
}

impl DTable {
    /// RLE_Mode 的表：只有一个符号，不消费任何状态位。
    pub fn rle(symbol: i32) -> Self {
        DTable { log: 0, symbols: vec![symbol], nb_bits: vec![0], new_states: vec![0] }
    }
}

/// 按 RFC §4.1.1 构造解码表：概率 <1 的符号各占一个格子、从表尾倒退分配；其余符号按
/// 自然序、以 step 散布占格；最后按符号统计下一个状态。
pub fn build_dtable(norm: &[i32], table_log: u32) -> DTable {
    let max_symbol = norm.len() - 1;
    let table_size = 1usize << table_log;
    let mut symbols = vec![0i32; table_size];
    let mut symbol_next = vec![0i32; max_symbol + 1];
    let mut high_threshold = table_size - 1;
    for s in 0..=max_symbol {
        if norm[s] == -1 {
            symbols[high_threshold] = s as i32;
            high_threshold -= 1;
            symbol_next[s] = 1;
        } else {
            symbol_next[s] = norm[s];
        }
    }
    let step = (table_size >> 1) + (table_size >> 3) + 3;
    let mask = table_size - 1;
    let mut position = 0usize;
    for s in 0..=max_symbol {
        let mut i = 0;
        while i < norm[s] {
            symbols[position] = s as i32;
            position = (position + step) & mask;
            while position > high_threshold {
                position = (position + step) & mask;
            }
            i += 1;
        }
    }
    let mut nb_bits = vec![0u32; table_size];
    let mut new_states = vec![0i32; table_size];
    for u in 0..table_size {
        let next = symbol_next[symbols[u] as usize];
        symbol_next[symbols[u] as usize] += 1;
        let bits = table_log - high_bit(next) as u32;
        nb_bits[u] = bits;
        new_states[u] = (next << bits) - table_size as i32;
    }
    DTable { log: table_log, symbols, nb_bits, new_states }
}

// ------------------------------------------------------------ 编码表

/// FSE 编码表：状态迁移用 `state_table` 与每个符号的位宽/偏移描述。
#[derive(Debug, Clone)]
pub struct CTable {
    pub log: u32,
    pub state_table: Vec<i32>,
    pub delta_nb_bits: Vec<i64>,
    pub delta_find_state: Vec<i32>,
}

/// 按 RFC §4.1.1 的散布规则构造编码表，布局取参考实现的形态：每个符号的
/// `delta_nb_bits` 同时编码「输出位数」与「下一状态基址」，这样 [`encode_symbol`]
/// 只做一次加法一次移位。
pub fn build_ctable(norm: &[i32], table_log: u32) -> CTable {
    let max_symbol = norm.len() - 1;
    let table_size = 1usize << table_log;
    let mask = table_size - 1;
    let step = (table_size >> 1) + (table_size >> 3) + 3;

    let mut cumul = vec![0i32; max_symbol + 2];
    let mut table_symbol = vec![0i32; table_size];
    let mut high_threshold = table_size - 1;
    for s in 0..=max_symbol {
        if norm[s] == -1 {
            cumul[s + 1] = cumul[s] + 1;
            table_symbol[high_threshold] = s as i32;
            high_threshold -= 1;
        } else {
            cumul[s + 1] = cumul[s] + norm[s];
        }
    }
    let mut position = 0usize;
    for s in 0..=max_symbol {
        let mut i = 0;
        while i < norm[s] {
            table_symbol[position] = s as i32;
            position = (position + step) & mask;
            while position > high_threshold {
                position = (position + step) & mask;
            }
            i += 1;
        }
    }
    let mut state_table = vec![0i32; table_size];
    let mut running = cumul.clone();
    for u in 0..table_size {
        let sym = table_symbol[u] as usize;
        let idx = running[sym] as usize;
        state_table[idx] = (table_size + u) as i32;
        running[sym] += 1;
    }

    let mut delta_nb_bits = vec![0i64; max_symbol + 1];
    let mut delta_find_state = vec![0i32; max_symbol + 1];
    let mut total = 0i32;
    for s in 0..=max_symbol {
        let freq = norm[s];
        if freq == 0 {
            // 不会用到，但留一个上界值，避免误用时算出越界下标
            delta_nb_bits[s] = ((table_log as i64 + 1) << 16) - table_size as i64;
        } else if freq == 1 || freq == -1 {
            delta_nb_bits[s] = ((table_log as i64) << 16) - table_size as i64;
            delta_find_state[s] = total - 1;
            total += 1;
        } else {
            let max_bits_out = table_log - high_bit(freq - 1) as u32;
            let min_state_plus = freq << max_bits_out;
            delta_nb_bits[s] = ((max_bits_out as i64) << 16) - min_state_plus as i64;
            delta_find_state[s] = total - freq;
            total += freq;
        }
    }
    CTable { log: table_log, state_table, delta_nb_bits, delta_find_state }
}

// ------------------------------------------------------------ 编码状态机

/// FSE 编码状态：一个状态值，按参考实现的方式携带「已输出位数」。
#[derive(Debug, Clone, Copy, Default)]
pub struct CState {
    pub value: i64,
}

pub fn init_cstate2(st: &mut CState, table: &CTable, symbol: usize) {
    let nb_bits_out = (table.delta_nb_bits[symbol] + (1i64 << 15)) >> 16;
    let v = (nb_bits_out << 16) - table.delta_nb_bits[symbol];
    let idx = (v >> nb_bits_out) + table.delta_find_state[symbol] as i64;
    st.value = table.state_table[idx as usize] as i64;
}

pub fn encode_symbol(writer: &mut BitWriter, st: &mut CState, table: &CTable, symbol: usize) {
    let nb_bits_out = (st.value + table.delta_nb_bits[symbol]) >> 16;
    writer.add_bits(st.value, nb_bits_out as u32);
    let idx = (st.value >> nb_bits_out) + table.delta_find_state[symbol] as i64;
    st.value = table.state_table[idx as usize] as i64;
}

pub fn flush_cstate(writer: &mut BitWriter, st: &CState, table: &CTable) {
    writer.add_bits(st.value, table.log);
}

// ------------------------------------------------------------ 预定义表（进程内建一次）

use std::sync::OnceLock;

pub fn ct_ll() -> &'static CTable {
    static T: OnceLock<CTable> = OnceLock::new();
    T.get_or_init(|| build_ctable(&LL_DEFAULT_NORM, LL_DEFAULT_LOG))
}

pub fn ct_of() -> &'static CTable {
    static T: OnceLock<CTable> = OnceLock::new();
    T.get_or_init(|| build_ctable(&OF_DEFAULT_NORM, OF_DEFAULT_LOG))
}

pub fn ct_ml() -> &'static CTable {
    static T: OnceLock<CTable> = OnceLock::new();
    T.get_or_init(|| build_ctable(&ML_DEFAULT_NORM, ML_DEFAULT_LOG))
}