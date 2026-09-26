//! PBP 内置的 zstd 压缩子集（RFC 8878），零第三方依赖。
//!
//! 逐行对齐 `runtime-java` 的 `PbpZstd.java`：输出必须与参考实现逐字节一致，
//! 所以压缩用到的每个细节（4 字节 hash 表 1<<16 项、跨块保留、最小匹配 4、匹配上限
//! 65536、块上限 128KB、整块同字节走 RLE、无序列或压完不小于原文走 Raw、
//! 单段帧 FCS 4 字节、预定义 FSE 表、位流按参考顺序反向编码）都照搬。
//!
//! 解码是编码输出集合的超集：接受 Raw / RLE 块、Raw / RLE literals、预定义 / RLE /
//! Repeat 序列表；对 Huffman literals、FSE_Compressed 表、字典帧、内容校验和一律
//! 显式失败（[`PbpError::Unsupported`]），不做静默降级。

use crate::error::{PbpError, Result};
use crate::fse;
use crate::frame::MAX_PAYLOAD_SIZE;

/// zstd 帧魔数（小端字节序 28 B5 2F FD）。
const MAGIC: u32 = 0xFD2FB528;
/// skippable 帧魔数的高 28 位（低 4 位是版本号）。
const SKIPPABLE_PREFIX: u32 = 0x184D2A50;

/// 单块上限：RFC 规定块最大 128KB，压缩前后都按这个上限校验。
pub const BLOCK_MAX: usize = 128 * 1024;

const HASH_LOG: usize = 16;
const MIN_MATCH: usize = 4;
/// 匹配长度上限。ML 码最大基线 65539，取 65536 对齐 2 的幂即可。
const MAX_MATCH: usize = 65536;
/// 预定义偏移分布支持的最大偏移码（码 28），更大的偏移走不了子集。
const MAX_OFFSET_CODE: usize = fse::OF_MAX_CODE_DEFAULT;

fn hash(word: u32) -> usize {
    // 先按 32 位截断再做无符号右移：与 Java 的 `((v * 2654435761L) & 0xFFFFFFFFL) >>> 16` 等价。
    (word.wrapping_mul(2654435761) >> (32 - HASH_LOG)) as usize
}

#[derive(Clone, Copy)]
enum BlockType {
    Raw,
    Rle,
    Compressed,
}

/// zstd 子集编解码器。
pub struct PbpZstd;

impl PbpZstd {
    /// 压缩为单个 zstd 帧。
    ///
    /// 结果可能比原文长（小输入加上帧头必然如此），是否采用由调用方比较长度决定。
    pub fn compress(src: &[u8]) -> Result<Vec<u8>> {
        if src.len() > MAX_PAYLOAD_SIZE {
            return Err(PbpError::BadLength);
        }
        let mut out: Vec<u8> = Vec::with_capacity(src.len() / 2 + 32);
        out.extend_from_slice(&MAGIC.to_le_bytes());
        // Frame_Header_Descriptor：FCS_Flag=2（4 字节长度）+ Single_Segment=1。
        // 单段帧的窗口等于内容长度，免去窗口描述字节。
        out.push(0xA0);
        out.extend_from_slice(&(src.len() as u32).to_le_bytes());
        let blocks = std::cmp::max(1, (src.len() + BLOCK_MAX - 1) / BLOCK_MAX);
        let mut head = vec![-1i32; 1 << HASH_LOG];
        for b in 0..blocks {
            let start = b * BLOCK_MAX;
            let end = std::cmp::min(start + BLOCK_MAX, src.len());
            emit_block(&mut out, src, start, end, b == blocks - 1, &mut head);
        }
        Ok(out)
    }

    /// 解压一个 zstd 帧。
    ///
    /// `max_size` 是允许的解压结果上限；帧声明的窗口与解压输出都不得超过它。
    pub fn decompress(raw: &[u8], max_size: usize) -> Result<Vec<u8>> {
        if raw.len() < 4 {
            return Err(PbpError::Truncated);
        }
        if max_size == 0 {
            return Err(PbpError::BadLength);
        }
        let mut p = 0usize;
        while p + 4 <= raw.len() {
            let magic = read_u32(raw, p);
            if (magic & 0xFFFF_FFF0) == SKIPPABLE_PREFIX {
                if p + 8 > raw.len() {
                    return Err(PbpError::Truncated);
                }
                let size = read_u32(raw, p + 4) as usize;
                if p + 8 + size > raw.len() {
                    return Err(PbpError::Truncated);
                }
                p += 8 + size;
                continue;
            }
            if magic != MAGIC {
                return Err(PbpError::BadFormat);
            }
            return decode_frame(raw, p + 4, max_size);
        }
        Err(PbpError::BadFormat)
    }
}

// ============================================================ 压缩

/// 单个块：全同字节走 RLE，无匹配走 Raw，否则压成「原始 literals + 预定义序列」。
fn emit_block(out: &mut Vec<u8>, src: &[u8], start: usize, end: usize, last: bool, head: &mut [i32]) {
    let block_len = end - start;
    if block_len == 0 {
        write_block_header(out, last, BlockType::Raw, 0);
        return;
    }
    if is_all_same(src, start, end) {
        write_block_header(out, last, BlockType::Rle, block_len);
        out.push(src[start]);
        return;
    }

    let mut lit_lens: Vec<i32> = Vec::new();
    let mut match_lens: Vec<i32> = Vec::new();
    let mut offsets: Vec<i32> = Vec::new();
    let mut literals: Vec<u8> = Vec::with_capacity(block_len);

    let mut i = start;
    let mut lit_start = start;
    while i + MIN_MATCH <= end {
        let h = hash(read_u32(src, i));
        let cand = head[h];
        head[h] = i as i32;
        if cand >= 0
            && (i as i64 - cand as i64) <= (1i64 << MAX_OFFSET_CODE)
            && src[cand as usize] == src[i]
            && src[cand as usize + 1] == src[i + 1]
            && src[cand as usize + 2] == src[i + 2]
            && src[cand as usize + 3] == src[i + 3]
        {
            let mut mlen = MIN_MATCH;
            while i + mlen < end && mlen < MAX_MATCH && src[cand as usize + mlen] == src[i + mlen] {
                mlen += 1;
            }
            literals.extend_from_slice(&src[lit_start..i]);
            lit_lens.push((i - lit_start) as i32);
            match_lens.push(mlen as i32);
            offsets.push((i - cand as usize) as i32);
            i += mlen;
            lit_start = i;
        } else {
            i += 1;
        }
    }
    literals.extend_from_slice(&src[lit_start..end]);

    if lit_lens.is_empty() {
        write_block_header(out, last, BlockType::Raw, block_len);
        out.extend_from_slice(&src[start..end]);
        return;
    }

    let literals_section = encode_raw_literals(&literals, literals.len());
    let sequences_section = encode_sequences(&lit_lens, &match_lens, &offsets);
    let payload_len = literals_section.len() + sequences_section.len();
    if payload_len >= block_len {
        // RFC 建议：压完不比原文短就发 Raw 块，别让解压方白做工
        write_block_header(out, last, BlockType::Raw, block_len);
        out.extend_from_slice(&src[start..end]);
        return;
    }
    write_block_header(out, last, BlockType::Compressed, payload_len);
    out.extend_from_slice(&literals_section);
    out.extend_from_slice(&sequences_section);
}

/// 原始 literals 段：1/2/3 字节头按 Regenerated_Size 选择（RFC §3.1.1.3.1.1）。
fn encode_raw_literals(literals: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 4);
    if len <= 31 {
        out.push(((len as u8) << 3) | 0);
    } else if len <= 4095 {
        out.push((((len as u8) & 0xF) << 4) | (1 << 2));
        out.push((len >> 4) as u8);
    } else {
        out.push((((len as u8) & 0xF) << 4) | (3 << 2));
        out.push(((len >> 4) & 0xFF) as u8);
        out.push((len >> 12) as u8);
    }
    out.extend_from_slice(&literals[..len]);
    out
}

/// 序列段：序号 + 三张预定义表（模式字节全 0）+ 反向编码的位流。
///
/// 编码顺序严格按 RFC §3.1.1.3.2.1.2 的逆序：解码是"先读偏移额外位、再匹配长度、
/// 最后字面量长度，然后按 LL→ML→OF 更新状态"，所以编码要反过来。
fn encode_sequences(lit_lens: &[i32], match_lens: &[i32], offsets: &[i32]) -> Vec<u8> {
    let seq_count = lit_lens.len();
    let ll_base = fse::build_base(&fse::LL_BITS, 0);
    let ml_base = fse::build_base(&fse::ML_BITS, 3);
    let ct_ll = fse::ct_ll();
    let ct_of = fse::ct_of();
    let ct_ml = fse::ct_ml();

    let mut writer = fse::BitWriter::new();
    let mut ml_state = fse::CState::default();
    let mut of_state = fse::CState::default();
    let mut ll_state = fse::CState::default();

    let n = seq_count - 1;
    let mut ll_code = ll_length_code(lit_lens[n], &ll_base);
    let mut ml_code = ml_length_code(match_lens[n], &ml_base);
    let mut of_code = fse::high_bit(offsets[n] + 3) as usize;
    fse::init_cstate2(&mut ml_state, ct_ml, ml_code);
    fse::init_cstate2(&mut of_state, ct_of, of_code);
    fse::init_cstate2(&mut ll_state, ct_ll, ll_code);
    writer.add_bits(lit_lens[n] as i64, fse::LL_BITS[ll_code]);
    writer.add_bits((match_lens[n] - ml_base[ml_code]) as i64, fse::ML_BITS[ml_code]);
    writer.add_bits((offsets[n] + 3 - (1i32 << of_code)) as i64, of_code as u32);

    for k in (0..seq_count - 1).rev() {
        ll_code = ll_length_code(lit_lens[k], &ll_base);
        ml_code = ml_length_code(match_lens[k], &ml_base);
        of_code = fse::high_bit(offsets[k] + 3) as usize;
        fse::encode_symbol(&mut writer, &mut of_state, ct_of, of_code);
        fse::encode_symbol(&mut writer, &mut ml_state, ct_ml, ml_code);
        fse::encode_symbol(&mut writer, &mut ll_state, ct_ll, ll_code);
        writer.add_bits(lit_lens[k] as i64, fse::LL_BITS[ll_code]);
        writer.add_bits((match_lens[k] - ml_base[ml_code]) as i64, fse::ML_BITS[ml_code]);
        writer.add_bits((offsets[k] + 3 - (1i32 << of_code)) as i64, of_code as u32);
    }
    fse::flush_cstate(&mut writer, &ml_state, ct_ml);
    fse::flush_cstate(&mut writer, &of_state, ct_of);
    fse::flush_cstate(&mut writer, &ll_state, ct_ll);
    let bitstream = writer.finish();

    let mut out = Vec::with_capacity(bitstream.len() + 8);
    if seq_count < 128 {
        out.push(seq_count as u8);
    } else if seq_count <= 32511 {
        out.push((128 + (seq_count >> 8)) as u8);
        out.push((seq_count & 0xFF) as u8);
    } else {
        let v = seq_count - 0x7F00;
        out.push(255);
        out.push((v & 0xFF) as u8);
        out.push(((v >> 8) & 0xFF) as u8);
    }
    // 三张表全部 Predefined_Mode（位 7-6 / 5-4 / 3-2 都为 0），保留位为 0
    out.push(0);
    out.extend_from_slice(&bitstream);
    out
}

fn ll_length_code(ll: i32, base: &[i32]) -> usize {
    for c in (1..=fse::LL_MAX_CODE).rev() {
        if ll >= base[c] {
            return c;
        }
    }
    0
}

fn ml_length_code(ml: i32, base: &[i32]) -> usize {
    for c in (1..=fse::ML_MAX_CODE).rev() {
        if ml >= base[c] {
            return c;
        }
    }
    0
}

fn is_all_same(src: &[u8], start: usize, end: usize) -> bool {
    let first = src[start];
    for &b in &src[start + 1..end] {
        if b != first {
            return false;
        }
    }
    true
}

fn write_block_header(out: &mut Vec<u8>, last: bool, block_type: BlockType, size: usize) {
    let type_bits: u32 = match block_type {
        BlockType::Raw => 0,
        BlockType::Rle => 1,
        BlockType::Compressed => 2,
    };
    let header: u32 = (last as u32) | (type_bits << 1) | ((size as u32) << 3);
    out.push(header as u8);
    out.push((header >> 8) as u8);
    out.push((header >> 16) as u8);
}

// ============================================================ 解压

/// 跨块保留的帧级状态：repeat 偏移历史与上一组序列表。
struct FrameState {
    prev_offsets: [i64; 3],
    ll: Option<fse::DTable>,
    of: Option<fse::DTable>,
    ml: Option<fse::DTable>,
}

fn decode_frame(raw: &[u8], mut p: usize, max_size: usize) -> Result<Vec<u8>> {
    if p >= raw.len() {
        return Err(PbpError::Truncated);
    }
    let fhd = raw[p];
    p += 1;
    let fcs_flag = fhd >> 6;
    let single_segment = (fhd & 0x20) != 0;
    if fhd & 0x08 != 0 {
        return Err(PbpError::BadFormat);
    }
    if fhd & 0x04 != 0 {
        return Err(PbpError::Unsupported);
    }
    if fhd & 0x03 != 0 {
        return Err(PbpError::Unsupported);
    }

    let mut window_size: i64 = -1;
    if !single_segment {
        if p >= raw.len() {
            return Err(PbpError::Truncated);
        }
        let wd = raw[p];
        p += 1;
        let window_log = 10 + (wd >> 3) as u32;
        let window_base = 1i64 << window_log;
        window_size = window_base + (window_base / 8) * (wd & 7) as i64;
    }

    let mut content_size: i64 = -1;
    let fcs_size: usize = match fcs_flag {
        0 => {
            if single_segment {
                1
            } else {
                0
            }
        }
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if fcs_size > 0 {
        if p + fcs_size > raw.len() {
            return Err(PbpError::Truncated);
        }
        content_size = read_u32_or_64(raw, p, fcs_size) as i64;
        if fcs_size == 2 {
            content_size += 256;
        }
        p += fcs_size;
    }
    if single_segment {
        window_size = content_size;
    }
    if window_size > max_size as i64 {
        return Err(PbpError::BadLength);
    }

    let mut state = FrameState { prev_offsets: [1, 4, 8], ll: None, of: None, ml: None };
    let cap = std::cmp::min(std::cmp::max(window_size, 64), 64 * 1024) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let block_max: i64 = std::cmp::min(window_size, BLOCK_MAX as i64);

    loop {
        if p + 3 > raw.len() {
            return Err(PbpError::Truncated);
        }
        let header = (raw[p] as u32) | ((raw[p + 1] as u32) << 8) | ((raw[p + 2] as u32) << 16);
        p += 3;
        let last = header & 1 != 0;
        let btype = (header >> 1) & 3;
        let size = (header >> 3) as usize;
        match btype {
            0 => {
                if size as i64 > block_max {
                    return Err(PbpError::BadLength);
                }
                if p + size > raw.len() {
                    return Err(PbpError::Truncated);
                }
                out.extend_from_slice(&raw[p..p + size]);
                p += size;
            }
            1 => {
                if size as i64 > block_max {
                    return Err(PbpError::BadLength);
                }
                if p >= raw.len() {
                    return Err(PbpError::Truncated);
                }
                let v = raw[p];
                p += 1;
                let new_len = out.len() + size;
                out.resize(new_len, v);
            }
            2 => {
                p = decode_compressed_block(raw, p, size, &mut out, window_size, block_max, &mut state)?;
            }
            _ => return Err(PbpError::BadFormat),
        }
        if out.len() as i64 > max_size as i64 {
            return Err(PbpError::BadLength);
        }
        if last {
            break;
        }
    }
    if content_size >= 0 && out.len() as i64 != content_size {
        return Err(PbpError::BadLength);
    }
    if p != raw.len() {
        return Err(PbpError::BadFormat);
    }
    Ok(out)
}

/// 压缩块：先解 literals 段，再解序列段，然后执行。返回块结束后的游标位置。
fn decode_compressed_block(
    raw: &[u8],
    p: usize,
    block_size: usize,
    out: &mut Vec<u8>,
    window_size: i64,
    block_max: i64,
    state: &mut FrameState,
) -> Result<usize> {
    let block_end = p + block_size;
    if block_end > raw.len() {
        return Err(PbpError::Truncated);
    }
    let mut lp = p;
    let lit_type = raw[lp] & 3;
    let size_format = (raw[lp] >> 2) & 3;
    let (regen_size, lit_content_size): (usize, usize) = if lit_type == 0 || lit_type == 1 {
        match size_format {
            0 | 2 => {
                if lp + 1 > block_end {
                    return Err(PbpError::Truncated);
                }
                let regen = (raw[lp] as usize) >> 3;
                lp += 1;
                (regen, if lit_type == 0 { regen } else { 1 })
            }
            1 => {
                if lp + 2 > block_end {
                    return Err(PbpError::Truncated);
                }
                let regen = ((raw[lp] as usize) >> 4) + ((raw[lp + 1] as usize) << 4);
                lp += 2;
                (regen, if lit_type == 0 { regen } else { 1 })
            }
            _ => {
                if lp + 3 > block_end {
                    return Err(PbpError::Truncated);
                }
                let regen = ((raw[lp] as usize) >> 4)
                    + ((raw[lp + 1] as usize) << 4)
                    + ((raw[lp + 2] as usize) << 12);
                lp += 3;
                (regen, if lit_type == 0 { regen } else { 1 })
            }
        }
    } else {
        return Err(PbpError::Unsupported);
    };
    if regen_size as i64 > block_max {
        return Err(PbpError::BadLength);
    }
    if lp + lit_content_size > block_end {
        return Err(PbpError::Truncated);
    }
    let literals: Vec<u8> = if lit_type == 0 {
        raw[lp..lp + regen_size].to_vec()
    } else {
        vec![raw[lp]; regen_size]
    };
    lp += lit_content_size;

    let block_start = out.len();
    let mut q = lp;
    if q >= block_end {
        return Err(PbpError::Truncated);
    }
    let b0 = raw[q] as usize;
    q += 1;
    let nb_seq: usize = if b0 == 0 {
        0
    } else if b0 < 128 {
        b0
    } else if b0 < 255 {
        if q >= block_end {
            return Err(PbpError::Truncated);
        }
        let v = ((b0 - 128) << 8) + raw[q] as usize;
        q += 1;
        v
    } else {
        if q + 2 > block_end {
            return Err(PbpError::Truncated);
        }
        let v = raw[q] as usize + ((raw[q + 1] as usize) << 8) + 0x7F00;
        q += 2;
        v
    };
    if nb_seq == 0 {
        if q != block_end {
            return Err(PbpError::BadFormat);
        }
        out.extend_from_slice(&literals);
        return Ok(block_end);
    }

    let modes = raw[q] as u32;
    q += 1;
    if modes & 0x03 != 0 {
        return Err(PbpError::BadFormat);
    }
    let ll_mode = modes >> 6;
    let of_mode = (modes >> 4) & 3;
    let ml_mode = (modes >> 2) & 3;
    let mut cursor = q;
    let ll_table = resolve_table(
        ll_mode,
        || fse::build_dtable(&fse::LL_DEFAULT_NORM, fse::LL_DEFAULT_LOG),
        fse::LL_MAX_CODE as i32,
        &state.ll,
        raw,
        &mut cursor,
        block_end,
    )?;
    let of_table = resolve_table(
        of_mode,
        || fse::build_dtable(&fse::OF_DEFAULT_NORM, fse::OF_DEFAULT_LOG),
        fse::OF_MAX_CODE_DEFAULT as i32,
        &state.of,
        raw,
        &mut cursor,
        block_end,
    )?;
    let ml_table = resolve_table(
        ml_mode,
        || fse::build_dtable(&fse::ML_DEFAULT_NORM, fse::ML_DEFAULT_LOG),
        fse::ML_MAX_CODE as i32,
        &state.ml,
        raw,
        &mut cursor,
        block_end,
    )?;
    state.ll = Some(ll_table.clone());
    state.of = Some(of_table.clone());
    state.ml = Some(ml_table.clone());
    q = cursor;
    if q >= block_end {
        return Err(PbpError::Truncated);
    }

    let mut reader = fse::BitReader::new(raw, q, block_end - q)?;
    let mut ll_state = reader.read_bits(ll_table.log)? as usize;
    let mut of_state = reader.read_bits(of_table.log)? as usize;
    let mut ml_state = reader.read_bits(ml_table.log)? as usize;
    let ll_base = fse::build_base(&fse::LL_BITS, 0);
    let ml_base = fse::build_base(&fse::ML_BITS, 3);
    let mut lit_pos = 0usize;
    let mut prev_offsets = state.prev_offsets;

    for s in 0..nb_seq {
        let ll_symbol = ll_table.symbols[ll_state] as usize;
        let of_symbol = of_table.symbols[of_state] as usize;
        let ml_symbol = ml_table.symbols[ml_state] as usize;
        // 额外位读取顺序：偏移 → 匹配长度 → 字面量长度
        let offset_value = (1i64 << of_symbol) + reader.read_bits(fse::of_bits(of_symbol))? as i64;
        let match_len = ml_base[ml_symbol] + reader.read_bits(fse::ML_BITS[ml_symbol])?;
        let lit_len = ll_base[ll_symbol] + reader.read_bits(fse::LL_BITS[ll_symbol])?;

        let offset = resolve_offset(offset_value, of_symbol, ll_base[ll_symbol] == 0, &mut prev_offsets)?;

        if lit_pos as i64 + lit_len as i64 > literals.len() as i64 {
            return Err(PbpError::BadLength);
        }
        out.extend_from_slice(&literals[lit_pos..lit_pos + lit_len as usize]);
        lit_pos += lit_len as usize;
        if offset <= 0 || offset > out.len() as i64 || offset > window_size {
            return Err(PbpError::BadFormat);
        }
        if out.len() as i64 + match_len as i64 - block_start as i64 > block_max {
            return Err(PbpError::BadLength);
        }
        copy_from_self(out, offset as usize, match_len as usize);

        if s + 1 < nb_seq {
            // 状态更新顺序：字面量长度 → 匹配长度 → 偏移
            ll_state = (ll_table.new_states[ll_state] + reader.read_bits(ll_table.nb_bits[ll_state])?) as usize;
            ml_state = (ml_table.new_states[ml_state] + reader.read_bits(ml_table.nb_bits[ml_state])?) as usize;
            of_state = (of_table.new_states[of_state] + reader.read_bits(of_table.nb_bits[of_state])?) as usize;
        }
    }
    state.prev_offsets = prev_offsets;
    if !reader.consumed_all() {
        return Err(PbpError::BadFormat);
    }
    out.extend_from_slice(&literals[lit_pos..]);
    if out.len() as i64 - block_start as i64 > block_max {
        return Err(PbpError::BadLength);
    }
    Ok(block_end)
}

/// 解析 offset 的实际值，含 repeat 偏移的历史维护。规则按 RFC §3.1.1.5 与参考实现。
fn resolve_offset(offset_value: i64, of_code: usize, lit_len_zero: bool, prev: &mut [i64; 3]) -> Result<i64> {
    if of_code >= 2 {
        let offset = offset_value - 3;
        prev[2] = prev[1];
        prev[1] = prev[0];
        prev[0] = offset;
        return Ok(offset);
    }
    let shift = if lit_len_zero { 1usize } else { 0usize };
    if of_code == 0 {
        let offset = prev[shift];
        prev[1] = prev[if shift == 0 { 1 } else { 0 }];
        prev[0] = offset;
        return Ok(offset);
    }
    // of_code == 1：值 2 或 3
    let value = offset_value + shift as i64;
    let offset = if value == 3 {
        prev[0] - 1
    } else if (value as usize) < prev.len() {
        prev[value as usize]
    } else {
        return Err(PbpError::BadFormat);
    };
    if offset <= 0 {
        return Err(PbpError::BadFormat);
    }
    if value != 1 {
        prev[2] = prev[1];
    }
    prev[1] = prev[0];
    prev[0] = offset;
    Ok(offset)
}

/// 解析序列表：预定义直接用、RLE 读一个符号字节、Repeat 复用上一块、自定义表在子集之外。
fn resolve_table(
    mode: u32,
    predefined: impl FnOnce() -> fse::DTable,
    max_symbol: i32,
    previous: &Option<fse::DTable>,
    raw: &[u8],
    cursor: &mut usize,
    block_end: usize,
) -> Result<fse::DTable> {
    let mut q = *cursor;
    let table = match mode {
        0 => predefined(),
        1 => {
            if q >= block_end {
                return Err(PbpError::Truncated);
            }
            let symbol = raw[q] as i32;
            q += 1;
            if symbol > max_symbol {
                return Err(PbpError::BadFormat);
            }
            fse::DTable::rle(symbol)
        }
        3 => previous.as_ref().ok_or(PbpError::BadFormat)?.clone(),
        _ => return Err(PbpError::Unsupported),
    };
    *cursor = q;
    Ok(table)
}

/// 从已输出内容里回拷一段（支持重叠，即匹配长度大于偏移的情况）。
fn copy_from_self(out: &mut Vec<u8>, offset: usize, count: usize) {
    let from = out.len() - offset;
    for i in 0..count {
        let b = out[from + i];
        out.push(b);
    }
}

// ============================================================ 工具

fn read_u32(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

fn read_u32_or_64(b: &[u8], off: usize, size: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..size {
        v |= (b[off + i] as u64) << (8 * i);
    }
    v
}