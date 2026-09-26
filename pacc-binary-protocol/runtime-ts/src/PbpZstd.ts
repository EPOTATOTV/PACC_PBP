import { PbpException } from "./PbpException.js";
import { PbpFrame } from "./PbpFrame.js";
import {
  BitReader,
  BitWriter,
  CState,
  CTable,
  DTable,
  LL_BASE,
  LL_BITS,
  LL_DEFAULT_LOG,
  LL_DEFAULT_NORM,
  LL_MAX_CODE,
  ML_BASE,
  ML_BITS,
  ML_DEFAULT_LOG,
  ML_DEFAULT_NORM,
  ML_MAX_CODE,
  OF_DEFAULT_LOG,
  OF_DEFAULT_NORM,
  OF_MAX_CODE_DEFAULT,
  encodeSymbol,
  flushCState,
  highBit,
  initCState2,
} from "./ZstdFse.js";

/**
 * PBP 内置的 zstd 压缩子集（RFC 8878），零第三方依赖。
 *
 * <p>编码只输出：单段帧（无字典、无校验和）+ Raw / RLE / 压缩块；压缩块内部固定是
 * 「原始 literals + 预定义 FSE 序列表」，序列一律用显式偏移，不发 repeat 码。
 * 解码是编码输出集合的超集：接受 Raw / RLE 块、Raw / RLE literals、预定义 / RLE / Repeat
 * 序列表；对 Huffman literals、FSE_Compressed 表、字典帧、内容校验和一律显式失败。</p>
 *
 * <p>本文件逐行对照 Java 参考实现移植，压缩输出必须与其逐字节一致（互操作向量的锚点）。</p>
 */

/** zstd 帧魔数（小端字节序 28 B5 2F FD）。 */
const MAGIC = 0xfd2fb528;
/** skippable 帧魔数的高 28 位（低 4 位是版本号）。 */
const SKIPPABLE_PREFIX = 0x184d2a50;

/** 单块上限：RFC 规定块最大 128KB。 */
const BLOCK_MAX = 128 * 1024;

const HASH_LOG = 16;
const MIN_MATCH = 4;
/** 匹配长度上限。ML 码最大基线 65539，取 65536 对齐 2 的幂即可。 */
const MAX_MATCH = 65536;

const CT_LL = CTable.build(LL_DEFAULT_NORM, LL_DEFAULT_LOG);
const CT_OF = CTable.build(OF_DEFAULT_NORM, OF_DEFAULT_LOG);
const CT_ML = CTable.build(ML_DEFAULT_NORM, ML_DEFAULT_LOG);

const DT_LL = DTable.build(LL_DEFAULT_NORM, LL_DEFAULT_LOG);
const DT_OF = DTable.build(OF_DEFAULT_NORM, OF_DEFAULT_LOG);
const DT_ML = DTable.build(ML_DEFAULT_NORM, ML_DEFAULT_LOG);

// ============================================================ 压缩

/**
 * 压缩为单个 zstd 帧。
 *
 * <p>不用抛异常的报告方式告诉调用方「压不小」：结果可能比原文长（小输入加上帧头必然如此），
 * 是否采用由调用方比较长度决定。</p>
 */
export function compress(src: Uint8Array): Uint8Array {
  if (src === null) {
    throw new PbpException("BAD_FORMAT", "待压缩数据为 null");
  }
  if (src.length > PbpFrame.MAX_PAYLOAD_SIZE) {
    throw new PbpException(
      "BAD_LENGTH",
      `待压缩数据超过 ${PbpFrame.MAX_PAYLOAD_SIZE} 字节上限: ${src.length}`,
    );
  }
  const out = new OutBuffer(Math.floor(src.length / 2) + 32);
  writeU32(out, MAGIC);
  // Frame_Header_Descriptor：FCS_Flag=2（4 字节长度）+ Single_Segment=1。
  out.writeByte(0xa0);
  writeU32(out, src.length);
  const blocks = Math.max(1, Math.ceil(src.length / BLOCK_MAX));
  // 4 字节 hash 表，跨块保留（head 在块循环外分配、不重置），所以跨块匹配可用
  const head = new Int32Array(1 << HASH_LOG).fill(-1);
  for (let b = 0; b < blocks; b++) {
    const start = b * BLOCK_MAX;
    const end = Math.min(start + BLOCK_MAX, src.length);
    emitBlock(out, src, start, end, b === blocks - 1, head);
  }
  return out.toByteArray();
}

/** 单个块：全同字节走 RLE，无匹配走 Raw，否则压成「原始 literals + 预定义序列」。 */
function emitBlock(
  out: OutBuffer,
  src: Uint8Array,
  start: number,
  end: number,
  last: boolean,
  head: Int32Array,
): void {
  const blockLen = end - start;
  if (blockLen === 0) {
    writeBlockHeader(out, last, "RAW", 0);
    return;
  }
  if (isAllSame(src, start, end)) {
    writeBlockHeader(out, last, "RLE", blockLen);
    out.writeByte(src[start]);
    return;
  }

  const litLens: number[] = [];
  const matchLens: number[] = [];
  const offsets: number[] = [];
  let seqCount = 0;
  const literals = new Uint8Array(blockLen);
  let litPos = 0;

  let i = start;
  let litStart = start;
  while (i + MIN_MATCH <= end) {
    const h = hash(readU32(src, i));
    const cand = head[h];
    head[h] = i;
    if (
      cand >= 0 &&
      i - cand <= 2 ** OF_MAX_CODE_DEFAULT &&
      src[cand] === src[i] &&
      src[cand + 1] === src[i + 1] &&
      src[cand + 2] === src[i + 2] &&
      src[cand + 3] === src[i + 3]
    ) {
      let mlen = MIN_MATCH;
      while (i + mlen < end && mlen < MAX_MATCH && src[cand + mlen] === src[i + mlen]) {
        mlen++;
      }
      literals.set(src.subarray(litStart, i), litPos);
      litPos += i - litStart;
      litLens.push(i - litStart);
      matchLens.push(mlen);
      offsets.push(i - cand);
      seqCount++;
      i += mlen;
      litStart = i;
    } else {
      i++;
    }
  }
  literals.set(src.subarray(litStart, end), litPos);
  litPos += end - litStart;

  if (seqCount === 0) {
    writeBlockHeader(out, last, "RAW", blockLen);
    out.write(src, start, blockLen);
    return;
  }

  const literalsSection = encodeRawLiterals(literals, litPos);
  const sequencesSection = encodeSequences(litLens, matchLens, offsets, seqCount);
  const payloadLen = literalsSection.length + sequencesSection.length;
  if (payloadLen >= blockLen) {
    // RFC 建议：压完不比原文短就发 Raw 块，别让解压方白做工
    writeBlockHeader(out, last, "RAW", blockLen);
    out.write(src, start, blockLen);
    return;
  }
  writeBlockHeader(out, last, "COMPRESSED", payloadLen);
  out.write(literalsSection, 0, literalsSection.length);
  out.write(sequencesSection, 0, sequencesSection.length);
}

/** 原始 literals 段：1/2/3 字节头按 Regenerated_Size 选择。 */
function encodeRawLiterals(literals: Uint8Array, len: number): Uint8Array {
  const out = new OutBuffer(len + 4);
  if (len <= 31) {
    out.writeByte((len << 3) | 0);
  } else if (len <= 4095) {
    out.writeByte(((len & 0xf) << 4) | (1 << 2));
    out.writeByte(len >>> 4);
  } else {
    out.writeByte(((len & 0xf) << 4) | (3 << 2));
    out.writeByte((len >>> 4) & 0xff);
    out.writeByte(len >>> 12);
  }
  out.write(literals, 0, len);
  return out.toByteArray();
}

/**
 * 序列段：序号 + 三张预定义表（模式字节全 0）+ 反向编码的位流。
 *
 * <p>编码顺序按 RFC §3.1.1.3.2.1.2 的逆序：解码是「先偏移额外位、再匹配长度、最后字面量
 * 长度，然后按 LL→ML→OF 更新状态」，所以编码要反过来：最后一个序列先写初始化状态，
 * 倒着写每个序列的 FSE 符号与额外位，最后冲掉三个状态。</p>
 */
function encodeSequences(litLens: number[], matchLens: number[], offsets: number[], seqCount: number): Uint8Array {
  const writer = new BitWriter();
  const mlState = new CState();
  const ofState = new CState();
  const llState = new CState();

  const n = seqCount - 1;
  let llCodeV = llCode(litLens[n]);
  let mlCodeV = mlCode(matchLens[n]);
  let ofCodeV = highBit(offsets[n] + 3);
  initCState2(mlState, CT_ML, mlCodeV);
  initCState2(ofState, CT_OF, ofCodeV);
  initCState2(llState, CT_LL, llCodeV);
  writer.addBits(litLens[n], LL_BITS[llCodeV]);
  writer.addBits(matchLens[n] - ML_BASE[mlCodeV], ML_BITS[mlCodeV]);
  writer.addBits(offsets[n] + 3 - 2 ** ofCodeV, ofCodeV);

  for (let k = seqCount - 2; k >= 0; k--) {
    llCodeV = llCode(litLens[k]);
    mlCodeV = mlCode(matchLens[k]);
    ofCodeV = highBit(offsets[k] + 3);
    encodeSymbol(writer, ofState, CT_OF, ofCodeV);
    encodeSymbol(writer, mlState, CT_ML, mlCodeV);
    encodeSymbol(writer, llState, CT_LL, llCodeV);
    writer.addBits(litLens[k], LL_BITS[llCodeV]);
    writer.addBits(matchLens[k] - ML_BASE[mlCodeV], ML_BITS[mlCodeV]);
    writer.addBits(offsets[k] + 3 - 2 ** ofCodeV, ofCodeV);
  }
  flushCState(writer, mlState, CT_ML);
  flushCState(writer, ofState, CT_OF);
  flushCState(writer, llState, CT_LL);
  const bitstream = writer.finish();

  const out = new OutBuffer(bitstream.length + 8);
  if (seqCount < 128) {
    out.writeByte(seqCount);
  } else if (seqCount <= 32511) {
    out.writeByte(128 + (seqCount >>> 8));
    out.writeByte(seqCount & 0xff);
  } else {
    const v = seqCount - 0x7f00;
    out.writeByte(255);
    out.writeByte(v & 0xff);
    out.writeByte((v >>> 8) & 0xff);
  }
  // 三张表全部 Predefined_Mode（位 7-6 / 5-4 / 3-2 都为 0），保留位为 0
  out.writeByte(0);
  out.write(bitstream, 0, bitstream.length);
  return out.toByteArray();
}

function llCode(ll: number): number {
  for (let c = LL_MAX_CODE; c > 0; c--) {
    if (ll >= LL_BASE[c]) {
      return c;
    }
  }
  return 0;
}

function mlCode(ml: number): number {
  for (let c = ML_MAX_CODE; c > 0; c--) {
    if (ml >= ML_BASE[c]) {
      return c;
    }
  }
  return 0;
}

/** 先按 32 位截断再做无符号右移：乘法是 64 位算的，不截断会把高位带进下标。 */
function hash(v: number): number {
  return Math.imul(v, 2654435761) >>> 16;
}

function isAllSame(src: Uint8Array, start: number, end: number): boolean {
  const first = src[start];
  for (let i = start + 1; i < end; i++) {
    if (src[i] !== first) {
      return false;
    }
  }
  return true;
}

type BlockType = "RAW" | "RLE" | "COMPRESSED";

function writeBlockHeader(out: OutBuffer, last: boolean, type: BlockType, size: number): void {
  const typeBits = type === "RAW" ? 0 : type === "RLE" ? 1 : 2;
  const header = (last ? 1 : 0) | (typeBits << 1) | (size << 3);
  out.writeByte(header & 0xff);
  out.writeByte((header >>> 8) & 0xff);
  out.writeByte((header >>> 16) & 0xff);
}

// ============================================================ 解压

/** 解压一个 zstd 帧。maxSize 是允许的解压结果上限（防解压炸弹）。 */
export function decompress(raw: Uint8Array, maxSize: number): Uint8Array {
  if (raw === null) {
    throw new PbpException("BAD_FORMAT", "zstd 帧为 null");
  }
  if (raw.length < 4) {
    throw new PbpException("TRUNCATED", "zstd 帧长度不足");
  }
  if (maxSize <= 0) {
    throw new PbpException("BAD_LENGTH", `解压上限必须为正: ${maxSize}`);
  }
  let p = 0;
  while (p + 4 <= raw.length) {
    const magic = readU32(raw, p);
    if (((magic & 0xfffffff0) >>> 0) === SKIPPABLE_PREFIX) {
      if (p + 8 > raw.length) {
        throw new PbpException("TRUNCATED", "skippable 帧头不完整");
      }
      const size = readU32(raw, p + 4);
      if (p + 8 + size > raw.length) {
        throw new PbpException("TRUNCATED", "skippable 帧内容不完整");
      }
      p += 8 + size;
      continue;
    }
    if (magic !== MAGIC) {
      throw new PbpException("BAD_FORMAT", `不是 zstd 帧: 0x${magic.toString(16)}`);
    }
    return decodeFrame(raw, p + 4, maxSize);
  }
  throw new PbpException("BAD_FORMAT", "没有找到 zstd 帧");
}

function decodeFrame(raw: Uint8Array, start: number, maxSize: number): Uint8Array {
  let p = start;
  if (p >= raw.length) {
    throw new PbpException("TRUNCATED", "帧头缺失");
  }
  const fhd = raw[p++];
  const fcsFlag = fhd >>> 6;
  const singleSegment = (fhd & 0x20) !== 0;
  if ((fhd & 0x08) !== 0) {
    throw new PbpException("BAD_FORMAT", "帧头保留位被置位");
  }
  if ((fhd & 0x04) !== 0) {
    throw new PbpException("UNSUPPORTED", "子集不支持带内容校验和的帧");
  }
  if ((fhd & 0x03) !== 0) {
    throw new PbpException("UNSUPPORTED", "子集不支持字典帧");
  }
  let windowSize = -1;
  if (!singleSegment) {
    if (p >= raw.length) {
      throw new PbpException("TRUNCATED", "窗口描述字节缺失");
    }
    const wd = raw[p++];
    const windowLog = 10 + (wd >>> 3);
    const windowBase = 2 ** windowLog;
    windowSize = windowBase + (windowBase / 8) * (wd & 7);
  }
  let contentSize = -1;
  const fcsSize = fcsFlag === 0 ? (singleSegment ? 1 : 0) : fcsFlag === 1 ? 2 : fcsFlag === 2 ? 4 : 8;
  if (fcsSize > 0) {
    if (p + fcsSize > raw.length) {
      throw new PbpException("TRUNCATED", "帧内容长度字段不完整");
    }
    contentSize = readU32Or64(raw, p, fcsSize);
    if (fcsSize === 2) {
      contentSize += 256;
    }
    p += fcsSize;
  }
  if (singleSegment) {
    windowSize = contentSize;
  }
  if (windowSize > maxSize) {
    throw new PbpException("BAD_LENGTH", `帧声明的窗口 ${windowSize} 超过允许的解压上限 ${maxSize}`);
  }

  const state = new FrameState();
  const out = new OutBuffer(Math.min(Math.max(windowSize, 64), 64 * 1024));
  const blockMax = Math.min(windowSize, BLOCK_MAX);
  for (;;) {
    if (p + 3 > raw.length) {
      throw new PbpException("TRUNCATED", "块头不完整");
    }
    const header = raw[p] | (raw[p + 1] << 8) | (raw[p + 2] << 16);
    p += 3;
    const last = (header & 1) !== 0;
    const type = (header >>> 1) & 3;
    const size = header >>> 3;
    if (type === 0) {
      if (size > blockMax) {
        throw new PbpException("BAD_LENGTH", `Raw 块超过块上限: ${size}`);
      }
      if (p + size > raw.length) {
        throw new PbpException("TRUNCATED", "Raw 块内容不完整");
      }
      out.write(raw, p, size);
      p += size;
    } else if (type === 1) {
      if (size > blockMax) {
        throw new PbpException("BAD_LENGTH", `RLE 块超过块上限: ${size}`);
      }
      if (p >= raw.length) {
        throw new PbpException("TRUNCATED", "RLE 块内容缺失");
      }
      const v = raw[p++];
      for (let i = 0; i < size; i++) {
        out.writeByte(v);
      }
    } else if (type === 2) {
      p = decodeCompressedBlock(raw, p, size, out, windowSize, blockMax, state);
    } else {
      throw new PbpException("BAD_FORMAT", "保留块类型");
    }
    if (out.size() > maxSize) {
      throw new PbpException("BAD_LENGTH", `解压输出超过上限 ${maxSize}`);
    }
    if (last) {
      break;
    }
  }
  if (contentSize >= 0 && out.size() !== contentSize) {
    throw new PbpException("BAD_LENGTH", `解压长度与帧声明不符: 声明 ${contentSize}，实际 ${out.size()}`);
  }
  if (p !== raw.length) {
    throw new PbpException("BAD_FORMAT", "帧尾还有多余字节（不支持多帧拼接）");
  }
  return out.toByteArray();
}

/** 压缩块：先解 literals 段，再解序列段，然后执行。返回块结束后的游标位置。 */
function decodeCompressedBlock(
  raw: Uint8Array,
  start: number,
  blockSize: number,
  out: OutBuffer,
  windowSize: number,
  blockMax: number,
  state: FrameState,
): number {
  const blockEnd = start + blockSize;
  if (blockEnd > raw.length) {
    throw new PbpException("TRUNCATED", "压缩块内容不完整");
  }
  let lp = start;
  const litType = raw[lp] & 3;
  const sizeFormat = (raw[lp] >>> 2) & 3;
  let regenSize: number;
  let litContentSize: number;
  if (litType === 0 || litType === 1) {
    if (sizeFormat === 0 || sizeFormat === 2) {
      if (lp + 1 > blockEnd) {
        throw new PbpException("TRUNCATED", "literals 段头不完整");
      }
      regenSize = raw[lp] >>> 3;
      lp += 1;
    } else if (sizeFormat === 1) {
      if (lp + 2 > blockEnd) {
        throw new PbpException("TRUNCATED", "literals 段头不完整");
      }
      regenSize = (raw[lp] >>> 4) + (raw[lp + 1] << 4);
      lp += 2;
    } else {
      if (lp + 3 > blockEnd) {
        throw new PbpException("TRUNCATED", "literals 段头不完整");
      }
      regenSize = (raw[lp] >>> 4) + (raw[lp + 1] << 4) + (raw[lp + 2] << 12);
      lp += 3;
    }
    litContentSize = litType === 0 ? regenSize : 1;
  } else {
    throw new PbpException("UNSUPPORTED", `子集不支持 Huffman literals（类型 ${litType}）`);
  }
  if (regenSize > blockMax) {
    throw new PbpException("BAD_LENGTH", `literals 长度超过块上限: ${regenSize}`);
  }
  if (lp + litContentSize > blockEnd) {
    throw new PbpException("TRUNCATED", "literals 内容不完整");
  }
  let literals: Uint8Array;
  if (litType === 0) {
    literals = raw.slice(lp, lp + regenSize);
  } else {
    literals = new Uint8Array(regenSize).fill(raw[lp]);
  }
  lp += litContentSize;

  const blockStart = out.size();
  let q = lp;
  if (q >= blockEnd) {
    throw new PbpException("TRUNCATED", "序列段缺失");
  }
  const b0 = raw[q++];
  let nbSeq: number;
  if (b0 === 0) {
    nbSeq = 0;
  } else if (b0 < 128) {
    nbSeq = b0;
  } else if (b0 < 255) {
    if (q >= blockEnd) {
      throw new PbpException("TRUNCATED", "序列数不完整");
    }
    nbSeq = ((b0 - 128) << 8) + raw[q++];
  } else {
    if (q + 2 > blockEnd) {
      throw new PbpException("TRUNCATED", "序列数不完整");
    }
    nbSeq = raw[q] + (raw[q + 1] << 8) + 0x7f00;
    q += 2;
  }
  if (nbSeq === 0) {
    if (q !== blockEnd) {
      throw new PbpException("BAD_FORMAT", "无序列时序列段仍有剩余字节");
    }
    out.write(literals, 0, literals.length);
    return blockEnd;
  }

  const modes = raw[q++];
  if ((modes & 0x03) !== 0) {
    throw new PbpException("BAD_FORMAT", "序列模式字节保留位非零");
  }
  const llMode = modes >>> 6;
  const ofMode = (modes >>> 4) & 3;
  const mlMode = (modes >>> 2) & 3;
  const cursor = { q };
  const llTable = resolveTable(llMode, DT_LL, LL_MAX_CODE, state.ll, raw, cursor, blockEnd, "字面量长度");
  const ofTable = resolveTable(ofMode, DT_OF, OF_MAX_CODE_DEFAULT, state.of, raw, cursor, blockEnd, "偏移");
  const mlTable = resolveTable(mlMode, DT_ML, ML_MAX_CODE, state.ml, raw, cursor, blockEnd, "匹配长度");
  state.ll = llTable;
  state.of = ofTable;
  state.ml = mlTable;
  q = cursor.q;
  if (q >= blockEnd) {
    throw new PbpException("TRUNCATED", "序列位流缺失");
  }

  const reader = new BitReader(raw, q, blockEnd - q);
  let llState = reader.readBits(llTable.log);
  let ofState = reader.readBits(ofTable.log);
  let mlState = reader.readBits(mlTable.log);
  let litPos = 0;
  for (let s = 0; s < nbSeq; s++) {
    const llSymbol = llTable.symbols[llState];
    const ofSymbol = ofTable.symbols[ofState];
    const mlSymbol = mlTable.symbols[mlState];
    // 额外位读取顺序：偏移 → 匹配长度 → 字面量长度
    const offsetValue = 2 ** ofSymbol + reader.readBits(ofBits(ofSymbol));
    const matchLen = ML_BASE[mlSymbol] + reader.readBits(ML_BITS[mlSymbol]);
    const litLen = LL_BASE[llSymbol] + reader.readBits(LL_BITS[llSymbol]);

    const offset = resolveOffset(offsetValue, ofSymbol, LL_BASE[llSymbol] === 0, state.prevOffsets);

    if (litPos + litLen > literals.length) {
      throw new PbpException("BAD_LENGTH", "字面量长度超出 literals 段");
    }
    out.write(literals, litPos, litLen);
    litPos += litLen;
    if (offset <= 0 || offset > out.size() || offset > windowSize) {
      throw new PbpException("BAD_FORMAT", `匹配偏移越界: ${offset}`);
    }
    if (out.size() + matchLen - blockStart > blockMax) {
      throw new PbpException("BAD_LENGTH", "块解压尺寸超过块上限");
    }
    out.copyFromSelf(offset, matchLen);

    if (s + 1 < nbSeq) {
      // 状态更新顺序：字面量长度 → 匹配长度 → 偏移
      llState = llTable.newStates[llState] + reader.readBits(llTable.nbBits[llState]);
      mlState = mlTable.newStates[mlState] + reader.readBits(mlTable.nbBits[mlState]);
      ofState = ofTable.newStates[ofState] + reader.readBits(ofTable.nbBits[ofState]);
    }
  }
  if (!reader.consumedAll()) {
    throw new PbpException("BAD_FORMAT", "序列位流未被完整消费");
  }
  out.write(literals, litPos, literals.length - litPos);
  if (out.size() - blockStart > blockMax) {
    throw new PbpException("BAD_LENGTH", "块解压尺寸超过块上限");
  }
  return blockEnd;
}

/**
 * 解析 offset 的实际值，含 repeat 偏移的历史维护。
 *
 * <p>规则按 RFC §3.1.1.5：code ≥ 2 是显式偏移（值 = 2^code + 额外位，实际偏移 = 值 - 3）；
 * code 0/1 是 repeat 码，当前序列字面量长度为 0 时整组 repeat 偏移要错一位。</p>
 */
function resolveOffset(offsetValue: number, ofCode: number, litLenZero: boolean, prev: number[]): number {
  if (ofCode >= 2) {
    const offset = offsetValue - 3;
    prev[2] = prev[1];
    prev[1] = prev[0];
    prev[0] = offset;
    return offset;
  }
  const shift = litLenZero ? 1 : 0;
  if (ofCode === 0) {
    const offset = prev[shift];
    prev[1] = prev[shift === 0 ? 1 : 0];
    prev[0] = offset;
    return offset;
  }
  // ofCode == 1：值 2 或 3
  const value = offsetValue + shift;
  const offset = value === 3 ? prev[0] - 1 : prev[value];
  if (offset <= 0) {
    throw new PbpException("BAD_FORMAT", "repeat 偏移回退到 0，数据损坏");
  }
  if (value !== 1) {
    prev[2] = prev[1];
  }
  prev[1] = prev[0];
  prev[0] = offset;
  return offset;
}

/** 解析序列表：预定义直接用、RLE 读一个符号字节、Repeat 复用上一块、自定义表在子集之外。 */
function resolveTable(
  mode: number,
  predefined: DTable,
  maxSymbol: number,
  previous: DTable | null,
  raw: Uint8Array,
  cursor: { q: number },
  blockEnd: number,
  what: string,
): DTable {
  let q = cursor.q;
  let table: DTable;
  if (mode === 0) {
    table = predefined;
  } else if (mode === 1) {
    if (q >= blockEnd) {
      throw new PbpException("TRUNCATED", `${what} 表的 RLE 符号缺失`);
    }
    const symbol = raw[q++];
    if (symbol > maxSymbol) {
      throw new PbpException("BAD_FORMAT", `${what} 表符号越界: ${symbol}`);
    }
    table = DTable.rle(symbol);
  } else if (mode === 3) {
    if (previous === null) {
      throw new PbpException("BAD_FORMAT", `${what} 表声明 Repeat 模式，但没有可复用的表`);
    }
    table = previous;
  } else {
    throw new PbpException("UNSUPPORTED", `子集不支持 ${what} 的 FSE_Compressed 表`);
  }
  cursor.q = q;
  return table;
}

function ofBits(code: number): number {
  return code;
}

/** 跨块保留的帧级状态：repeat 偏移历史与上一组序列表。 */
class FrameState {
  readonly prevOffsets = [1, 4, 8];
  ll: DTable | null = null;
  of: DTable | null = null;
  ml: DTable | null = null;
}

// ============================================================ 工具

function readU32(b: Uint8Array, off: number): number {
  return ((b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0);
}

function readU32Or64(b: Uint8Array, off: number, size: number): number {
  let v = 0;
  for (let i = 0; i < size; i++) {
    v += b[off + i] * 2 ** (8 * i);
  }
  return v;
}

function writeU32(out: OutBuffer, v: number): void {
  out.writeByte(v & 0xff);
  out.writeByte((v >>> 8) & 0xff);
  out.writeByte((v >>> 16) & 0xff);
  out.writeByte((v >>> 24) & 0xff);
}

/** 可增长输出缓冲：解码侧要按字节下标回拷（匹配重叠），所以不用普通数组拼接。 */
class OutBuffer {
  private buf: Uint8Array;
  private len = 0;

  constructor(capacity: number) {
    this.buf = new Uint8Array(Math.max(64, capacity));
  }

  size(): number {
    return this.len;
  }

  writeByte(v: number): void {
    this.ensure(1);
    this.buf[this.len++] = v & 0xff;
  }

  write(src: Uint8Array, off: number, count: number): void {
    if (count === 0) {
      return;
    }
    this.ensure(count);
    this.buf.set(src.subarray(off, off + count), this.len);
    this.len += count;
  }

  /** 从已输出内容里回拷一段（支持重叠，即匹配长度大于偏移的情况）。 */
  copyFromSelf(offset: number, count: number): void {
    this.ensure(count);
    const from = this.len - offset;
    for (let i = 0; i < count; i++) {
      this.buf[this.len + i] = this.buf[from + i];
    }
    this.len += count;
  }

  toByteArray(): Uint8Array {
    return this.buf.slice(0, this.len);
  }

  private ensure(extra: number): void {
    if (this.len + extra <= this.buf.length) {
      return;
    }
    let capacity = this.buf.length;
    while (capacity < this.len + extra) {
      capacity = capacity < 1024 ? capacity * 2 : capacity + (capacity >> 1);
    }
    const grown = new Uint8Array(capacity);
    grown.set(this.buf.subarray(0, this.len));
    this.buf = grown;
  }
}