import { PbpException } from "./PbpException.js";

/**
 * zstd 子集（RFC 8878）用到的熵编码与比特流原语。
 *
 * <p>常量与算法都来自 RFC 8878：序列码表是 §3.1.1.3.2.1.1 的表 16/17，预定义分布是
 * §3.1.1.3.2.2 的三张表，FSE 表构造是 §4.1.1。</p>
 *
 * <p>Java 参考实现里 FSE 状态机用 long，但实际数值都 &lt; 2^22，32 位足够。TS 侧一律用
 * number，凡涉及移位/取低位的地方改用乘除与取模，避免 JS 位运算的 32 位截断带来偏差。
 * 位流约定：编码按「先写的位在低位」正向写入，解码从末字节最高有效位反向读取，
 * 反读时先读到的位是字段的高位。</p>
 */

// ------------------------------------------------------------ 序列码表

/** 字面量长度码的额外位数（RFC 8878 表 16）。 */
export const LL_BITS: number[] = [
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 2, 2, 3, 3,
  4, 6, 7, 8, 9, 10, 11, 12,
  13, 14, 15, 16,
];

/** 匹配长度码的额外位数（RFC 8878 表 17）。 */
export const ML_BITS: number[] = [
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 2, 2, 3, 3,
  4, 4, 5, 7, 8, 9, 10, 11,
  12, 13, 14, 15, 16,
];

function buildBase(bits: number[], first: number): number[] {
  const base = new Array<number>(bits.length).fill(0);
  base[0] = first;
  for (let i = 1; i < bits.length; i++) {
    base[i] = base[i - 1] + (bits[i - 1] === 0 ? 1 : 2 ** bits[i - 1]);
  }
  return base;
}

export const LL_BASE: number[] = buildBase(LL_BITS, 0);
export const ML_BASE: number[] = buildBase(ML_BITS, 3);

/** 偏移码的额外位数等于码值本身。 */
export function ofBits(code: number): number {
  return code;
}

export const LL_MAX_CODE = LL_BITS.length - 1;
export const ML_MAX_CODE = ML_BITS.length - 1;
/** 预定义偏移分布只到码 28，更大的偏移必须走自定义表，子集里不支持。 */
export const OF_MAX_CODE_DEFAULT = 28;

// ------------------------------------------------------------ 预定义分布

/** 字面量长度码的预定义分布（精度 6）。 */
export const LL_DEFAULT_NORM: number[] = [
  4, 3, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 1, 1, 1,
  2, 2, 2, 2, 2, 2, 2, 2,
  2, 3, 2, 1, 1, 1, 1, 1,
  -1, -1, -1, -1,
];

/** 匹配长度码的预定义分布（精度 6）。 */
export const ML_DEFAULT_NORM: number[] = [
  1, 4, 3, 2, 2, 2, 2, 2,
  2, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, -1, -1,
  -1, -1, -1, -1, -1,
];

/** 偏移码的预定义分布（精度 5，最大码 28）。 */
export const OF_DEFAULT_NORM: number[] = [
  1, 1, 1, 1, 1, 1, 2, 2,
  2, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  -1, -1, -1, -1, -1,
];

export const LL_DEFAULT_LOG = 6;
export const ML_DEFAULT_LOG = 6;
export const OF_DEFAULT_LOG = 5;

/** 32 位值的最高有效位下标；入参为 0 时返回 -1（调用点都在已校验的分支里）。 */
export function highBit(v: number): number {
  return 31 - Math.clz32(v);
}

// ------------------------------------------------------------ 比特流写入

/**
 * 比特流写入器：按「先写的位在低位」累积，字节小端落到缓冲。
 *
 * <p>acc 只在 &lt; 8 位的余量上累积，单次最多 32 位，总宽度远低于 2^53，用 number 精确表示。</p>
 */
export class BitWriter {
  private buf = new Uint8Array(64);
  private len = 0;
  private acc = 0;
  private accBits = 0;

  /** 写入 n 位（取 value 的低 n 位）；单次最多 32 位。 */
  addBits(value: number, n: number): void {
    if (n < 0 || n > 32) {
      throw new PbpException("BAD_FORMAT", `位流写入长度非法: ${n}`);
    }
    if (n === 0) {
      return;
    }
    const masked = value % 2 ** n;
    this.acc += masked * 2 ** this.accBits;
    this.accBits += n;
    while (this.accBits >= 8) {
      this.writeByte(this.acc % 256);
      this.acc = Math.floor(this.acc / 256);
      this.accBits -= 8;
    }
  }

  /** 收尾：写结束标记位（单个 1），把剩余位补零成整字节。 */
  finish(): Uint8Array {
    this.addBits(1, 1);
    if (this.accBits > 0) {
      this.writeByte(this.acc % 256);
      this.acc = 0;
      this.accBits = 0;
    }
    return this.buf.slice(0, this.len);
  }

  private writeByte(v: number): void {
    this.ensure(1);
    this.buf[this.len++] = v & 0xff;
  }

  private ensure(extra: number): void {
    if (this.len + extra <= this.buf.length) {
      return;
    }
    let capacity = this.buf.length;
    while (capacity < this.len + extra) {
      capacity *= 2;
    }
    const grown = new Uint8Array(capacity);
    grown.set(this.buf.subarray(0, this.len));
    this.buf = grown;
  }
}

// ------------------------------------------------------------ 比特流读取

/**
 * 比特流读取器：从指定区间的末字节开始反向读取。
 *
 * <p>末字节必须含结束标记位（最高的一个 1），标记之上的 0 是填充、不参与取值；
 * 读到区间起点以下即视为损坏，直接抛错而不是继续读零。</p>
 */
export class BitReader {
  private readonly src: Uint8Array;
  private readonly minBit: number;
  private pos: number;

  constructor(src: Uint8Array, offset: number, length: number) {
    if (length <= 0) {
      throw new PbpException("BAD_FORMAT", "位流长度为 0");
    }
    if (offset < 0 || offset + length > src.length) {
      throw new PbpException("TRUNCATED", "位流区间越界");
    }
    const last = src[offset + length - 1];
    if (last === 0) {
      throw new PbpException("BAD_FORMAT", "位流末字节为 0：缺少结束标记位");
    }
    this.src = src;
    this.minBit = offset * 8;
    this.pos = (offset + length - 1) * 8 + highBit(last) - 1;
  }

  /** 读取 n 位；先读到的位是高位。 */
  readBits(n: number): number {
    if (n === 0) {
      return 0;
    }
    if (this.pos - n + 1 < this.minBit) {
      throw new PbpException(
        "BAD_FORMAT",
        `位流越界：需要 ${n} 位，实际只剩 ${this.pos - this.minBit + 1}`,
      );
    }
    let v = 0;
    for (let i = 0; i < n; i++) {
      v = v * 2 + ((this.src[this.pos >> 3] >>> (this.pos & 7)) & 1);
      this.pos--;
    }
    return v;
  }

  /** 位流是否已被恰好读完（RFC 要求序列位流必须精确消费）。 */
  consumedAll(): boolean {
    return this.pos < this.minBit;
  }
}

// ------------------------------------------------------------ 解码表

/**
 * FSE 解码表：每个状态给出符号、下一状态的额外位数与基线。
 *
 * <p>构造按 RFC §4.1.1：概率 &lt;1 的符号各占一个格子、从表尾倒退分配；其余符号按自然序、
 * 以 step 散布占格；最后按符号统计下一个状态，算出 nbBits/newStates。</p>
 */
export class DTable {
  readonly log: number;
  readonly symbols: number[];
  readonly nbBits: number[];
  readonly newStates: number[];

  private constructor(log: number, symbols: number[], nbBits: number[], newStates: number[]) {
    this.log = log;
    this.symbols = symbols;
    this.nbBits = nbBits;
    this.newStates = newStates;
  }

  /** RLE_Mode 的表：只有一个符号，不消费任何状态位。 */
  static rle(symbol: number): DTable {
    return new DTable(0, [symbol], [0], [0]);
  }

  static build(norm: number[], tableLog: number): DTable {
    const maxSymbol = norm.length - 1;
    const tableSize = 2 ** tableLog;
    const symbols = new Array<number>(tableSize).fill(0);
    const symbolNext = new Array<number>(maxSymbol + 1).fill(0);
    let highThreshold = tableSize - 1;
    for (let s = 0; s <= maxSymbol; s++) {
      if (norm[s] === -1) {
        symbols[highThreshold--] = s;
        symbolNext[s] = 1;
      } else {
        symbolNext[s] = norm[s];
      }
    }
    const step = (tableSize >> 1) + (tableSize >> 3) + 3;
    const mask = tableSize - 1;
    let position = 0;
    for (let s = 0; s <= maxSymbol; s++) {
      for (let i = 0; i < norm[s]; i++) {
        symbols[position] = s;
        position = (position + step) & mask;
        while (position > highThreshold) {
          position = (position + step) & mask;
        }
      }
    }
    const nbBits = new Array<number>(tableSize).fill(0);
    const newStates = new Array<number>(tableSize).fill(0);
    for (let u = 0; u < tableSize; u++) {
      const next = symbolNext[symbols[u]]++;
      const bits = tableLog - highBit(next);
      nbBits[u] = bits;
      newStates[u] = next * 2 ** bits - tableSize;
    }
    return new DTable(tableLog, symbols, nbBits, newStates);
  }
}

// ------------------------------------------------------------ 编码表

/**
 * FSE 编码表：每个符号的 deltaNbBits 同时编码「输出位数」与「下一状态基址」，
 * 这样 encodeSymbol 只做一次加法一次移位。</p>
 */
export class CTable {
  readonly log: number;
  readonly stateTable: number[];
  readonly deltaNbBits: number[];
  readonly deltaFindState: number[];

  private constructor(log: number, stateTable: number[], deltaNbBits: number[], deltaFindState: number[]) {
    this.log = log;
    this.stateTable = stateTable;
    this.deltaNbBits = deltaNbBits;
    this.deltaFindState = deltaFindState;
  }

  static build(norm: number[], tableLog: number): CTable {
    const maxSymbol = norm.length - 1;
    const tableSize = 2 ** tableLog;
    const mask = tableSize - 1;
    const step = (tableSize >> 1) + (tableSize >> 3) + 3;

    const cumul = new Array<number>(maxSymbol + 2).fill(0);
    const tableSymbol = new Array<number>(tableSize).fill(0);
    let highThreshold = tableSize - 1;
    for (let s = 0; s <= maxSymbol; s++) {
      if (norm[s] === -1) {
        cumul[s + 1] = cumul[s] + 1;
        tableSymbol[highThreshold--] = s;
      } else {
        cumul[s + 1] = cumul[s] + norm[s];
      }
    }
    let position = 0;
    for (let s = 0; s <= maxSymbol; s++) {
      for (let i = 0; i < norm[s]; i++) {
        tableSymbol[position] = s;
        position = (position + step) & mask;
        while (position > highThreshold) {
          position = (position + step) & mask;
        }
      }
    }
    const stateTable = new Array<number>(tableSize).fill(0);
    const running = cumul.slice();
    for (let u = 0; u < tableSize; u++) {
      stateTable[running[tableSymbol[u]]++] = tableSize + u;
    }

    const deltaNbBits = new Array<number>(maxSymbol + 1).fill(0);
    const deltaFindState = new Array<number>(maxSymbol + 1).fill(0);
    let total = 0;
    for (let s = 0; s <= maxSymbol; s++) {
      const freq = norm[s];
      if (freq === 0) {
        deltaNbBits[s] = (tableLog + 1) * 65536 - tableSize;
      } else if (freq === 1 || freq === -1) {
        deltaNbBits[s] = tableLog * 65536 - tableSize;
        deltaFindState[s] = total - 1;
        total++;
      } else {
        const maxBitsOut = tableLog - highBit(freq - 1);
        const minStatePlus = freq * 2 ** maxBitsOut;
        deltaNbBits[s] = maxBitsOut * 65536 - minStatePlus;
        deltaFindState[s] = total - freq;
        total += freq;
      }
    }
    return new CTable(tableLog, stateTable, deltaNbBits, deltaFindState);
  }
}

// ------------------------------------------------------------ 编码状态机

/** FSE 编码状态。 */
export class CState {
  value = 0;
}

export function initCState2(st: CState, table: CTable, symbol: number): void {
  const nbBitsOut = Math.floor((table.deltaNbBits[symbol] + 32768) / 65536);
  const v = nbBitsOut * 65536 - table.deltaNbBits[symbol];
  st.value = table.stateTable[Math.floor(v / 2 ** nbBitsOut) + table.deltaFindState[symbol]];
}

export function encodeSymbol(writer: BitWriter, st: CState, table: CTable, symbol: number): void {
  const nbBitsOut = Math.floor((st.value + table.deltaNbBits[symbol]) / 65536);
  writer.addBits(st.value, nbBitsOut);
  st.value = table.stateTable[Math.floor(st.value / 2 ** nbBitsOut) + table.deltaFindState[symbol]];
}

export function flushCState(writer: BitWriter, st: CState, table: CTable): void {
  writer.addBits(st.value, table.log);
}