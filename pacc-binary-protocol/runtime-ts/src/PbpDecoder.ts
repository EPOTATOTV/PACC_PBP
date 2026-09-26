import { PbpEncoder } from "./PbpEncoder.js";
import { PbpException } from "./PbpException.js";
import type { PbpMessage } from "./PbpMessage.js";

/**
 * PBP 二进制解码器。
 *
 * <p>与 PbpEncoder 严格镜像：同样的字段顺序、同样的类型宽度。</p>
 *
 * <p>所有读取都做边界检查，越界一律抛 PbpException 而不是返回默认值 —— 输入来自网络，
 * 静默截断会把「攻击者截断了载荷」变成「对端发了个全零消息」，后者在日志上完全看不出来。</p>
 */

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

/** 集合元素个数上界：挡住伪造长度的循环消耗，正常载荷远远够用。 */
const MAX_COLLECTION_SIZE = 1 << 20;

export class PbpDecoder {
  private readonly buf: Uint8Array;
  private readonly limit: number;
  private pos: number;

  constructor(buf: Uint8Array, offset = 0, length = buf.length - offset) {
    if (offset < 0 || length < 0 || offset + length > buf.length) {
      throw new PbpException(
        "BAD_LENGTH",
        `解码窗口越界: offset=${offset} length=${length} capacity=${buf.length}`,
      );
    }
    this.buf = buf;
    this.pos = offset;
    this.limit = offset + length;
  }

  /** 尚未读取的字节数。 */
  remaining(): number {
    return this.limit - this.pos;
  }

  hasRemaining(): boolean {
    return this.pos < this.limit;
  }

  /** 已消费的字节数（相对解码窗口起点）。 */
  position(): number {
    return this.pos;
  }

  /** 丢弃剩余字节（向前兼容：旧端不认识的尾巴直接跳过）。 */
  skipRemaining(): void {
    this.pos = this.limit;
  }

  // ------------------------------------------------------------ 标量

  readBool(): boolean {
    const b = this.readRaw();
    if (b !== 0 && b !== 1) {
      throw new PbpException("BAD_FORMAT", `bool 字段只能是 0/1，读到 ${b}`);
    }
    return b === 1;
  }

  readInt8(): number {
    return this.readRaw() << 24 >> 24;
  }

  readUInt8(): number {
    return this.readRaw();
  }

  readInt16(): number {
    const lo = this.readRaw();
    const hi = this.readRaw();
    return ((hi << 8) | lo) << 16 >> 16;
  }

  readUInt16(): number {
    const lo = this.readRaw();
    const hi = this.readRaw();
    return (hi << 8) | lo;
  }

  readInt32(): number {
    const z = Number(this.readVarInt() & 0xffffffffn);
    return ((z >>> 1) ^ -(z & 1)) | 0;
  }

  readUInt32(): number {
    const v = this.readVarInt();
    if (v > 0xffffffffn) {
      throw new PbpException("BAD_FORMAT", `uint32 溢出: ${v}`);
    }
    return Number(v);
  }

  readInt64(): bigint {
    const z = this.readVarInt();
    return (z >> 1n) ^ -(z & 1n);
  }

  /** 返回 64 位无符号原始位模式，调用方按无符号解释。 */
  readUInt64(): bigint {
    return this.readVarInt();
  }

  readEnum(): number {
    const v = this.readUInt32();
    if (v > 0x7fffffff) {
      throw new PbpException("BAD_FORMAT", `enum 值溢出: ${v}`);
    }
    return v;
  }

  readFloat32(): number {
    this.requireBytes(4);
    const view = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 4);
    this.pos += 4;
    return view.getFloat32(0, true);
  }

  readFloat64(): number {
    this.requireBytes(8);
    const view = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 8);
    this.pos += 8;
    return view.getFloat64(0, true);
  }

  // ------------------------------------------------------------ 变长

  readString(): string {
    const length = this.readLength();
    const s = this.decodeUtf8(this.pos, length);
    this.pos += length;
    return s;
  }

  readBytes(): Uint8Array {
    const length = this.readLength();
    const out = this.buf.slice(this.pos, this.pos + length);
    this.pos += length;
    return out;
  }

  // ------------------------------------------------------------ 可空字段

  /** 读取 fieldCount 个连续可空字段的存在位图，低位对应更靠前的字段。 */
  readPresence(fieldCount: number): boolean[] {
    if (fieldCount < 0) {
      throw new PbpException("BAD_FORMAT", `可空字段数为负: ${fieldCount}`);
    }
    const byteCount = (fieldCount + 7) >> 3;
    const present: boolean[] = new Array(fieldCount).fill(false);
    for (let i = 0; i < byteCount; i++) {
      const bits = this.readRaw();
      for (let bit = 0; bit < 8; bit++) {
        const idx = i * 8 + bit;
        if (idx < fieldCount) {
          present[idx] = (bits & (1 << bit)) !== 0;
        }
      }
    }
    return present;
  }

  readOptionalString(): string | null {
    return this.readPresence(1)[0] ? this.readString() : null;
  }

  readOptionalBytes(): Uint8Array | null {
    return this.readPresence(1)[0] ? this.readBytes() : null;
  }

  readOptionalMessage<T extends PbpMessage>(factory: () => T): T | null {
    return this.readPresence(1)[0] ? this.readMessage(factory) : null;
  }

  // ------------------------------------------------------------ 消息与集合

  readMessage<T extends PbpMessage>(factory: () => T): T {
    const msg = factory();
    msg.decode(this);
    return msg;
  }

  readMessageList<T extends PbpMessage>(factory: () => T): T[] {
    const count = this.readCount("list");
    const list: T[] = [];
    for (let i = 0; i < count; i++) {
      list.push(this.readMessage(factory));
    }
    return list;
  }

  readStringList(): string[] {
    return this.readList(() => [], (dec) => dec.readString());
  }

  readList<T>(factory: () => T[], elementReader: (dec: PbpDecoder) => T): T[] {
    const count = this.readCount("list");
    const list = factory();
    for (let i = 0; i < count; i++) {
      list.push(elementReader(this));
    }
    return list;
  }

  readMap<K, V>(
    factory: () => Map<K, V>,
    keyReader: (dec: PbpDecoder) => K,
    valueReader: (dec: PbpDecoder) => V,
  ): Map<K, V> {
    const count = this.readCount("map");
    const map = factory();
    for (let i = 0; i < count; i++) {
      const key = keyReader(this);
      const value = valueReader(this);
      map.set(key, value);
    }
    return map;
  }

  /** 键固定为 string 的映射，默认用 Map 保持线上顺序（便于比对与复现）。 */
  readStringMap<V>(valueReader: (dec: PbpDecoder) => V): Map<string, V> {
    return this.readMap(() => new Map<string, V>(), (dec) => dec.readString(), valueReader);
  }

  // ------------------------------------------------------------ 落地

  private readRaw(): number {
    if (this.pos >= this.limit) {
      throw new PbpException("TRUNCATED", `读取越界: 位置 ${this.pos} 已达上限 ${this.limit}`);
    }
    return this.buf[this.pos++];
  }

  private requireBytes(n: number): void {
    if (this.pos + n > this.limit) {
      throw new PbpException("TRUNCATED", `读取越界: 位置 ${this.pos} 需要 ${n} 字节已达上限 ${this.limit}`);
    }
  }

  /** VarInt 解码，最多 10 字节；超过 10 字节或第 10 字节溢出 64 位一律拒绝。 */
  private readVarInt(): bigint {
    let value = 0n;
    for (let i = 0; i < PbpEncoder.MAX_VARINT_BYTES; i++) {
      const b = this.readRaw();
      if (i === 9 && (b & 0xfe) !== 0) {
        throw new PbpException("BAD_VARINT", "VarInt 第 10 字节溢出 64 位");
      }
      value |= BigInt(b & 0x7f) << BigInt(i * 7);
      if ((b & 0x80) === 0) {
        return value;
      }
    }
    throw new PbpException("BAD_VARINT", "VarInt 超过 10 字节");
  }

  private readLength(): number {
    const length = this.readVarInt();
    if (length < 0n || length > BigInt(this.remaining())) {
      throw new PbpException(
        "TRUNCATED",
        `变长字段声明长度 ${length} 超出剩余 ${this.remaining()} 字节`,
      );
    }
    return Number(length);
  }

  private readCount(what: string): number {
    const count = this.readVarInt();
    if (count < 0n || count > BigInt(MAX_COLLECTION_SIZE)) {
      throw new PbpException("BAD_FORMAT", `${what} 元素个数越界: ${count}`);
    }
    return Number(count);
  }

  /** 严格 UTF-8 解码：非法字节序列直接失败，避免把篡改内容当有效字符串用下去。 */
  private decodeUtf8(offset: number, length: number): string {
    try {
      return UTF8_DECODER.decode(this.buf.subarray(offset, offset + length));
    } catch (e) {
      throw new PbpException("BAD_FORMAT", "字符串字段不是合法 UTF-8", e);
    }
  }
}