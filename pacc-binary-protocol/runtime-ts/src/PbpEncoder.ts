import { PbpException } from "./PbpException.js";
import type { PbpMessage } from "./PbpMessage.js";

/**
 * PBP 二进制编码器。
 *
 * <p>字段按 MDL 定义顺序写入、不带标签：省掉每个字段 1-2 字节的标签开销，代价是编解码双方
 * 必须持有同一份字段顺序定义，且新字段只能加在末尾。</p>
 *
 * <p>所有多字节定长字段一律小端，与帧头保持一致。int64/uint64 用 bigint 承载，
 * 因为 JS number 只有 53 位精度，撑不住 ZigZag 后的 64 位取值。</p>
 */

const UTF8_ENCODER = new TextEncoder();
const FLOAT_SCRATCH = new DataView(new ArrayBuffer(8));
const MASK64 = 0xffffffffffffffffn;

export class PbpEncoder {
  /** VarInt 最多 10 字节（每 7 位一组，64 位需要 10 组）。 */
  static readonly MAX_VARINT_BYTES = 10;

  private buf: Uint8Array;
  private len = 0;

  constructor(initialCapacity = 64) {
    this.buf = new Uint8Array(Math.max(16, initialCapacity));
  }

  /** 已写入的字节数。 */
  size(): number {
    return this.len;
  }

  /** 复制出当前已写入的字节，长度正好等于 size()。 */
  toByteArray(): Uint8Array {
    return this.buf.slice(0, this.len);
  }

  /** 清空缓冲区以便复用；容量保留。 */
  reset(): void {
    this.len = 0;
  }

  // ------------------------------------------------------------ 标量

  writeBool(v: boolean): this {
    return this.writeByte(v ? 1 : 0);
  }

  writeInt8(v: number): this {
    requireRange(v, -128, 127, "int8");
    return this.writeByte(v & 0xff);
  }

  writeUInt8(v: number): this {
    requireRange(v, 0, 0xff, "uint8");
    return this.writeByte(v & 0xff);
  }

  writeInt16(v: number): this {
    requireRange(v, -32768, 32767, "int16");
    const u = v & 0xffff;
    return this.writeByte(u & 0xff).writeByte((u >>> 8) & 0xff);
  }

  writeUInt16(v: number): this {
    requireRange(v, 0, 0xffff, "uint16");
    return this.writeByte(v & 0xff).writeByte((v >>> 8) & 0xff);
  }

  /** int32 走 ZigZag + VarInt（负数不会占满 10 字节）。 */
  writeInt32(v: number): this {
    const zz = ((v << 1) ^ (v >> 31)) >>> 0;
    this.writeVarInt(BigInt(zz));
    return this;
  }

  /** uint32 走 VarInt。 */
  writeUInt32(v: number): this {
    requireRange(v, 0, 0xffffffff, "uint32");
    this.writeVarInt(BigInt(v));
    return this;
  }

  /** int64 走 ZigZag + VarInt。 */
  writeInt64(v: bigint): this {
    const zz = ((v << 1n) ^ (v >> 63n)) & MASK64;
    this.writeVarInt(zz);
    return this;
  }

  /** uint64 走 VarInt，按 64 位无符号位模式写入。 */
  writeUInt64(v: bigint): this {
    this.writeVarInt(v & MASK64);
    return this;
  }

  writeEnum(v: number): this {
    if (v < 0) {
      throw new PbpException("BAD_FORMAT", `enum 值不能为负: ${v}`);
    }
    this.writeVarInt(BigInt(v));
    return this;
  }

  writeFloat32(v: number): this {
    FLOAT_SCRATCH.setFloat32(0, v, true);
    for (let i = 0; i < 4; i++) {
      this.writeByte(FLOAT_SCRATCH.getUint8(i));
    }
    return this;
  }

  writeFloat64(v: number): this {
    FLOAT_SCRATCH.setFloat64(0, v, true);
    for (let i = 0; i < 8; i++) {
      this.writeByte(FLOAT_SCRATCH.getUint8(i));
    }
    return this;
  }

  // ------------------------------------------------------------ 变长

  /** UTF-8 字符串：VarInt 字节长度 + 数据。null 必须走 writeOptionalString。 */
  writeString(s: string): this {
    if (s === null || s === undefined) {
      throw new PbpException("BAD_FORMAT", "string 字段为 null，可空字段请用 writeOptionalString");
    }
    const b = UTF8_ENCODER.encode(s);
    this.writeVarInt(BigInt(b.length));
    return this.writeBytesRaw(b);
  }

  writeBytes(b: Uint8Array): this {
    if (b === null || b === undefined) {
      throw new PbpException("BAD_FORMAT", "bytes 字段为 null，可空字段请用 writeOptionalBytes");
    }
    this.writeVarInt(BigInt(b.length));
    return this.writeBytesRaw(b);
  }

  // ------------------------------------------------------------ 可空字段

  /** 写入一段连续可空字段的存在位图，低位对应更靠前的字段。 */
  writePresence(present: readonly boolean[]): this {
    const byteCount = (present.length + 7) >> 3;
    for (let i = 0; i < byteCount; i++) {
      let bits = 0;
      for (let bit = 0; bit < 8; bit++) {
        const idx = i * 8 + bit;
        if (idx < present.length && present[idx]) {
          bits |= 1 << bit;
        }
      }
      this.writeByte(bits & 0xff);
    }
    return this;
  }

  writeOptionalString(s: string | null): this {
    this.writePresence([s !== null]);
    return s === null ? this : this.writeString(s);
  }

  writeOptionalBytes(b: Uint8Array | null): this {
    this.writePresence([b !== null]);
    return b === null ? this : this.writeBytes(b);
  }

  writeOptionalMessage(m: PbpMessage | null): this {
    this.writePresence([m !== null]);
    return m === null ? this : this.writeMessage(m);
  }

  // ------------------------------------------------------------ 消息与集合

  /** 嵌套消息内联编码，不加长度前缀：字段顺序即边界，由最外层帧的 PayloadLen 兜底。 */
  writeMessage(m: PbpMessage | null): this {
    if (m === null || m === undefined) {
      throw new PbpException("BAD_FORMAT", "嵌套消息为 null，可空字段请用 writeOptionalMessage");
    }
    m.encode(this);
    return this;
  }

  writeMessageList(list: readonly PbpMessage[] | null): this {
    if (list === null) {
      throw new PbpException("BAD_FORMAT", "消息列表为 null");
    }
    this.writeVarInt(BigInt(list.length));
    for (const m of list) {
      m.encode(this);
    }
    return this;
  }

  writeStringList(list: readonly string[] | null): this {
    return this.writeList(list, (e, v) => e.writeString(v));
  }

  /** 通用列表：元素为标量时用 {@code (e, v) => e.writeInt64(v)} 这类回调传入。 */
  writeList<T>(list: readonly T[] | null, elementWriter: (enc: PbpEncoder, value: T) => void): this {
    if (list === null) {
      throw new PbpException("BAD_FORMAT", "列表为 null");
    }
    this.writeVarInt(BigInt(list.length));
    for (const e of list) {
      elementWriter(this, e);
    }
    return this;
  }

  /** 通用映射：键值对按 Map 迭代顺序写入，两侧需使用有序 Map 才能保证字节一致。 */
  writeMap<K, V>(
    map: Map<K, V> | null,
    keyWriter: (enc: PbpEncoder, key: K) => void,
    valueWriter: (enc: PbpEncoder, value: V) => void,
  ): this {
    if (map === null) {
      throw new PbpException("BAD_FORMAT", "map 为 null");
    }
    this.writeVarInt(BigInt(map.size));
    for (const [key, value] of map) {
      keyWriter(this, key);
      valueWriter(this, value);
    }
    return this;
  }

  /** 键固定为 string 的映射。 */
  writeStringMap<V>(map: Map<string, V> | null, valueWriter: (enc: PbpEncoder, value: V) => void): this {
    return this.writeMap(map, (e, k) => e.writeString(k), valueWriter);
  }

  // ------------------------------------------------------------ 长度预估（纯预分配提示）

  static varIntSize(v: bigint): number {
    let n = 1;
    let value = v;
    while ((value & ~0x7fn) !== 0n) {
      value >>= 7n;
      n++;
    }
    return n;
  }

  static boolSize(): number {
    return 1;
  }

  static int8Size(): number {
    return 1;
  }

  static uint8Size(): number {
    return 1;
  }

  static int16Size(): number {
    return 2;
  }

  static uint16Size(): number {
    return 2;
  }

  static int32Size(v: number): number {
    return PbpEncoder.varIntSize(BigInt(((v << 1) ^ (v >> 31)) >>> 0));
  }

  static uint32Size(v: number): number {
    return PbpEncoder.varIntSize(BigInt(v));
  }

  static int64Size(v: bigint): number {
    return PbpEncoder.varIntSize(((v << 1n) ^ (v >> 63n)) & MASK64);
  }

  static uint64Size(v: bigint): number {
    return PbpEncoder.varIntSize(v & MASK64);
  }

  static enumSize(v: number): number {
    return PbpEncoder.varIntSize(BigInt(v));
  }

  static float32Size(): number {
    return 4;
  }

  static float64Size(): number {
    return 8;
  }

  static stringSize(s: string | null): number {
    if (s === null) {
      return 0;
    }
    return PbpEncoder.varIntSize(BigInt(UTF8_ENCODER.encode(s).length)) + UTF8_ENCODER.encode(s).length;
  }

  static bytesSize(b: Uint8Array | null): number {
    return b === null ? 0 : PbpEncoder.varIntSize(BigInt(b.length)) + b.length;
  }

  static presenceSize(fieldCount: number): number {
    return (fieldCount + 7) >> 3;
  }

  static optionalStringSize(s: string | null): number {
    return 1 + PbpEncoder.stringSize(s);
  }

  static optionalBytesSize(b: Uint8Array | null): number {
    return 1 + PbpEncoder.bytesSize(b);
  }

  static messageSize(m: PbpMessage | null): number {
    return m === null ? 0 : m.encodedSize();
  }

  static optionalMessageSize(m: PbpMessage | null): number {
    return 1 + PbpEncoder.messageSize(m);
  }

  static messageListSize(list: readonly PbpMessage[] | null): number {
    if (list === null) {
      return 0;
    }
    let size = PbpEncoder.varIntSize(BigInt(list.length));
    for (const m of list) {
      size += m.encodedSize();
    }
    return size;
  }

  static stringListSize(list: readonly string[] | null): number {
    if (list === null) {
      return 0;
    }
    let size = PbpEncoder.varIntSize(BigInt(list.length));
    for (const s of list) {
      size += PbpEncoder.stringSize(s);
    }
    return size;
  }

  static listSize<T>(list: readonly T[] | null, elementSize: (value: T) => number): number {
    if (list === null) {
      return 0;
    }
    let size = PbpEncoder.varIntSize(BigInt(list.length));
    for (const e of list) {
      size += elementSize(e);
    }
    return size;
  }

  static mapSize<K, V>(
    map: Map<K, V> | null,
    keySize: (key: K) => number,
    valueSize: (value: V) => number,
  ): number {
    if (map === null) {
      return 0;
    }
    let size = PbpEncoder.varIntSize(BigInt(map.size));
    for (const [key, value] of map) {
      size += keySize(key) + valueSize(value);
    }
    return size;
  }

  static stringMapSize<V>(map: Map<string, V> | null, valueSize: (value: V) => number): number {
    return PbpEncoder.mapSize(map, (k) => PbpEncoder.stringSize(k), valueSize);
  }

  // ------------------------------------------------------------ 落地

  private writeByte(b: number): this {
    this.ensure(1);
    this.buf[this.len++] = b & 0xff;
    return this;
  }

  private writeBytesRaw(src: Uint8Array): this {
    if (src.length === 0) {
      return this;
    }
    this.ensure(src.length);
    this.buf.set(src, this.len);
    this.len += src.length;
    return this;
  }

  private writeVarInt(value: bigint): void {
    let v = value;
    while ((v & ~0x7fn) !== 0n) {
      this.writeByte(Number((v & 0x7fn) | 0x80n));
      v >>= 7n;
    }
    this.writeByte(Number(v & 0x7fn));
  }

  private ensure(extra: number): void {
    const need = this.len + extra;
    if (need <= this.buf.length) {
      return;
    }
    let capacity = this.buf.length;
    while (capacity < need) {
      capacity = capacity < 1024 ? capacity * 2 : capacity + (capacity >> 1);
    }
    const grown = new Uint8Array(capacity);
    grown.set(this.buf.subarray(0, this.len));
    this.buf = grown;
  }
}

function requireRange(v: number, min: number, max: number, type: string): void {
  if (v < min || v > max) {
    throw new PbpException("BAD_FORMAT", `${type} 越界: ${v}`);
  }
}