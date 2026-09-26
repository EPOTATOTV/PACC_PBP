import { PbpException } from "./PbpException.js";

/**
 * PBP 消息帧：固定 30 字节帧头 + 载荷 + 可选 32 字节签名。
 *
 * <pre>
 *   偏移  长度  字段
 *   0     2     Magic        0x5042 "PB"
 *   2     1     Version      协议版本，当前 1
 *   3     1     Flags        bit0 加密 / bit1 压缩 / bit2 差分 / bit3 签名
 *   4     2     MessageID    uint16
 *   6     4     Sequence     uint32
 *   10    8     Timestamp    int64 毫秒
 *   18    8     SessionID    uint64
 *   26    4     PayloadLen   uint32
 *   30    N     Payload
 *   30+N  32    Signature    HMAC-SHA256（Flags bit3 置位时存在）
 * </pre>
 *
 * <p>多字节字段一律小端，唯一例外是开头的 2 字节 Magic：它是 ASCII 标记，按 'P','B' 顺序写。</p>
 *
 * <p>本类只负责布局与长度校验，不碰密码学：签名计算在 PbpCrypto，这样帧解析可以在
 * 没有密钥的场景（如抓包分析）下单独使用。</p>
 */
const MASK64 = 0xffffffffffffffffn;

export class PbpFrame {
  static readonly MAGIC = 0x5042;
  static readonly VERSION = 1;
  static readonly MIN_VERSION = 1;
  static readonly HEADER_SIZE = 30;
  static readonly SIGNATURE_SIZE = 32;

  static readonly FLAG_ENCRYPTED = 0x01;
  static readonly FLAG_COMPRESSED = 0x02;
  static readonly FLAG_DELTA = 0x04;
  static readonly FLAG_SIGNED = 0x08;

  /** 已知标志位掩码；其余位为保留位，置位即视为协议不认识。 */
  private static readonly KNOWN_FLAGS =
    PbpFrame.FLAG_ENCRYPTED | PbpFrame.FLAG_COMPRESSED | PbpFrame.FLAG_DELTA | PbpFrame.FLAG_SIGNED;

  /** 载荷长度硬上限（帧头 PayloadLen 是 uint32，真按它分配就等于把内存交给对端控制）。 */
  static readonly MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

  private static readonly OFF_MAGIC = 0;
  private static readonly OFF_VERSION = 2;
  private static readonly OFF_FLAGS = 3;
  private static readonly OFF_MESSAGE_ID = 4;
  private static readonly OFF_SEQUENCE = 6;
  private static readonly OFF_TIMESTAMP = 10;
  private static readonly OFF_SESSION_ID = 18;
  private static readonly OFF_PAYLOAD_LEN = 26;

  readonly version: number;
  readonly flags: number;
  readonly messageId: number;
  readonly sequence: number;
  readonly timestampMs: bigint;
  readonly sessionId: bigint;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;

  constructor(
    version: number,
    flags: number,
    messageId: number,
    sequence: number,
    timestampMs: bigint,
    sessionId: bigint,
    payload: Uint8Array | null,
    signature: Uint8Array | null,
  ) {
    this.version = version;
    this.flags = flags;
    this.messageId = messageId;
    this.sequence = sequence;
    this.timestampMs = timestampMs;
    this.sessionId = sessionId;
    this.payload = payload === null ? new Uint8Array(0) : payload.slice();
    this.signature = signature === null ? new Uint8Array(0) : signature.slice();
  }

  /** 构造一条无签名帧（sessionId 与 sequence 默认 0，由需要它们的上层显式覆盖）。 */
  static of(messageId: number, timestampMs: bigint, payload: Uint8Array): PbpFrame {
    return new PbpFrame(PbpFrame.VERSION, 0, messageId, 0, timestampMs, 0n, payload, null);
  }

  signed(): boolean {
    return (this.flags & PbpFrame.FLAG_SIGNED) !== 0;
  }

  compressed(): boolean {
    return (this.flags & PbpFrame.FLAG_COMPRESSED) !== 0;
  }

  delta(): boolean {
    return (this.flags & PbpFrame.FLAG_DELTA) !== 0;
  }

  /** 返回置位指定标志的副本；只允许置已知标志位。 */
  withFlag(flag: number): PbpFrame {
    if (flag === 0) {
      return this;
    }
    if ((flag & ~PbpFrame.KNOWN_FLAGS) !== 0 || flag === PbpFrame.FLAG_ENCRYPTED) {
      throw new PbpException("UNSUPPORTED_FLAG", `不能置位未实现的标志: 0x${flag.toString(16)}`);
    }
    return new PbpFrame(
      this.version,
      this.flags | flag,
      this.messageId,
      this.sequence,
      this.timestampMs,
      this.sessionId,
      this.payload,
      this.signature,
    );
  }

  payloadLength(): number {
    return this.payload.length;
  }

  /**
   * 返回带签名的副本：置位 FLAG_SIGNED 并写入 32 字节签名。
   *
   * <p>签名覆盖 signingInput()，其中帧头是按 FLAG_SIGNED 已置位的形态计算的，因此签名方与
   * 验签方拿到的是同一串字节。</p>
   */
  withSignature(sig: Uint8Array): PbpFrame {
    if (sig === null || sig.length !== PbpFrame.SIGNATURE_SIZE) {
      throw new PbpException(
        "BAD_LENGTH",
        `签名必须是 ${PbpFrame.SIGNATURE_SIZE} 字节，实际 ${sig === null ? "null" : sig.length}`,
      );
    }
    return new PbpFrame(
      this.version,
      this.flags | PbpFrame.FLAG_SIGNED,
      this.messageId,
      this.sequence,
      this.timestampMs,
      this.sessionId,
      this.payload,
      sig,
    );
  }

  /** HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。 */
  signingInput(): Uint8Array {
    const payloadLen = this.payload.length;
    const out = new Uint8Array(PbpFrame.HEADER_SIZE + payloadLen);
    putHeader(out, this, this.flags | PbpFrame.FLAG_SIGNED, payloadLen);
    out.set(this.payload, PbpFrame.HEADER_SIZE);
    return out;
  }

  /** 序列化为完整帧字节；签名是否存在由 FLAG_SIGNED 决定。 */
  encode(): Uint8Array {
    PbpFrame.validateFlags(this.flags);
    if (this.version !== PbpFrame.VERSION) {
      throw new PbpException(
        "BAD_VERSION",
        `本运行时只支持版本 ${PbpFrame.VERSION}，不能编码版本 ${this.version}`,
      );
    }
    const payloadLen = this.payload.length;
    if (payloadLen > PbpFrame.MAX_PAYLOAD_SIZE) {
      throw new PbpException("BAD_LENGTH", `载荷长度超上限: ${payloadLen}`);
    }
    const isSigned = this.signed();
    if (isSigned && this.signature.length !== PbpFrame.SIGNATURE_SIZE) {
      throw new PbpException(
        "BAD_LENGTH",
        `帧头声明已签名，但签名长度为 ${this.signature.length}`,
      );
    }
    if (!isSigned && this.signature.length !== 0) {
      throw new PbpException("BAD_FORMAT", "带了签名字节但 FLAG_SIGNED 未置位");
    }

    const out = new Uint8Array(PbpFrame.HEADER_SIZE + payloadLen + (isSigned ? PbpFrame.SIGNATURE_SIZE : 0));
    putHeader(out, this, this.flags, payloadLen);
    out.set(this.payload, PbpFrame.HEADER_SIZE);
    if (isSigned) {
      out.set(this.signature, PbpFrame.HEADER_SIZE + payloadLen);
    }
    return out;
  }

  /** 解析完整帧；任何长度或标志位不符都抛 PbpException。 */
  static parse(raw: Uint8Array): PbpFrame {
    if (raw === null || raw.length < PbpFrame.HEADER_SIZE) {
      throw new PbpException(
        "TRUNCATED",
        `帧长度不足 ${PbpFrame.HEADER_SIZE} 字节: ${raw === null ? "null" : raw.length}`,
      );
    }
    const magic = ((raw[PbpFrame.OFF_MAGIC] & 0xff) << 8) | (raw[PbpFrame.OFF_MAGIC + 1] & 0xff);
    if (magic !== PbpFrame.MAGIC) {
      throw new PbpException("BAD_MAGIC", `Magic 不是 "PB": 0x${magic.toString(16)}`);
    }
    const version = raw[PbpFrame.OFF_VERSION] & 0xff;
    if (version < PbpFrame.MIN_VERSION) {
      throw new PbpException(
        "BAD_VERSION",
        `协议版本过旧: ${version}（最低支持 ${PbpFrame.MIN_VERSION}）`,
      );
    }
    if (version > PbpFrame.VERSION) {
      throw new PbpException(
        "BAD_VERSION",
        `协议版本过新: ${version}（本运行时最高支持 ${PbpFrame.VERSION}）`,
      );
    }
    const flags = raw[PbpFrame.OFF_FLAGS] & 0xff;
    PbpFrame.validateFlags(flags);

    const payloadLen = getUInt32(raw, PbpFrame.OFF_PAYLOAD_LEN);
    if (payloadLen > PbpFrame.MAX_PAYLOAD_SIZE) {
      throw new PbpException("BAD_LENGTH", `载荷长度超上限: ${payloadLen}`);
    }
    const isSigned = (flags & PbpFrame.FLAG_SIGNED) !== 0;
    const expected = PbpFrame.HEADER_SIZE + payloadLen + (isSigned ? PbpFrame.SIGNATURE_SIZE : 0);
    if (raw.length !== expected) {
      throw new PbpException(
        "BAD_LENGTH",
        `帧长与 PayloadLen 不符: 实际 ${raw.length}，按声明应为 ${expected}`,
      );
    }

    const payload = raw.slice(PbpFrame.HEADER_SIZE, PbpFrame.HEADER_SIZE + payloadLen);
    const signature = isSigned
      ? raw.slice(PbpFrame.HEADER_SIZE + payloadLen, expected)
      : new Uint8Array(0);
    return new PbpFrame(
      version,
      flags,
      getUInt16(raw, PbpFrame.OFF_MESSAGE_ID),
      getUInt32(raw, PbpFrame.OFF_SEQUENCE),
      readInt64(raw, PbpFrame.OFF_TIMESTAMP),
      readUInt64(raw, PbpFrame.OFF_SESSION_ID),
      payload,
      signature,
    );
  }

  private static validateFlags(flags: number): void {
    if ((flags & PbpFrame.FLAG_ENCRYPTED) !== 0) {
      throw new PbpException(
        "UNSUPPORTED_FLAG",
        `当前版本未实现加密标志位 0x${PbpFrame.FLAG_ENCRYPTED.toString(16)}`,
      );
    }
    const unknown = flags & ~PbpFrame.KNOWN_FLAGS;
    if (unknown !== 0) {
      throw new PbpException("UNSUPPORTED_FLAG", `保留标志位被置位: 0x${unknown.toString(16)}`);
    }
  }
}

function putHeader(out: Uint8Array, header: PbpFrame, flags: number, payloadLen: number): void {
  // Magic 是 ASCII 标记，按可读顺序写 'P','B'；帧头其余多字节字段才是小端。
  out[0] = (PbpFrame.MAGIC >>> 8) & 0xff;
  out[1] = PbpFrame.MAGIC & 0xff;
  out[2] = header.version & 0xff;
  out[3] = flags & 0xff;
  writeUInt16LE(out, 4, header.messageId);
  writeUInt32LE(out, 6, header.sequence);
  writeInt64LE(out, 10, header.timestampMs);
  writeInt64LE(out, 18, header.sessionId);
  writeUInt32LE(out, 26, payloadLen);
}

function writeUInt16LE(b: Uint8Array, off: number, v: number): void {
  b[off] = v & 0xff;
  b[off + 1] = (v >>> 8) & 0xff;
}

function writeUInt32LE(b: Uint8Array, off: number, v: number): void {
  for (let i = 0; i < 4; i++) {
    b[off + i] = (v >>> (i * 8)) & 0xff;
  }
}

function writeInt64LE(b: Uint8Array, off: number, v: bigint): void {
  const masked = v & MASK64;
  for (let i = 0; i < 8; i++) {
    b[off + i] = Number((masked >> BigInt(i * 8)) & 0xffn);
  }
}

function readUIntLE(b: Uint8Array, off: number, size: number): bigint {
  let v = 0n;
  for (let i = 0; i < size; i++) {
    v |= BigInt(b[off + i]) << BigInt(i * 8);
  }
  return v;
}

function readUInt64(b: Uint8Array, off: number): bigint {
  return readUIntLE(b, off, 8);
}

function readInt64(b: Uint8Array, off: number): bigint {
  const v = readUIntLE(b, off, 8);
  return v >= 0x8000000000000000n ? v - 0x10000000000000000n : v;
}

function getUInt16(b: Uint8Array, off: number): number {
  return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
}

function getUInt32(b: Uint8Array, off: number): number {
  let v = 0;
  for (let i = 0; i < 4; i++) {
    v |= (b[off + i] & 0xff) << (i * 8);
  }
  return v >>> 0;
}