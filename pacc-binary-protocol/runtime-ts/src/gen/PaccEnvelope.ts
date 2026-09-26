// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

import type { PbpMessage } from "../PbpMessage.js";
import { PbpCodec } from "../PbpCodec.js";
import { PbpDecoder } from "../PbpDecoder.js";
import { PbpEncoder } from "../PbpEncoder.js";
import { PbpException } from "../PbpException.js";
import { PbpFrame } from "../PbpFrame.js";
import { bytesFromHex, bytesToHex } from "../PbpCrypto.js";

/**
 * PBP 消息 PaccEnvelope（0x2001，0x2000-0x2FFF 双向）。
 *
 * 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。
 *
 * 签名不在载荷里：置位帧头 FLAG_SIGNED，32 字节 HMAC-SHA256 放在帧尾，
 * 覆盖面是「帧头 + 载荷」整串字节（见 signingInput()）。
 */
export class PaccEnvelope implements PbpMessage {
  /** MDL 里声明的消息 ID。 */
  static readonly MESSAGE_ID = 0x2001;

  // ------------------------------------------------------------ 字段

  type: string = "";
  tsMs: bigint = 0n;
  nonce: string = "";
  sessionId: string = "";
  pteid: string = "";
  payloadJson: string = "";
  sigVersion: number = 0;

  // 帧尾签名，载荷里没有这个字段
  signature: Uint8Array = new Uint8Array(0);

  /** 建一个空构造器；可空性由 MDL 决定：String 与 byte[] 默认空值、消息类型字段默认 null。 */
  static newBuilder(): PaccEnvelopeBuilder {
    return new PaccEnvelopeBuilder();
  }

  /** 以当前值为初值开一个新构造器（例如改完字段要重新签名）。 */
  toBuilder(): PaccEnvelopeBuilder {
    const builder = new PaccEnvelopeBuilder();
    builder.type = this.type;
    builder.tsMs = this.tsMs;
    builder.nonce = this.nonce;
    builder.sessionId = this.sessionId;
    builder.pteid = this.pteid;
    builder.payloadJson = this.payloadJson;
    builder.sigVersion = this.sigVersion;
    builder.signature = this.signature.slice();
    return builder;
  }

  // ------------------------------------------------------------ 帧

  /** 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。 */
  toByteArray(): Uint8Array {
    let frame = PbpCodec.frameOf(this, this.tsMs);
    if (this.signature.length === PbpFrame.SIGNATURE_SIZE) {
      frame = frame.withSignature(this.signature);
    } else if (this.signature.length !== 0) {
      throw new PbpException(
        "BAD_LENGTH",
        `签名长度必须是 0 或 ${PbpFrame.SIGNATURE_SIZE}，实际 ${this.signature.length}`,
      );
    }
    return frame.encode();
  }

  /** HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。 */
  signingInput(): Uint8Array {
    return PbpCodec.frameOf(this, this.tsMs).signingInput();
  }

  /** 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。置位 FLAG_COMPRESSED 的帧先解压再解码载荷。 */
  static parseFrom(raw: Uint8Array): PaccEnvelope {
    const frame = PbpFrame.parse(raw);
    if (frame.messageId !== PaccEnvelope.MESSAGE_ID) {
      throw new PbpException(
        "BAD_FORMAT",
        `消息 ID 不符：期望 0x${PaccEnvelope.MESSAGE_ID.toString(16)}，实际 0x${frame.messageId.toString(16)}`,
      );
    }
    const msg = new PaccEnvelope();
    msg.decode(new PbpDecoder(PbpCodec.payloadOfFrame(frame)));
    msg.signature = frame.signature;
    return msg;
  }

  // ------------------------------------------------------------ 签名

  /** 帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。 */
  getSignatureHex(): string {
    return this.signature.length === 0 ? "" : bytesToHex(this.signature);
  }

  /** 帧尾签名的副本；未签名返回零长数组。 */
  signatureBytes(): Uint8Array {
    return this.signature.slice();
  }

  // ------------------------------------------------------------ PbpMessage

  messageId(): number {
    return PaccEnvelope.MESSAGE_ID;
  }

  encode(enc: PbpEncoder): void {
    enc.writeString(this.type);
    enc.writeInt64(this.tsMs);
    enc.writeString(this.nonce);
    enc.writeString(this.sessionId);
    enc.writeString(this.pteid);
    enc.writeString(this.payloadJson);
    enc.writeUInt8(this.sigVersion);
  }

  /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
  decode(dec: PbpDecoder): void {
    this.type = dec.readString();
    this.tsMs = dec.readInt64();
    this.nonce = dec.readString();
    this.sessionId = dec.readString();
    this.pteid = dec.readString();
    this.payloadJson = dec.readString();
    // 末尾字段自动 optional：旧端的载荷在这里已经读完
    this.sigVersion = dec.remaining() > 0 ? dec.readUInt8() : 0;
  }

  /** 编码后的字节数，仅用于预分配缓冲区。 */
  encodedSize(): number {
    let size = 0;
    size += PbpEncoder.stringSize(this.type);
    size += PbpEncoder.int64Size(this.tsMs);
    size += PbpEncoder.stringSize(this.nonce);
    size += PbpEncoder.stringSize(this.sessionId);
    size += PbpEncoder.stringSize(this.pteid);
    size += PbpEncoder.stringSize(this.payloadJson);
    size += PbpEncoder.uint8Size();
    return size;
  }

}

/**
 * PaccEnvelope 的字段构造器：setter 处理 null 归一化，build() 对可变字段做拷贝。
 */
export class PaccEnvelopeBuilder {
  type: string = "";
  tsMs: bigint = 0n;
  nonce: string = "";
  sessionId: string = "";
  pteid: string = "";
  payloadJson: string = "";
  sigVersion: number = 0;
  signature: Uint8Array = new Uint8Array(0);

  /** MDL 字段 1 type。 */
  setType(value: string | null): this {
    this.type = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 2 ts_ms。 */
  setTsMs(value: bigint): this {
    this.tsMs = value;
    return this;
  }

  /** MDL 字段 3 nonce。 */
  setNonce(value: string | null): this {
    this.nonce = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 4 session_id。 */
  setSessionId(value: string | null): this {
    this.sessionId = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 5 pteid。 */
  setPteid(value: string | null): this {
    this.pteid = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 6 payload_json。 */
  setPayloadJson(value: string | null): this {
    this.payloadJson = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 7 sig_version。 */
  setSigVersion(value: number): this {
    this.sigVersion = value;
    return this;
  }

  /** 帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。 */
  setSignature(hex: string | null): this {
    this.signature = hex === null || hex === "" ? new Uint8Array(0) : bytesFromHex(hex);
    return this;
  }

  /** 帧尾签名的原始字节；null 视为不签名。 */
  setSignatureBytes(value: Uint8Array | null): this {
    this.signature = value === null ? new Uint8Array(0) : value.slice();
    return this;
  }

  build(): PaccEnvelope {
    const msg = new PaccEnvelope();
    msg.type = this.type;
    msg.tsMs = this.tsMs;
    msg.nonce = this.nonce;
    msg.sessionId = this.sessionId;
    msg.pteid = this.pteid;
    msg.payloadJson = this.payloadJson;
    msg.sigVersion = this.sigVersion;
    msg.signature = this.signature.slice();
    return msg;
  }
}
