// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

import type { PbpMessage } from "../PbpMessage.js";
import { PbpDecoder } from "../PbpDecoder.js";
import { PbpEncoder } from "../PbpEncoder.js";

/**
 * PBP 消息 DetectionEvent，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
 *
 * 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。
 */
export class DetectionEvent implements PbpMessage {
  /** 可空字段个数，用于定位载荷里的存在性位图。 */
  static readonly OPTIONAL_FIELD_COUNT = 1;

  // ------------------------------------------------------------ 字段

  eventType: number = 0;
  confidence: number = 0;
  timestamp: bigint = 0n;
  evidence: Map<string, Uint8Array> = new Map();
  detail: string | null = null;

  /** 建一个空构造器；可空性由 MDL 决定：String 与 byte[] 默认空值、消息类型字段默认 null。 */
  static newBuilder(): DetectionEventBuilder {
    return new DetectionEventBuilder();
  }

  /** 以当前值为初值开一个新构造器（例如改完字段要重新签名）。 */
  toBuilder(): DetectionEventBuilder {
    const builder = new DetectionEventBuilder();
    builder.eventType = this.eventType;
    builder.confidence = this.confidence;
    builder.timestamp = this.timestamp;
    builder.evidence = new Map(this.evidence);
    builder.detail = this.detail;
    return builder;
  }

  // ------------------------------------------------------------ PbpMessage

  messageId(): number {
    return 0;
  }

  encode(enc: PbpEncoder): void {
    enc.writeInt32(this.eventType);
    enc.writeFloat32(this.confidence);
    enc.writeInt64(this.timestamp);
    enc.writeStringMap(this.evidence, (e, v) => e.writeBytes(v));
    enc.writeOptionalString(this.detail);
  }

  /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
  decode(dec: PbpDecoder): void {
    this.eventType = dec.readInt32();
    this.confidence = dec.readFloat32();
    this.timestamp = dec.readInt64();
    this.evidence = dec.readStringMap((d) => d.readBytes());
    this.detail = dec.readOptionalString();
  }

  /** 编码后的字节数，仅用于预分配缓冲区。 */
  encodedSize(): number {
    let size = 0;
    size += PbpEncoder.int32Size(this.eventType);
    size += PbpEncoder.float32Size();
    size += PbpEncoder.int64Size(this.timestamp);
    size += PbpEncoder.stringMapSize(this.evidence, PbpEncoder.bytesSize);
    size += PbpEncoder.optionalStringSize(this.detail);
    return size;
  }

}

/**
 * DetectionEvent 的字段构造器：setter 处理 null 归一化，build() 对可变字段做拷贝。
 */
export class DetectionEventBuilder {
  eventType: number = 0;
  confidence: number = 0;
  timestamp: bigint = 0n;
  evidence: Map<string, Uint8Array> = new Map();
  detail: string | null = null;

  /** MDL 字段 1 event_type。 */
  setEventType(value: number): this {
    this.eventType = value;
    return this;
  }

  /** MDL 字段 2 confidence。 */
  setConfidence(value: number): this {
    this.confidence = value;
    return this;
  }

  /** MDL 字段 3 timestamp。 */
  setTimestamp(value: bigint): this {
    this.timestamp = value;
    return this;
  }

  /** MDL 字段 4 evidence。 */
  setEvidence(value: Map<string, Uint8Array> | null): this {
    this.evidence = value === null ? new Map() : new Map(value);
    return this;
  }

  /** 写入一个 evidence 键值对。 */
  putEvidence(key: string, value: Uint8Array): this {
    this.evidence.set(key, value);
    return this;
  }

  /** MDL 字段 5 detail。 */
  setDetail(value: string | null): this {
    this.detail = value;
    return this;
  }

  build(): DetectionEvent {
    const msg = new DetectionEvent();
    msg.eventType = this.eventType;
    msg.confidence = this.confidence;
    msg.timestamp = this.timestamp;
    msg.evidence = new Map(this.evidence);
    msg.detail = this.detail;
    return msg;
  }
}
