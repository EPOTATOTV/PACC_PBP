// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

import type { PbpDeltaMessage } from "../PbpDeltaMessage.js";
import type { PbpMessage } from "../PbpMessage.js";
import { ApmSnapshot } from "./ApmSnapshot.js";
import { DetectionEvent } from "./DetectionEvent.js";
import { PbpCodec } from "../PbpCodec.js";
import { PbpDecoder } from "../PbpDecoder.js";
import { PbpDelta } from "../PbpDelta.js";
import { PbpEncoder } from "../PbpEncoder.js";
import { PbpException } from "../PbpException.js";
import { PbpFrame } from "../PbpFrame.js";

/**
 * PBP 消息 DetectionReport（0x0103，0x0100-0x0FFF 客户端 → 服务端）。
 *
 * 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。
 *
 * 实现了 PbpDeltaMessage：可经 PbpDeltaChain 发差分帧（设计文档 §3.10.2）。
 */
export class DetectionReport implements PbpMessage, PbpDeltaMessage<DetectionReport> {
  /** MDL 里声明的消息 ID。 */
  static readonly MESSAGE_ID = 0x0103;

  /** 可空字段个数，用于定位载荷里的存在性位图。 */
  static readonly OPTIONAL_FIELD_COUNT = 1;

  // ------------------------------------------------------------ 字段

  pteid: string = "";
  timestamp: bigint = 0n;
  clientVersion: string = "";
  platform: string = "";
  events: DetectionEvent[] = [];
  apm: ApmSnapshot | null = null;
  signature: Uint8Array = new Uint8Array(0);

  /** 建一个空构造器；可空性由 MDL 决定：String 与 byte[] 默认空值、消息类型字段默认 null。 */
  static newBuilder(): DetectionReportBuilder {
    return new DetectionReportBuilder();
  }

  /** 以当前值为初值开一个新构造器（例如改完字段要重新签名）。 */
  toBuilder(): DetectionReportBuilder {
    const builder = new DetectionReportBuilder();
    builder.pteid = this.pteid;
    builder.timestamp = this.timestamp;
    builder.clientVersion = this.clientVersion;
    builder.platform = this.platform;
    builder.events = this.events.slice();
    builder.apm = this.apm;
    builder.signature = this.signature.slice();
    return builder;
  }

  // ------------------------------------------------------------ 帧

  /** 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。 */
  toByteArray(): Uint8Array {
    const frame = PbpCodec.frameOf(this, 0n);
    return frame.encode();
  }

  /** 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。置位 FLAG_COMPRESSED 的帧先解压再解码载荷。 */
  static parseFrom(raw: Uint8Array): DetectionReport {
    const frame = PbpFrame.parse(raw);
    if (frame.messageId !== DetectionReport.MESSAGE_ID) {
      throw new PbpException(
        "BAD_FORMAT",
        `消息 ID 不符：期望 0x${DetectionReport.MESSAGE_ID.toString(16)}，实际 0x${frame.messageId.toString(16)}`,
      );
    }
    const msg = new DetectionReport();
    msg.decode(new PbpDecoder(PbpCodec.payloadOfFrame(frame)));
    return msg;
  }

  // ------------------------------------------------------------ PbpMessage

  messageId(): number {
    return DetectionReport.MESSAGE_ID;
  }

  encode(enc: PbpEncoder): void {
    enc.writeString(this.pteid);
    enc.writeInt64(this.timestamp);
    enc.writeString(this.clientVersion);
    enc.writeString(this.platform);
    enc.writeMessageList(this.events);
    enc.writeOptionalMessage(this.apm);
    enc.writeBytes(this.signature);
  }

  /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
  decode(dec: PbpDecoder): void {
    this.pteid = dec.readString();
    this.timestamp = dec.readInt64();
    this.clientVersion = dec.readString();
    this.platform = dec.readString();
    this.events = dec.readMessageList(() => new DetectionEvent());
    this.apm = dec.readOptionalMessage(() => new ApmSnapshot());
    // 末尾字段自动 optional：旧端的载荷在这里已经读完
    this.signature = dec.remaining() > 0 ? dec.readBytes() : new Uint8Array(0);
  }

  /** 编码后的字节数，仅用于预分配缓冲区。 */
  encodedSize(): number {
    let size = 0;
    size += PbpEncoder.stringSize(this.pteid);
    size += PbpEncoder.int64Size(this.timestamp);
    size += PbpEncoder.stringSize(this.clientVersion);
    size += PbpEncoder.stringSize(this.platform);
    size += PbpEncoder.messageListSize(this.events);
    size += PbpEncoder.optionalMessageSize(this.apm);
    size += PbpEncoder.bytesSize(this.signature);
    return size;
  }

  // ------------------------------------------------------------ 差分（设计文档 §3.10.2）

  /** 相对基线只写变化的字段：存在位图 + 按字段序的变化值。 */
  encodeDelta(enc: PbpEncoder, previous: DetectionReport): void {
    const changed = [
      this.pteid !== previous.pteid,
      this.timestamp !== previous.timestamp,
      this.clientVersion !== previous.clientVersion,
      this.platform !== previous.platform,
      PbpDelta.differs((x) => x.writeMessageList(this.events), (x) => x.writeMessageList(previous.events)),
      PbpDelta.differs((x) => x.writeOptionalMessage(this.apm), (x) => x.writeOptionalMessage(previous.apm)),
      !PbpDelta.bytesEqual(this.signature, previous.signature),
    ];
    enc.writePresence(changed);
    if (changed[0]) {
      enc.writeString(this.pteid);
    }
    if (changed[1]) {
      enc.writeInt64(this.timestamp);
    }
    if (changed[2]) {
      enc.writeString(this.clientVersion);
    }
    if (changed[3]) {
      enc.writeString(this.platform);
    }
    if (changed[4]) {
      enc.writeMessageList(this.events);
    }
    if (changed[5]) {
      enc.writeOptionalMessage(this.apm);
    }
    if (changed[6]) {
      enc.writeBytes(this.signature);
    }
  }

  /** 未变化的字段从基线拷贝（消息与字节数组深拷贝、集合按元素复制），变化的字段按位图读入；传入的基线对象不会被改动。 */
  applyDelta(dec: PbpDecoder, previous: DetectionReport): void {
    const present = dec.readPresence(7);
    this.pteid = present[0] ? dec.readString() : previous.pteid;
    this.timestamp = present[1] ? dec.readInt64() : previous.timestamp;
    this.clientVersion = present[2] ? dec.readString() : previous.clientVersion;
    this.platform = present[3] ? dec.readString() : previous.platform;
    this.events = present[4] ? dec.readMessageList(() => new DetectionEvent()) : PbpDelta.copyList(previous.events, () => new DetectionEvent());
    this.apm = present[5] ? dec.readOptionalMessage(() => new ApmSnapshot()) : PbpDelta.copy(previous.apm, () => new ApmSnapshot());
    this.signature = present[6] ? dec.readBytes() : previous.signature.slice();
  }

}

/**
 * DetectionReport 的字段构造器：setter 处理 null 归一化，build() 对可变字段做拷贝。
 */
export class DetectionReportBuilder {
  pteid: string = "";
  timestamp: bigint = 0n;
  clientVersion: string = "";
  platform: string = "";
  events: DetectionEvent[] = [];
  apm: ApmSnapshot | null = null;
  signature: Uint8Array = new Uint8Array(0);

  /** MDL 字段 1 pteid。 */
  setPteid(value: string | null): this {
    this.pteid = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 2 timestamp。 */
  setTimestamp(value: bigint): this {
    this.timestamp = value;
    return this;
  }

  /** MDL 字段 3 client_version。 */
  setClientVersion(value: string | null): this {
    this.clientVersion = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 4 platform。 */
  setPlatform(value: string | null): this {
    this.platform = value === null ? "" : value;
    return this;
  }

  /** MDL 字段 5 events。 */
  setEvents(value: DetectionEvent[] | null): this {
    this.events = value === null ? [] : value.slice();
    return this;
  }

  /** 追加一个 events 元素。 */
  addEvents(value: DetectionEvent): this {
    this.events.push(value);
    return this;
  }

  /** MDL 字段 6 apm。 */
  setApm(value: ApmSnapshot | null): this {
    this.apm = value;
    return this;
  }

  /** MDL 字段 7 signature。 */
  setSignature(value: Uint8Array | null): this {
    this.signature = value === null ? new Uint8Array(0) : value.slice();
    return this;
  }

  build(): DetectionReport {
    const msg = new DetectionReport();
    msg.pteid = this.pteid;
    msg.timestamp = this.timestamp;
    msg.clientVersion = this.clientVersion;
    msg.platform = this.platform;
    msg.events = this.events.slice();
    msg.apm = this.apm;
    msg.signature = this.signature.slice();
    return msg;
  }
}
