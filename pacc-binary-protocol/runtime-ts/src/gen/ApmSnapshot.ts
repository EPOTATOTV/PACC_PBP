// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

import type { PbpMessage } from "../PbpMessage.js";
import { PbpDecoder } from "../PbpDecoder.js";
import { PbpEncoder } from "../PbpEncoder.js";

/**
 * PBP 消息 ApmSnapshot，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
 *
 * 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。
 */
export class ApmSnapshot implements PbpMessage {
  // ------------------------------------------------------------ 字段

  cpuUsage: number = 0;
  memoryUsageKb: number = 0;
  fps: number = 0;
  detectionLatencyMs: number = 0;
  activeRules: number = 0;
  customMetrics: Map<string, number> = new Map();

  /** 建一个空构造器；可空性由 MDL 决定：String 与 byte[] 默认空值、消息类型字段默认 null。 */
  static newBuilder(): ApmSnapshotBuilder {
    return new ApmSnapshotBuilder();
  }

  /** 以当前值为初值开一个新构造器（例如改完字段要重新签名）。 */
  toBuilder(): ApmSnapshotBuilder {
    const builder = new ApmSnapshotBuilder();
    builder.cpuUsage = this.cpuUsage;
    builder.memoryUsageKb = this.memoryUsageKb;
    builder.fps = this.fps;
    builder.detectionLatencyMs = this.detectionLatencyMs;
    builder.activeRules = this.activeRules;
    builder.customMetrics = new Map(this.customMetrics);
    return builder;
  }

  // ------------------------------------------------------------ PbpMessage

  messageId(): number {
    return 0;
  }

  encode(enc: PbpEncoder): void {
    enc.writeFloat32(this.cpuUsage);
    enc.writeInt32(this.memoryUsageKb);
    enc.writeFloat32(this.fps);
    enc.writeInt32(this.detectionLatencyMs);
    enc.writeInt32(this.activeRules);
    enc.writeStringMap(this.customMetrics, (e, v) => e.writeFloat32(v));
  }

  /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
  decode(dec: PbpDecoder): void {
    this.cpuUsage = dec.readFloat32();
    this.memoryUsageKb = dec.readInt32();
    this.fps = dec.readFloat32();
    this.detectionLatencyMs = dec.readInt32();
    this.activeRules = dec.readInt32();
    this.customMetrics = dec.readStringMap((d) => d.readFloat32());
  }

  /** 编码后的字节数，仅用于预分配缓冲区。 */
  encodedSize(): number {
    let size = 0;
    size += PbpEncoder.float32Size();
    size += PbpEncoder.int32Size(this.memoryUsageKb);
    size += PbpEncoder.float32Size();
    size += PbpEncoder.int32Size(this.detectionLatencyMs);
    size += PbpEncoder.int32Size(this.activeRules);
    size += PbpEncoder.stringMapSize(this.customMetrics, () => PbpEncoder.float32Size());
    return size;
  }

}

/**
 * ApmSnapshot 的字段构造器：setter 处理 null 归一化，build() 对可变字段做拷贝。
 */
export class ApmSnapshotBuilder {
  cpuUsage: number = 0;
  memoryUsageKb: number = 0;
  fps: number = 0;
  detectionLatencyMs: number = 0;
  activeRules: number = 0;
  customMetrics: Map<string, number> = new Map();

  /** MDL 字段 1 cpu_usage。 */
  setCpuUsage(value: number): this {
    this.cpuUsage = value;
    return this;
  }

  /** MDL 字段 2 memory_usage_kb。 */
  setMemoryUsageKb(value: number): this {
    this.memoryUsageKb = value;
    return this;
  }

  /** MDL 字段 3 fps。 */
  setFps(value: number): this {
    this.fps = value;
    return this;
  }

  /** MDL 字段 4 detection_latency_ms。 */
  setDetectionLatencyMs(value: number): this {
    this.detectionLatencyMs = value;
    return this;
  }

  /** MDL 字段 5 active_rules。 */
  setActiveRules(value: number): this {
    this.activeRules = value;
    return this;
  }

  /** MDL 字段 6 custom_metrics。 */
  setCustomMetrics(value: Map<string, number> | null): this {
    this.customMetrics = value === null ? new Map() : new Map(value);
    return this;
  }

  /** 写入一个 custom_metrics 键值对。 */
  putCustomMetrics(key: string, value: number): this {
    this.customMetrics.set(key, value);
    return this;
  }

  build(): ApmSnapshot {
    const msg = new ApmSnapshot();
    msg.cpuUsage = this.cpuUsage;
    msg.memoryUsageKb = this.memoryUsageKb;
    msg.fps = this.fps;
    msg.detectionLatencyMs = this.detectionLatencyMs;
    msg.activeRules = this.activeRules;
    msg.customMetrics = new Map(this.customMetrics);
    return msg;
  }
}
