import { PbpEncoder } from "./PbpEncoder.js";
import { PbpException } from "./PbpException.js";
import { PbpFrame } from "./PbpFrame.js";
import type { PbpMessage } from "./PbpMessage.js";
import { compress as zstdCompress, decompress as zstdDecompress } from "./PbpZstd.js";

/**
 * 载荷 ↔ 帧的组装层。
 *
 * <p>把「消息编码 → 压缩策略 → 帧装配」和「帧解析 → 解压」这两条固定链路收敛到一处，
 * 生成代码的 toByteArray/parseFrom/signingInput 都走它。压缩决策是载荷的确定性函数：
 * 任何一端拿字段重新编码一遍都能得到同一串待签字节。</p>
 *
 * <p>策略照设计文档 §3.10.1：载荷超过 COMPRESS_THRESHOLD 才尝试压缩，压完比原文小才启用。</p>
 */
export class PbpCodec {
  /** 触发压缩尝试的载荷长度。 */
  static readonly COMPRESS_THRESHOLD = 1024;

  private constructor() {}

  /** 编码消息载荷（不含帧头）。 */
  static payloadOf(message: PbpMessage): Uint8Array {
    if (message === null || message === undefined) {
      throw new PbpException("BAD_FORMAT", "消息为 null，无法编码");
    }
    const encoder = new PbpEncoder(Math.max(64, message.encodedSize()));
    message.encode(encoder);
    return encoder.toByteArray();
  }

  /** 按策略尝试压缩；不值得压缩时原样返回入参（调用方用引用相等判断是否启用）。 */
  static maybeCompress(payload: Uint8Array): Uint8Array {
    if (payload === null) {
      throw new PbpException("BAD_FORMAT", "载荷为 null，无法压缩");
    }
    if (payload.length <= PbpCodec.COMPRESS_THRESHOLD) {
      return payload;
    }
    const packed = zstdCompress(payload);
    return packed.length < payload.length ? packed : payload;
  }

  /** 组装整帧：需要压缩时置 FLAG_COMPRESSED。 */
  static frameOf(message: PbpMessage, timestampMs: bigint): PbpFrame {
    const payload = PbpCodec.payloadOf(message);
    const packed = PbpCodec.maybeCompress(payload);
    const frame = PbpFrame.of(message.messageId(), timestampMs, packed);
    return packed === payload ? frame : frame.withFlag(PbpFrame.FLAG_COMPRESSED);
  }

  /** 取出帧载荷：声明压缩就解压（上限取载荷长度上限，兼作解压炸弹拦截点）。 */
  static payloadOfFrame(frame: PbpFrame): Uint8Array {
    if (frame === null) {
      throw new PbpException("BAD_FORMAT", "帧为 null，无法取载荷");
    }
    if (!frame.compressed()) {
      return frame.payload;
    }
    return zstdDecompress(frame.payload, PbpFrame.MAX_PAYLOAD_SIZE);
  }
}