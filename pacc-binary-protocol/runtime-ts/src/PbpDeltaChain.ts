import { PbpCodec } from "./PbpCodec.js";
import { PbpDelta } from "./PbpDelta.js";
import type { PbpDeltaMessage } from "./PbpDeltaMessage.js";
import { PbpDecoder } from "./PbpDecoder.js";
import { PbpEncoder } from "./PbpEncoder.js";
import { PbpException } from "./PbpException.js";
import { PbpFrame } from "./PbpFrame.js";
import type { PbpMessage } from "./PbpMessage.js";

/**
 * 一条消息 ID 上的差分链：发送侧决定「发完整还是发差分」，接收侧按标志位回放。
 *
 * <p>两条硬规则：最多连续 MAX_CONSECUTIVE 条差分后必须发一条完整消息；差分以「上一轮同 ID
 * 的消息」为基线，双方各自维护。</p>
 *
 * <p>每条消息一条链实例，按「一条连接一个方向」使用：里面存着基线与计数，非线程安全。</p>
 */
export class PbpDeltaChain<T extends PbpMessage & PbpDeltaMessage<T>> {
  /** 连续差分上限。 */
  static readonly MAX_CONSECUTIVE = 10;

  private previous: T | null = null;
  private consecutiveCount = 0;

  constructor(
    private readonly messageId: number,
    private readonly factory: () => T,
  ) {}

  /** 已连续发出的 / 收到的差分条数。 */
  consecutive(): number {
    return this.consecutiveCount;
  }

  /** 丢弃基线，下一条必定发完整消息（重连、丢帧后的复位点）。 */
  reset(): void {
    this.previous = null;
    this.consecutiveCount = 0;
  }

  /**
   * 发送侧：按规则选择完整或差分，并把当前消息深拷贝为新基线。
   *
   * <p>差分时置 FLAG_DELTA，压得动时置 FLAG_COMPRESSED。</p>
   */
  encode(current: T, timestampMs: bigint): PbpFrame {
    if (current === null) {
      throw new PbpException("BAD_FORMAT", "差分链消息为 null");
    }
    const previous = this.previous;
    const useDelta = previous !== null && this.consecutiveCount < PbpDeltaChain.MAX_CONSECUTIVE;
    let payload: Uint8Array;
    if (useDelta) {
      const encoder = new PbpEncoder(Math.max(64, Math.floor(current.encodedSize() / 2) + 8));
      current.encodeDelta(encoder, previous);
      payload = encoder.toByteArray();
    } else {
      payload = PbpCodec.payloadOf(current);
    }
    const packed = PbpCodec.maybeCompress(payload);
    let frame = PbpFrame.of(this.messageId, timestampMs, packed);
    if (useDelta) {
      frame = frame.withFlag(PbpFrame.FLAG_DELTA);
    }
    if (packed !== payload) {
      frame = frame.withFlag(PbpFrame.FLAG_COMPRESSED);
    }
    this.previous = PbpDelta.copy(current, this.factory);
    this.consecutiveCount = useDelta ? this.consecutiveCount + 1 : 0;
    return frame;
  }

  /**
   * 接收侧：完整消息直接解码，差分消息在基线上回放。
   *
   * <p>没有基线时收到差分、或连续差分超过上限，都按协议错误拒绝。</p>
   */
  decode(frameBytes: Uint8Array): T {
    const frame = PbpFrame.parse(frameBytes);
    if (frame.messageId !== this.messageId) {
      throw new PbpException(
        "BAD_FORMAT",
        `差分链消息 ID 不符：期望 0x${this.messageId.toString(16)}，实际 0x${frame.messageId.toString(16)}`,
      );
    }
    const previous = this.previous;
    const message = this.factory();
    if (frame.delta()) {
      if (previous === null) {
        throw new PbpException("BAD_FORMAT", "收到差分帧，但没有可用基线");
      }
      if (this.consecutiveCount >= PbpDeltaChain.MAX_CONSECUTIVE) {
        throw new PbpException(
          "BAD_FORMAT",
          `连续差分超过 ${PbpDeltaChain.MAX_CONSECUTIVE} 条，发送方应先发完整消息`,
        );
      }
      message.applyDelta(new PbpDecoder(PbpCodec.payloadOfFrame(frame)), previous);
    } else {
      message.decode(new PbpDecoder(PbpCodec.payloadOfFrame(frame)));
    }
    this.previous = PbpDelta.copy(message, this.factory);
    this.consecutiveCount = frame.delta() ? this.consecutiveCount + 1 : 0;
    return message;
  }
}