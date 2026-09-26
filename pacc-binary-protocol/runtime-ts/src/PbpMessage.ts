import type { PbpDecoder } from "./PbpDecoder.js";
import type { PbpEncoder } from "./PbpEncoder.js";

/**
 * 可编码的 PBP 消息。
 *
 * <p>字段按定义顺序写入、按同一顺序读出，编解码双方靠同一份 MDL 约定顺序，
 * 所以编码里没有字段标签。代价是新字段只能加在末尾，且不能改动已有字段的类型。</p>
 *
 * <p>实现类由 tools/pbpgen 从 mdl/*.mdl 生成，不要手写。</p>
 */
export interface PbpMessage {
  /** MDL 里声明的消息 ID；嵌套类型（无 ID）返回 0。 */
  messageId(): number;

  /** 把自身字段按定义顺序写入编码器。 */
  encode(enc: PbpEncoder): void;

  /** 按定义顺序从解码器读回字段。 */
  decode(dec: PbpDecoder): void;

  /** 编码后的字节数，用于预分配缓冲区。 */
  encodedSize(): number;
}