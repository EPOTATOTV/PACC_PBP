/**
 * PBP 编解码与帧解析异常。
 *
 * <p>带 code 是为了让调用方能区分「对端说了听不懂的话」和「对端在攻击我」：
 * magic/version 不符多半是协议不匹配或旧版本残留，tag 不匹配与长度不符则是明确的篡改信号。
 * 调用方按 code 决定是记计数日志还是告警，而不是一律打堆栈。</p>
 */
export type PbpErrorCode =
  | "BAD_MAGIC"
  | "BAD_VERSION"
  | "UNSUPPORTED_FLAG"
  | "UNSUPPORTED"
  | "BAD_LENGTH"
  | "TAG_MISMATCH"
  | "TRUNCATED"
  | "BAD_VARINT"
  | "BAD_FORMAT";

export class PbpException extends Error {
  readonly code: PbpErrorCode;

  constructor(code: PbpErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "PbpException";
    this.code = code;
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}