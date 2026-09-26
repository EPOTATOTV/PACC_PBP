package com.potatotv.pbp;

/**
 * PBP 编解码与帧解析异常。
 *
 * <p>带 {@link Code} 是为了让调用方能区分「对端说了听不懂的话」和「对端在攻击我」：
 * magic/version 不符多半是协议不匹配或旧版本残留，tag 不匹配与长度不符则是明确的篡改信号。
 * 调用方按 code 决定是记计数日志还是告警，而不是一律打堆栈。</p>
 */
public final class PbpException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** 失败原因分类。 */
    public enum Code {
        /** 帧头 magic 不是 "PB"。 */
        BAD_MAGIC,
        /** 协议版本不认识。 */
        BAD_VERSION,
        /** 标志位要求了当前版本尚未实现的能力。 */
        UNSUPPORTED_FLAG,
        /** 数据本身合法，但用到了当前实现在该格式上明确的子集之外的能力（如 zstd 的 Huffman literals）。 */
        UNSUPPORTED,
        /** 声明长度与实际字节数不符。 */
        BAD_LENGTH,
        /** 签名校验不通过。 */
        TAG_MISMATCH,
        /** 数据在读完之前就结束了。 */
        TRUNCATED,
        /** VarInt 超过 10 字节或编码非法。 */
        BAD_VARINT,
        /** 字段内容不符合定义（如 UTF-8 非法、集合长度超限）。 */
        BAD_FORMAT
    }

    private final Code code;

    public PbpException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public PbpException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}