package com.potatotv.pbp;

import java.util.Arrays;

/**
 * PBP 消息帧：固定 30 字节帧头 + 载荷 + 可选 32 字节签名（设计文档 §3.3.1）。
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
 * <p>多字节字段一律小端，唯一例外是开头的 2 字节 Magic：它是 ASCII 标记，按 'P','B' 顺序写
 * （即字节 0x50、0x42），不像数值字段那样小端展开成 0x42、0x50。载荷长度不写进载荷内部，
 * 而是放在帧头，是为了让"新客户端多发了字段、旧服务端不认识"这件事变成可跳过的尾巴，
 * 而不是解析错位。</p>
 *
 * <p>本类只负责布局与长度校验，不碰密码学：签名计算与验证在 {@code PbpCrypto}，
 * 这样帧解析可以在没有密钥的场景（如抓包分析）下单独使用。</p>
 */
public record PbpFrame(int version,
                       int flags,
                       int messageId,
                       int sequence,
                       long timestampMs,
                       long sessionId,
                       byte[] payload,
                       byte[] signature) {

    /** Magic "PB"。 */
    public static final int MAGIC = 0x5042;
    /** 当前协议版本。 */
    public static final int VERSION = 1;
    /**
     * 还能解析的最旧版本。
     *
     * <p>破坏性变更走大版本升级时，过渡期靠 MIN_VERSION 到 {@link #VERSION} 的区间实现
     * "新旧互通"（设计文档 §3.11.3）：解析接受区间内任意版本，编码永远输出当前版本。</p>
     */
    public static final int MIN_VERSION = 1;

    public static final int HEADER_SIZE = 30;
    public static final int SIGNATURE_SIZE = 32;

    public static final int FLAG_ENCRYPTED = 0x01;
    public static final int FLAG_COMPRESSED = 0x02;
    public static final int FLAG_DELTA = 0x04;
    public static final int FLAG_SIGNED = 0x08;

    /** 已知标志位掩码；其余位为保留位，置位即视为协议不认识。 */
    private static final int KNOWN_FLAGS = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_DELTA | FLAG_SIGNED;

    /**
     * 载荷长度硬上限。
     *
     * <p>帧头里的 PayloadLen 是 uint32，字面上允许 4GB，但真按它分配就等于把内存交给对端控制。
     * 当前协议里最大的消息也只有几百 KB，留 16MB 已经宽裕。</p>
     */
    public static final int MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

    private static final int OFF_MAGIC = 0;
    private static final int OFF_VERSION = 2;
    private static final int OFF_FLAGS = 3;
    private static final int OFF_MESSAGE_ID = 4;
    private static final int OFF_SEQUENCE = 6;
    private static final int OFF_TIMESTAMP = 10;
    private static final int OFF_SESSION_ID = 18;
    private static final int OFF_PAYLOAD_LEN = 26;

    public PbpFrame {
        payload = payload == null ? new byte[0] : payload.clone();
        signature = signature == null ? new byte[0] : signature.clone();
    }

    /** 构造一条无签名帧（sessionId 与 sequence 默认 0，由需要它们的上层显式覆盖）。 */
    public static PbpFrame of(int messageId, long timestampMs, byte[] payload) {
        return new PbpFrame(VERSION, 0, messageId, 0, timestampMs, 0, payload, null);
    }

    public boolean signed() {
        return (flags & FLAG_SIGNED) != 0;
    }

    /** 载荷是否已压缩（设计文档 §3.10.1，压缩由 {@link PbpCodec} 完成）。 */
    public boolean compressed() {
        return (flags & FLAG_COMPRESSED) != 0;
    }

    /** 载荷是否为差分编码（设计文档 §3.10.2，基线由 {@link PbpDeltaChain} 维护）。 */
    public boolean delta() {
        return (flags & FLAG_DELTA) != 0;
    }

    /** 返回置位指定标志的副本；只允许置已知标志位。 */
    public PbpFrame withFlag(int flag) {
        if (flag == 0) {
            return this;
        }
        if ((flag & ~KNOWN_FLAGS) != 0 || flag == FLAG_ENCRYPTED) {
            throw new PbpException(PbpException.Code.UNSUPPORTED_FLAG,
                    "不能置位未实现的标志: 0x" + Integer.toHexString(flag));
        }
        return new PbpFrame(version, flags | flag, messageId, sequence,
                timestampMs, sessionId, payload, signature);
    }

    /** 载荷长度，等于 {@code payload().length}。 */
    public int payloadLength() {
        return payload.length;
    }

    /**
     * 返回带签名的副本：置位 {@code FLAG_SIGNED} 并写入 32 字节签名。
     *
     * <p>签名覆盖 {@link #signingInput()}，其中帧头是按 {@code FLAG_SIGNED} 已置位的形态计算的，
     * 因此签名方与验签方拿到的是同一串字节，不存在"先签后置标志位导致两边不一致"的坑。</p>
     */
    public PbpFrame withSignature(byte[] sig) {
        if (sig == null || sig.length != SIGNATURE_SIZE) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "签名必须是 " + SIGNATURE_SIZE + " 字节，实际 " + (sig == null ? "null" : sig.length));
        }
        return new PbpFrame(version, flags | FLAG_SIGNED, messageId, sequence,
                timestampMs, sessionId, payload, sig);
    }

    /**
     * HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。
     *
     * <p>签名必须覆盖帧头而不是只盖载荷，否则 messageId / timestamp / sessionId 都能被
     * 中间人改写而验签照样通过。</p>
     */
    public byte[] signingInput() {
        int payloadLen = payload.length;
        byte[] out = new byte[HEADER_SIZE + payloadLen];
        putHeader(out, flags | FLAG_SIGNED, payloadLen);
        System.arraycopy(payload, 0, out, HEADER_SIZE, payloadLen);
        return out;
    }

    /** 序列化为完整帧字节；签名是否存在由 {@code FLAG_SIGNED} 决定。 */
    public byte[] encode() {
        validateFlags(flags);
        if (version != VERSION) {
            throw new PbpException(PbpException.Code.BAD_VERSION, "本运行时只支持版本 " + VERSION + "，不能编码版本 " + version);
        }
        int payloadLen = payload.length;
        if (payloadLen > MAX_PAYLOAD_SIZE) {
            throw new PbpException(PbpException.Code.BAD_LENGTH, "载荷长度超上限: " + payloadLen);
        }
        boolean isSigned = signed();
        if (isSigned && signature.length != SIGNATURE_SIZE) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "帧头声明已签名，但签名长度为 " + signature.length);
        }
        if (!isSigned && signature.length != 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "带了签名字节但 FLAG_SIGNED 未置位");
        }

        byte[] out = new byte[HEADER_SIZE + payloadLen + (isSigned ? SIGNATURE_SIZE : 0)];
        putHeader(out, flags, payloadLen);
        System.arraycopy(payload, 0, out, HEADER_SIZE, payloadLen);
        if (isSigned) {
            System.arraycopy(signature, 0, out, HEADER_SIZE + payloadLen, SIGNATURE_SIZE);
        }
        return out;
    }

    /** 解析完整帧；任何长度或标志位不符都抛 {@link PbpException}。 */
    public static PbpFrame parse(byte[] raw) {
        if (raw == null || raw.length < HEADER_SIZE) {
            throw new PbpException(PbpException.Code.TRUNCATED,
                    "帧长度不足 " + HEADER_SIZE + " 字节: " + (raw == null ? "null" : raw.length));
        }
        int magic = ((raw[OFF_MAGIC] & 0xFF) << 8) | (raw[OFF_MAGIC + 1] & 0xFF);
        if (magic != MAGIC) {
            throw new PbpException(PbpException.Code.BAD_MAGIC, "Magic 不是 \"PB\": 0x" + Integer.toHexString(magic));
        }
        int version = raw[OFF_VERSION] & 0xFF;
        if (version < MIN_VERSION) {
            throw new PbpException(PbpException.Code.BAD_VERSION,
                    "协议版本过旧: " + version + "（最低支持 " + MIN_VERSION + "）");
        }
        if (version > VERSION) {
            throw new PbpException(PbpException.Code.BAD_VERSION,
                    "协议版本过新: " + version + "（本运行时最高支持 " + VERSION + "）");
        }
        int flags = raw[OFF_FLAGS] & 0xFF;
        validateFlags(flags);

        long payloadLen = getUInt32(raw, OFF_PAYLOAD_LEN);
        if (payloadLen > MAX_PAYLOAD_SIZE) {
            throw new PbpException(PbpException.Code.BAD_LENGTH, "载荷长度超上限: " + payloadLen);
        }
        int expected = HEADER_SIZE + (int) payloadLen + ((flags & FLAG_SIGNED) != 0 ? SIGNATURE_SIZE : 0);
        if (raw.length != expected) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "帧长与 PayloadLen 不符: 实际 " + raw.length + "，按声明应为 " + expected);
        }

        byte[] payload = Arrays.copyOfRange(raw, HEADER_SIZE, HEADER_SIZE + (int) payloadLen);
        byte[] signature = (flags & FLAG_SIGNED) != 0
                ? Arrays.copyOfRange(raw, HEADER_SIZE + (int) payloadLen, expected)
                : new byte[0];
        return new PbpFrame(version, flags, getUInt16(raw, OFF_MESSAGE_ID), getUInt32AsInt(raw, OFF_SEQUENCE),
                getInt64(raw, OFF_TIMESTAMP), getInt64(raw, OFF_SESSION_ID), payload, signature);
    }

    /**
     * 拒绝尚未实现的标志位。
     *
     * <p>压缩与差分位已经落地（{@link PbpCodec} 负责压缩、{@link PbpDeltaChain} 负责差分），
     * 帧层只校验位的合法性，不解释载荷：载荷是不是真的压缩过、差分基线是哪条，由会话语境决定。</p>
     *
     * <p>加密位仍然是"未实现"：载荷加密目前不在帧层（会话密钥在更高层用），
     * 这个位一旦被置位就显式失败——把"对端以为已经加密"的载荷当明文解析是最危险的失败方式。</p>
     */
    private static void validateFlags(int flags) {
        if ((flags & FLAG_ENCRYPTED) != 0) {
            throw new PbpException(PbpException.Code.UNSUPPORTED_FLAG,
                    "当前版本未实现加密标志位 0x" + Integer.toHexString(FLAG_ENCRYPTED));
        }
        int unknown = flags & ~KNOWN_FLAGS;
        if (unknown != 0) {
            throw new PbpException(PbpException.Code.UNSUPPORTED_FLAG,
                    "保留标志位被置位: 0x" + Integer.toHexString(unknown));
        }
    }

    private void putHeader(byte[] out, int flags, int payloadLen) {
        // Magic 是 ASCII 标记，按可读顺序写 'P','B'；帧头其余多字节字段才是小端。
        out[OFF_MAGIC] = (byte) (MAGIC >>> 8);
        out[OFF_MAGIC + 1] = (byte) MAGIC;
        out[OFF_VERSION] = (byte) version;
        out[OFF_FLAGS] = (byte) flags;
        putUInt16(out, OFF_MESSAGE_ID, messageId);
        putUInt32(out, OFF_SEQUENCE, sequence);
        putInt64(out, OFF_TIMESTAMP, timestampMs);
        putInt64(out, OFF_SESSION_ID, sessionId);
        putUInt32(out, OFF_PAYLOAD_LEN, payloadLen);
    }

    // ------------------------------------------------------------ 小端读写

    private static void putUInt16(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
    }

    private static void putUInt32(byte[] b, int off, int v) {
        for (int i = 0; i < 4; i++) {
            b[off + i] = (byte) (v >>> (i * 8));
        }
    }

    private static void putInt64(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (i * 8));
        }
    }

    private static int getUInt16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long getUInt32(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 4; i++) {
            v |= (long) (b[off + i] & 0xFF) << (i * 8);
        }
        return v;
    }

    private static int getUInt32AsInt(byte[] b, int off) {
        return (int) getUInt32(b, off);
    }

    private static long getInt64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (b[off + i] & 0xFF) << (i * 8);
        }
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        return o instanceof PbpFrame other
                && version == other.version
                && flags == other.flags
                && messageId == other.messageId
                && sequence == other.sequence
                && timestampMs == other.timestampMs
                && sessionId == other.sessionId
                && Arrays.equals(payload, other.payload)
                && Arrays.equals(signature, other.signature);
    }

    @Override
    public int hashCode() {
        int result = Integer.hashCode(version);
        result = 31 * result + Integer.hashCode(flags);
        result = 31 * result + Integer.hashCode(messageId);
        result = 31 * result + Integer.hashCode(sequence);
        result = 31 * result + Long.hashCode(timestampMs);
        result = 31 * result + Long.hashCode(sessionId);
        result = 31 * result + Arrays.hashCode(payload);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "PbpFrame[version=" + version + ", flags=0x" + Integer.toHexString(flags)
                + ", messageId=0x" + Integer.toHexString(messageId) + ", sequence=" + Integer.toUnsignedString(sequence)
                + ", timestampMs=" + timestampMs + ", sessionId=" + Long.toUnsignedString(sessionId)
                + ", payload=" + payload.length + " bytes, signature=" + signature.length + " bytes]";
    }
}