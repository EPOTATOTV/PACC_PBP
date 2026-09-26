// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

package com.potatotv.pbp.gen;

import com.potatotv.pbp.PbpDecoder;
import com.potatotv.pbp.PbpEncoder;
import com.potatotv.pbp.PbpCodec;
import com.potatotv.pbp.PbpException;
import com.potatotv.pbp.PbpFrame;
import com.potatotv.pbp.PbpMessage;

import java.util.HexFormat;

/**
 * PBP 消息 {@code PaccEnvelope}（{@code 0x2001}，0x2000-0x2FFF 双向）。
 *
 * <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
 *
 * <p>签名不在载荷里：置位帧头 {@code FLAG_SIGNED}，32 字节 HMAC-SHA256 放在帧尾，
 * 覆盖面是「帧头 + 载荷」整串字节（见 {@link #signingInput()}）。</p>
 */
public final class PaccEnvelope implements PbpMessage {

    /** MDL 里声明的消息 ID。 */
    public static final int MESSAGE_ID = 0x2001;

    // ------------------------------------------------------------ 字段

    private String type = "";
    private long tsMs;
    private String nonce = "";
    private String sessionId = "";
    private String pteid = "";
    private String payloadJson = "";
    private int sigVersion;

    // 帧尾签名，载荷里没有这个字段
    private byte[] signature = new byte[0];

    /** 解析路径用它建空对象，字段默认值见声明处。 */
    PaccEnvelope() {
    }

    /**
     * 字段构造器。可空性由 MDL 决定：String 与 byte[] 默认空值、
     * 消息类型字段默认 null（编码时才校验，为空直接抛 PbpException）。
     */
    public static final class Builder {

        private String type = "";
        private long tsMs = 0L;
        private String nonce = "";
        private String sessionId = "";
        private String pteid = "";
        private String payloadJson = "";
        private int sigVersion = 0;
        private byte[] signature = new byte[0];

        private Builder() {
        }

        /** MDL 字段 1 {@code type}。 */
        public Builder setType(String value) {
            this.type = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 2 {@code ts_ms}。 */
        public Builder setTsMs(long value) {
            this.tsMs = value;
            return this;
        }

        /** MDL 字段 3 {@code nonce}。 */
        public Builder setNonce(String value) {
            this.nonce = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 4 {@code session_id}。 */
        public Builder setSessionId(String value) {
            this.sessionId = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 5 {@code pteid}。 */
        public Builder setPteid(String value) {
            this.pteid = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 6 {@code payload_json}。 */
        public Builder setPayloadJson(String value) {
            this.payloadJson = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 7 {@code sig_version}。 */
        public Builder setSigVersion(int value) {
            this.sigVersion = value;
            return this;
        }

        /** 帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。 */
        public Builder setSignature(String hex) {
            this.signature = signatureFromHex(hex);
            return this;
        }

        /** 帧尾签名的原始字节；null 视为不签名。 */
        public Builder setSignatureBytes(byte[] value) {
            this.signature = value == null ? new byte[0] : value.clone();
            return this;
        }

        public PaccEnvelope build() {
            PaccEnvelope msg = new PaccEnvelope();
            msg.type = type;
            msg.tsMs = tsMs;
            msg.nonce = nonce;
            msg.sessionId = sessionId;
            msg.pteid = pteid;
            msg.payloadJson = payloadJson;
            msg.sigVersion = sigVersion;
            msg.signature = signature.clone();
            return msg;
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /** 以当前值为初值开一个新 Builder（例如改完字段要重新签名）。 */
    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.type = type;
        builder.tsMs = tsMs;
        builder.nonce = nonce;
        builder.sessionId = sessionId;
        builder.pteid = pteid;
        builder.payloadJson = payloadJson;
        builder.sigVersion = sigVersion;
        builder.signature = signature.clone();
        return builder;
    }

    // ------------------------------------------------------------ 字段读取

    /** MDL 字段 1 {@code type}。 */
    public String getType() {
        return type;
    }

    /** MDL 字段 2 {@code ts_ms}。 */
    public long getTsMs() {
        return tsMs;
    }

    /** MDL 字段 3 {@code nonce}。 */
    public String getNonce() {
        return nonce;
    }

    /** MDL 字段 4 {@code session_id}。 */
    public String getSessionId() {
        return sessionId;
    }

    /** MDL 字段 5 {@code pteid}。 */
    public String getPteid() {
        return pteid;
    }

    /** MDL 字段 6 {@code payload_json}。 */
    public String getPayloadJson() {
        return payloadJson;
    }

    /** MDL 字段 7 {@code sig_version}。 */
    public int getSigVersion() {
        return sigVersion;
    }

    // ------------------------------------------------------------ 帧

    /** 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。 */
    public byte[] toByteArray() {
        PbpFrame frame = PbpCodec.frameOf(this, tsMs);
        if (signature.length == PbpFrame.SIGNATURE_SIZE) {
            frame = frame.withSignature(signature);
        } else if (signature.length != 0) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                "签名长度必须是 0 或 " + PbpFrame.SIGNATURE_SIZE + "，实际 " + signature.length);
        }
        return frame.encode();
    }

    /** HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。 */
    public byte[] signingInput() {
        return PbpCodec.frameOf(this, tsMs).signingInput();
    }

    /** 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。置位 FLAG_COMPRESSED 的帧先解压再解码载荷。 */
    public static PaccEnvelope parseFrom(byte[] raw) {
        PbpFrame frame = PbpFrame.parse(raw);
        if (frame.messageId() != MESSAGE_ID) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                "消息 ID 不符：期望 0x" + Integer.toHexString(MESSAGE_ID)
                + "，实际 0x" + Integer.toHexString(frame.messageId()));
        }
        PaccEnvelope msg = new PaccEnvelope();
        msg.decode(new PbpDecoder(PbpCodec.payloadOf(frame)));
        msg.signature = frame.signature().clone();
        return msg;
    }

    // ------------------------------------------------------------ 签名

    /** 帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。 */
    public String getSignature() {
        return signature.length == 0 ? "" : HexFormat.of().formatHex(signature);
    }

    /** 帧尾签名的副本；未签名返回零长数组。 */
    public byte[] signatureBytes() {
        return signature.clone();
    }

    private static byte[] signatureFromHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        try {
            return HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "签名不是合法十六进制串", e);
        }
    }

    // ------------------------------------------------------------ PbpMessage

    @Override
    public int messageId() {
        return MESSAGE_ID;
    }

    @Override
    public void encode(PbpEncoder enc) {
        enc.writeString(type);
        enc.writeInt64(tsMs);
        enc.writeString(nonce);
        enc.writeString(sessionId);
        enc.writeString(pteid);
        enc.writeString(payloadJson);
        enc.writeUInt8(sigVersion);
    }

    /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
    @Override
    public void decode(PbpDecoder dec) {
        type = dec.readString();
        tsMs = dec.readInt64();
        nonce = dec.readString();
        sessionId = dec.readString();
        pteid = dec.readString();
        payloadJson = dec.readString();
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        sigVersion = dec.remaining() > 0 ? dec.readUInt8() : 0;
    }

    /** 编码后的字节数，仅用于预分配缓冲区。 */
    @Override
    public int encodedSize() {
        int size = 0;
        size += PbpEncoder.stringSize(type);
        size += PbpEncoder.int64Size(tsMs);
        size += PbpEncoder.stringSize(nonce);
        size += PbpEncoder.stringSize(sessionId);
        size += PbpEncoder.stringSize(pteid);
        size += PbpEncoder.stringSize(payloadJson);
        size += PbpEncoder.uint8Size();
        return size;
    }

    @Override
    public String toString() {
        return "PaccEnvelope{" + "type=" + type + ", " + "ts_ms=" + tsMs + ", " + "nonce=" + nonce + ", " + "session_id=" + sessionId + ", " + "pteid=" + pteid + ", " + "payload_json=" + payloadJson + ", " + "sig_version=" + sigVersion + "}";
    }

}
