// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

package com.potatotv.pbp.gen;

import com.potatotv.pbp.PbpDecoder;
import com.potatotv.pbp.PbpEncoder;
import com.potatotv.pbp.PbpCodec;
import com.potatotv.pbp.PbpException;
import com.potatotv.pbp.PbpFrame;
import com.potatotv.pbp.PbpDeltaMessage;
import com.potatotv.pbp.PbpDelta;
import com.potatotv.pbp.PbpMessage;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * PBP 消息 {@code DetectionReport}（{@code 0x0103}，0x0100-0x0FFF 客户端 → 服务端）。
 *
 * <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
 *
 * <p>实现了 {@link com.potatotv.pbp.PbpDeltaMessage}：可经 {@code PbpDeltaChain} 发差分帧（设计文档 §3.10.2）。</p>
 */
public final class DetectionReport implements PbpMessage, PbpDeltaMessage<DetectionReport> {

    /** MDL 里声明的消息 ID。 */
    public static final int MESSAGE_ID = 0x0103;

    /** 可空字段个数，用于定位载荷里的存在性位图。 */
    public static final int OPTIONAL_FIELD_COUNT = 1;

    // ------------------------------------------------------------ 字段

    private String pteid = "";
    private long timestamp;
    private String clientVersion = "";
    private String platform = "";
    private List<DetectionEvent> events = new ArrayList<>();
    private ApmSnapshot apm = null;
    private byte[] signature = new byte[0];

    /** 解析路径用它建空对象，字段默认值见声明处。 */
    DetectionReport() {
    }

    /**
     * 字段构造器。可空性由 MDL 决定：String 与 byte[] 默认空值、
     * 消息类型字段默认 null（编码时才校验，为空直接抛 PbpException）。
     */
    public static final class Builder {

        private String pteid = "";
        private long timestamp = 0L;
        private String clientVersion = "";
        private String platform = "";
        private List<DetectionEvent> events = new ArrayList<>();
        private ApmSnapshot apm = null;
        private byte[] signature = new byte[0];

        private Builder() {
        }

        /** MDL 字段 1 {@code pteid}。 */
        public Builder setPteid(String value) {
            this.pteid = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 2 {@code timestamp}。 */
        public Builder setTimestamp(long value) {
            this.timestamp = value;
            return this;
        }

        /** MDL 字段 3 {@code client_version}。 */
        public Builder setClientVersion(String value) {
            this.clientVersion = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 4 {@code platform}。 */
        public Builder setPlatform(String value) {
            this.platform = value == null ? "" : value;
            return this;
        }

        /** MDL 字段 5 {@code events}。 */
        public Builder setEvents(List<DetectionEvent> value) {
            this.events = value == null ? new ArrayList<>() : new ArrayList<>(value);
            return this;
        }

        /** 追加一个 {@code events} 元素。 */
        public Builder addEvents(DetectionEvent value) {
            this.events.add(value);
            return this;
        }

        /** MDL 字段 6 {@code apm}。 */
        public Builder setApm(ApmSnapshot value) {
            this.apm = value;
            return this;
        }

        /** MDL 字段 7 {@code signature}。 */
        public Builder setSignature(byte[] value) {
            this.signature = value == null ? new byte[0] : value.clone();
            return this;
        }

        public DetectionReport build() {
            DetectionReport msg = new DetectionReport();
            msg.pteid = pteid;
            msg.timestamp = timestamp;
            msg.clientVersion = clientVersion;
            msg.platform = platform;
            msg.events = new ArrayList<>(events);
            msg.apm = apm;
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
        builder.pteid = pteid;
        builder.timestamp = timestamp;
        builder.clientVersion = clientVersion;
        builder.platform = platform;
        builder.events = new ArrayList<>(events);
        builder.apm = apm;
        builder.signature = signature.clone();
        return builder;
    }

    // ------------------------------------------------------------ 字段读取

    /** MDL 字段 1 {@code pteid}。 */
    public String getPteid() {
        return pteid;
    }

    /** MDL 字段 2 {@code timestamp}。 */
    public long getTimestamp() {
        return timestamp;
    }

    /** MDL 字段 3 {@code client_version}。 */
    public String getClientVersion() {
        return clientVersion;
    }

    /** MDL 字段 4 {@code platform}。 */
    public String getPlatform() {
        return platform;
    }

    /** MDL 字段 5 {@code events}。 */
    public List<DetectionEvent> getEvents() {
        return Collections.unmodifiableList(events);
    }

    /** MDL 字段 6 {@code apm}。 */
    public ApmSnapshot getApm() {
        return apm;
    }

    /** MDL 字段 7 {@code signature}。 */
    public byte[] getSignature() {
        return signature.clone();
    }

    // ------------------------------------------------------------ 帧

    /** 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。 */
    public byte[] toByteArray() {
        PbpFrame frame = PbpCodec.frameOf(this, 0L);
        return frame.encode();
    }

    /** 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。置位 FLAG_COMPRESSED 的帧先解压再解码载荷。 */
    public static DetectionReport parseFrom(byte[] raw) {
        PbpFrame frame = PbpFrame.parse(raw);
        if (frame.messageId() != MESSAGE_ID) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                "消息 ID 不符：期望 0x" + Integer.toHexString(MESSAGE_ID)
                + "，实际 0x" + Integer.toHexString(frame.messageId()));
        }
        DetectionReport msg = new DetectionReport();
        msg.decode(new PbpDecoder(PbpCodec.payloadOf(frame)));
        return msg;
    }

    // ------------------------------------------------------------ PbpMessage

    @Override
    public int messageId() {
        return MESSAGE_ID;
    }

    @Override
    public void encode(PbpEncoder enc) {
        enc.writeString(pteid);
        enc.writeInt64(timestamp);
        enc.writeString(clientVersion);
        enc.writeString(platform);
        enc.writeMessageList(events);
        enc.writeOptionalMessage(apm);
        enc.writeBytes(signature);
    }

    /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
    @Override
    public void decode(PbpDecoder dec) {
        pteid = dec.readString();
        timestamp = dec.readInt64();
        clientVersion = dec.readString();
        platform = dec.readString();
        events = dec.readMessageList(DetectionEvent::new);
        apm = dec.readOptionalMessage(ApmSnapshot::new);
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        signature = dec.remaining() > 0 ? dec.readBytes() : new byte[0];
    }

    /** 编码后的字节数，仅用于预分配缓冲区。 */
    @Override
    public int encodedSize() {
        int size = 0;
        size += PbpEncoder.stringSize(pteid);
        size += PbpEncoder.int64Size(timestamp);
        size += PbpEncoder.stringSize(clientVersion);
        size += PbpEncoder.stringSize(platform);
        size += PbpEncoder.messageListSize(events);
        size += PbpEncoder.optionalMessageSize(apm);
        size += PbpEncoder.bytesSize(signature);
        return size;
    }

    // ------------------------------------------------------------ 差分（设计文档 §3.10.2）

    /** 相对基线只写变化的字段：存在位图 + 按字段序的变化值。 */
    @Override
    public void encodeDelta(PbpEncoder enc, DetectionReport previous) {
        boolean[] changed = {
            !Objects.equals(pteid, previous.pteid),
            timestamp != previous.timestamp,
            !Objects.equals(clientVersion, previous.clientVersion),
            !Objects.equals(platform, previous.platform),
            PbpDelta.differs(x -> x.writeMessageList(events), x -> x.writeMessageList(previous.events)),
            PbpDelta.differs(x -> x.writeOptionalMessage(apm), x -> x.writeOptionalMessage(previous.apm)),
            !Arrays.equals(signature, previous.signature),
        };
        enc.writePresence(changed);
        if (changed[0]) {
            enc.writeString(pteid);
        }
        if (changed[1]) {
            enc.writeInt64(timestamp);
        }
        if (changed[2]) {
            enc.writeString(clientVersion);
        }
        if (changed[3]) {
            enc.writeString(platform);
        }
        if (changed[4]) {
            enc.writeMessageList(events);
        }
        if (changed[5]) {
            enc.writeOptionalMessage(apm);
        }
        if (changed[6]) {
            enc.writeBytes(signature);
        }
    }

    /** 未变化的字段从基线拷贝（消息与字节数组深拷贝、集合按元素复制），变化的字段按位图读入；传入的基线对象不会被改动。 */
    @Override
    public void applyDelta(PbpDecoder dec, DetectionReport previous) {
        boolean[] present = dec.readPresence(7);
        pteid = present[0] ? dec.readString() : previous.pteid;
        timestamp = present[1] ? dec.readInt64() : previous.timestamp;
        clientVersion = present[2] ? dec.readString() : previous.clientVersion;
        platform = present[3] ? dec.readString() : previous.platform;
        events = present[4] ? dec.readMessageList(DetectionEvent::new) : PbpDelta.copyList(previous.events, DetectionEvent::new);
        apm = present[5] ? dec.readOptionalMessage(ApmSnapshot::new) : PbpDelta.copy(previous.apm, ApmSnapshot::new);
        signature = present[6] ? dec.readBytes() : previous.signature.clone();
    }

    @Override
    public String toString() {
        return "DetectionReport{" + "pteid=" + pteid + ", " + "timestamp=" + timestamp + ", " + "client_version=" + clientVersion + ", " + "platform=" + platform + ", " + "events=" + events.size() + " 项" + ", " + "apm=" + apm + ", " + "signature=" + signature.length + " 字节" + "}";
    }

}
