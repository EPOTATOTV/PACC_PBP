// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

package com.potatotv.pbp.gen;

import com.potatotv.pbp.PbpDecoder;
import com.potatotv.pbp.PbpEncoder;
import com.potatotv.pbp.PbpMessage;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PBP 消息 {@code DetectionEvent}，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
 *
 * <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
 */
public final class DetectionEvent implements PbpMessage {

    /** 可空字段个数，用于定位载荷里的存在性位图。 */
    public static final int OPTIONAL_FIELD_COUNT = 1;

    // ------------------------------------------------------------ 字段

    private int eventType;
    private float confidence;
    private long timestamp;
    private Map<String, byte[]> evidence = new LinkedHashMap<>();
    private String detail = null;

    /** 解析路径用它建空对象，字段默认值见声明处。 */
    DetectionEvent() {
    }

    /**
     * 字段构造器。可空性由 MDL 决定：String 与 byte[] 默认空值、
     * 消息类型字段默认 null（编码时才校验，为空直接抛 PbpException）。
     */
    public static final class Builder {

        private int eventType = 0;
        private float confidence = 0.0f;
        private long timestamp = 0L;
        private Map<String, byte[]> evidence = new LinkedHashMap<>();
        private String detail = null;

        private Builder() {
        }

        /** MDL 字段 1 {@code event_type}。 */
        public Builder setEventType(int value) {
            this.eventType = value;
            return this;
        }

        /** MDL 字段 2 {@code confidence}。 */
        public Builder setConfidence(float value) {
            this.confidence = value;
            return this;
        }

        /** MDL 字段 3 {@code timestamp}。 */
        public Builder setTimestamp(long value) {
            this.timestamp = value;
            return this;
        }

        /** MDL 字段 4 {@code evidence}。 */
        public Builder setEvidence(Map<String, byte[]> value) {
            this.evidence = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value);
            return this;
        }

        /** 写入一个 {@code evidence} 键值对。 */
        public Builder putEvidence(String key, byte[] value) {
            this.evidence.put(key, value);
            return this;
        }

        /** MDL 字段 5 {@code detail}。 */
        public Builder setDetail(String value) {
            this.detail = value;
            return this;
        }

        public DetectionEvent build() {
            DetectionEvent msg = new DetectionEvent();
            msg.eventType = eventType;
            msg.confidence = confidence;
            msg.timestamp = timestamp;
            msg.evidence = new LinkedHashMap<>(evidence);
            msg.detail = detail;
            return msg;
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /** 以当前值为初值开一个新 Builder（例如改完字段要重新签名）。 */
    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.eventType = eventType;
        builder.confidence = confidence;
        builder.timestamp = timestamp;
        builder.evidence = new LinkedHashMap<>(evidence);
        builder.detail = detail;
        return builder;
    }

    // ------------------------------------------------------------ 字段读取

    /** MDL 字段 1 {@code event_type}。 */
    public int getEventType() {
        return eventType;
    }

    /** MDL 字段 2 {@code confidence}。 */
    public float getConfidence() {
        return confidence;
    }

    /** MDL 字段 3 {@code timestamp}。 */
    public long getTimestamp() {
        return timestamp;
    }

    /** MDL 字段 4 {@code evidence}。 */
    public Map<String, byte[]> getEvidence() {
        return Collections.unmodifiableMap(evidence);
    }

    /** MDL 字段 5 {@code detail}。 */
    public String getDetail() {
        return detail;
    }

    // ------------------------------------------------------------ PbpMessage

    @Override
    public int messageId() {
        return 0;
    }

    @Override
    public void encode(PbpEncoder enc) {
        enc.writeInt32(eventType);
        enc.writeFloat32(confidence);
        enc.writeInt64(timestamp);
        enc.writeStringMap(evidence, PbpEncoder::writeBytes);
        enc.writeOptionalString(detail);
    }

    /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
    @Override
    public void decode(PbpDecoder dec) {
        eventType = dec.readInt32();
        confidence = dec.readFloat32();
        timestamp = dec.readInt64();
        evidence = dec.readStringMap(PbpDecoder::readBytes);
        detail = dec.readOptionalString();
    }

    /** 编码后的字节数，仅用于预分配缓冲区。 */
    @Override
    public int encodedSize() {
        int size = 0;
        size += PbpEncoder.int32Size(eventType);
        size += PbpEncoder.float32Size();
        size += PbpEncoder.int64Size(timestamp);
        size += PbpEncoder.stringMapSize(evidence, PbpEncoder::bytesSize);
        size += PbpEncoder.optionalStringSize(detail);
        return size;
    }

    @Override
    public String toString() {
        return "DetectionEvent{" + "event_type=" + eventType + ", " + "confidence=" + confidence + ", " + "timestamp=" + timestamp + ", " + "evidence=" + evidence.size() + " 项" + ", " + "detail=" + detail + "}";
    }

}
