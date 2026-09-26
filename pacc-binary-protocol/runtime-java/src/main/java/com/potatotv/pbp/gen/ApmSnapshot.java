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
 * PBP 消息 {@code ApmSnapshot}，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
 *
 * <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
 * 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
 */
public final class ApmSnapshot implements PbpMessage {

    // ------------------------------------------------------------ 字段

    private float cpuUsage;
    private int memoryUsageKb;
    private float fps;
    private int detectionLatencyMs;
    private int activeRules;
    private Map<String, Float> customMetrics = new LinkedHashMap<>();

    /** 解析路径用它建空对象，字段默认值见声明处。 */
    ApmSnapshot() {
    }

    /**
     * 字段构造器。可空性由 MDL 决定：String 与 byte[] 默认空值、
     * 消息类型字段默认 null（编码时才校验，为空直接抛 PbpException）。
     */
    public static final class Builder {

        private float cpuUsage = 0.0f;
        private int memoryUsageKb = 0;
        private float fps = 0.0f;
        private int detectionLatencyMs = 0;
        private int activeRules = 0;
        private Map<String, Float> customMetrics = new LinkedHashMap<>();

        private Builder() {
        }

        /** MDL 字段 1 {@code cpu_usage}。 */
        public Builder setCpuUsage(float value) {
            this.cpuUsage = value;
            return this;
        }

        /** MDL 字段 2 {@code memory_usage_kb}。 */
        public Builder setMemoryUsageKb(int value) {
            this.memoryUsageKb = value;
            return this;
        }

        /** MDL 字段 3 {@code fps}。 */
        public Builder setFps(float value) {
            this.fps = value;
            return this;
        }

        /** MDL 字段 4 {@code detection_latency_ms}。 */
        public Builder setDetectionLatencyMs(int value) {
            this.detectionLatencyMs = value;
            return this;
        }

        /** MDL 字段 5 {@code active_rules}。 */
        public Builder setActiveRules(int value) {
            this.activeRules = value;
            return this;
        }

        /** MDL 字段 6 {@code custom_metrics}。 */
        public Builder setCustomMetrics(Map<String, Float> value) {
            this.customMetrics = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value);
            return this;
        }

        /** 写入一个 {@code custom_metrics} 键值对。 */
        public Builder putCustomMetrics(String key, float value) {
            this.customMetrics.put(key, value);
            return this;
        }

        public ApmSnapshot build() {
            ApmSnapshot msg = new ApmSnapshot();
            msg.cpuUsage = cpuUsage;
            msg.memoryUsageKb = memoryUsageKb;
            msg.fps = fps;
            msg.detectionLatencyMs = detectionLatencyMs;
            msg.activeRules = activeRules;
            msg.customMetrics = new LinkedHashMap<>(customMetrics);
            return msg;
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /** 以当前值为初值开一个新 Builder（例如改完字段要重新签名）。 */
    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.cpuUsage = cpuUsage;
        builder.memoryUsageKb = memoryUsageKb;
        builder.fps = fps;
        builder.detectionLatencyMs = detectionLatencyMs;
        builder.activeRules = activeRules;
        builder.customMetrics = new LinkedHashMap<>(customMetrics);
        return builder;
    }

    // ------------------------------------------------------------ 字段读取

    /** MDL 字段 1 {@code cpu_usage}。 */
    public float getCpuUsage() {
        return cpuUsage;
    }

    /** MDL 字段 2 {@code memory_usage_kb}。 */
    public int getMemoryUsageKb() {
        return memoryUsageKb;
    }

    /** MDL 字段 3 {@code fps}。 */
    public float getFps() {
        return fps;
    }

    /** MDL 字段 4 {@code detection_latency_ms}。 */
    public int getDetectionLatencyMs() {
        return detectionLatencyMs;
    }

    /** MDL 字段 5 {@code active_rules}。 */
    public int getActiveRules() {
        return activeRules;
    }

    /** MDL 字段 6 {@code custom_metrics}。 */
    public Map<String, Float> getCustomMetrics() {
        return Collections.unmodifiableMap(customMetrics);
    }

    // ------------------------------------------------------------ PbpMessage

    @Override
    public int messageId() {
        return 0;
    }

    @Override
    public void encode(PbpEncoder enc) {
        enc.writeFloat32(cpuUsage);
        enc.writeInt32(memoryUsageKb);
        enc.writeFloat32(fps);
        enc.writeInt32(detectionLatencyMs);
        enc.writeInt32(activeRules);
        enc.writeStringMap(customMetrics, PbpEncoder::writeFloat32);
    }

    /** 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。 */
    @Override
    public void decode(PbpDecoder dec) {
        cpuUsage = dec.readFloat32();
        memoryUsageKb = dec.readInt32();
        fps = dec.readFloat32();
        detectionLatencyMs = dec.readInt32();
        activeRules = dec.readInt32();
        customMetrics = dec.readStringMap(PbpDecoder::readFloat32);
    }

    /** 编码后的字节数，仅用于预分配缓冲区。 */
    @Override
    public int encodedSize() {
        int size = 0;
        size += PbpEncoder.float32Size();
        size += PbpEncoder.int32Size(memoryUsageKb);
        size += PbpEncoder.float32Size();
        size += PbpEncoder.int32Size(detectionLatencyMs);
        size += PbpEncoder.int32Size(activeRules);
        size += PbpEncoder.stringMapSize(customMetrics, v -> PbpEncoder.float32Size());
        return size;
    }

    @Override
    public String toString() {
        return "ApmSnapshot{" + "cpu_usage=" + cpuUsage + ", " + "memory_usage_kb=" + memoryUsageKb + ", " + "fps=" + fps + ", " + "detection_latency_ms=" + detectionLatencyMs + ", " + "active_rules=" + activeRules + ", " + "custom_metrics=" + customMetrics.size() + " 项" + "}";
    }

}
