package com.potatotv.pbp;

import com.potatotv.pbp.gen.ApmSnapshot;
import com.potatotv.pbp.gen.DetectionEvent;
import com.potatotv.pbp.gen.DetectionReport;
import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 紧凑性对比（设计文档 §3.1 与验收项 B02：比 Protobuf 小 ≥15%）。
 *
 * <p>对比基准是 same-schema 的 proto3 线格式，由本测试里的
 * {@link Proto3Writer} 按规范手写：这样既不需要把 protobuf 依赖拉回仓库
 * （验收项 I05 要求 pom 里没有 protobuf），也不至于拿"加了标签的假想格式"当靶子。
 * 写出的是真实 protobuf 编码——字段标签、varint、长度前缀、map 的 entry 包装，
 * 以及 proto3 的标量默认值不落盘，一条不少。</p>
 *
 * <p>只比载荷，不含各自的传输封装（PBP 的 30 字节帧头与 protobuf 场景下的
 * WebSocket/TLS 封装不是同一层的东西）。省下的部分基本来自"每个字段一个标签"的消除，
 * 字段越少、值越短（比如只有 7 个短字符串的查端信封），相对收益就越接近标签占比本身；
 * 用例里逐条打印各消息的实测值，不做合并掩盖。</p>
 */
class PbpCompactnessTest {

    /** proto3 线格式的最小子集：只实现本测试用到的 writer 类型。 */
    private static final class Proto3Writer {

        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] toByteArray() {
            return out.toByteArray();
        }

        private void varint(long value) {
            while ((value & ~0x7FL) != 0) {
                out.write((int) ((value & 0x7F) | 0x80));
                value >>>= 7;
            }
            out.write((int) value);
        }

        private void tag(int field, int wireType) {
            varint(((long) field << 3) | wireType);
        }

        void int64Field(int field, long value) {
            if (value == 0) {
                return;   // proto3 隐含存在：默认值不落盘
            }
            tag(field, 0);
            varint(value);
        }

        void uint32Field(int field, int value) {
            if (value == 0) {
                return;
            }
            tag(field, 0);
            varint(value & 0xFFFFFFFFL);
        }

        void floatField(int field, float value) {
            if (value == 0f) {
                return;
            }
            tag(field, 5);
            int bits = Float.floatToRawIntBits(value);
            for (int i = 0; i < 4; i++) {
                out.write((bits >>> (i * 8)) & 0xFF);
            }
        }

        void stringField(int field, String value) {
            if (value == null || value.isEmpty()) {
                return;
            }
            bytesField(field, value.getBytes(StandardCharsets.UTF_8));
        }

        void bytesField(int field, byte[] value) {
            if (value == null || value.length == 0) {
                return;
            }
            tag(field, 2);
            varint(value.length);
            out.write(value, 0, value.length);
        }

        void messageField(int field, byte[] nested) {
            bytesField(field, nested);
        }

        /** map&lt;string, bytes&gt; 的一个 entry：protobuf 会包一层 entry 消息再加标签。 */
        void stringBytesMapEntry(int field, String key, byte[] value) {
            Proto3Writer entry = new Proto3Writer();
            entry.stringField(1, key);
            entry.bytesField(2, value);
            messageField(field, entry.toByteArray());
        }

        /** map&lt;string, float&gt; 的一个 entry。 */
        void stringFloatMapEntry(int field, String key, float value) {
            Proto3Writer entry = new Proto3Writer();
            entry.stringField(1, key);
            entry.floatField(2, value);
            messageField(field, entry.toByteArray());
        }
    }

    private record Comparison(String label, int pbpBytes, int protoBytes) {
    }

    @Test
    void pbpIsAtLeast15PercentSmallerThanEquivalentProtobuf() {
        Comparison envelope = compareEnvelope();
        Comparison report = compareDetectionReport();
        Comparison apm = compareApmSnapshot();

        int pbpTotal = envelope.pbpBytes() + report.pbpBytes() + apm.pbpBytes();
        int protoTotal = envelope.protoBytes() + report.protoBytes() + apm.protoBytes();
        double saving = 1.0 - (double) pbpTotal / protoTotal;

        System.out.printf("%-24s %10s %12s %8s%n", "消息", "PBP(B)", "Protobuf(B)", "节省");
        for (Comparison c : new Comparison[]{envelope, report, apm}) {
            System.out.printf("%-24s %10d %12d %7.1f%%%n", c.label(), c.pbpBytes(), c.protoBytes(),
                    100.0 * (1.0 - (double) c.pbpBytes() / c.protoBytes()));
        }
        System.out.printf("%-24s %10d %12d %7.1f%%%n", "合计", pbpTotal, protoTotal, saving * 100);

        assertTrue(saving >= 0.15, String.format(
                "整体紧凑性未达标：PBP %d 字节 vs Protobuf %d 字节，仅省 %.1f%%（目标 ≥15%%）",
                pbpTotal, protoTotal, saving * 100));
    }

    // ------------------------------------------------------------ 三个代表性消息

    private static Comparison compareEnvelope() {
        PaccEnvelope envelope = PaccEnvelope.newBuilder()
                .setType("inspect_result")
                .setTsMs(1_700_000_000_000L)
                .setNonce("0123456789abcdef")
                .setSessionId("sess-123456")
                .setPteid("PT00000001")
                .setPayloadJson("{\"verdict\":\"clean\",\"score\":0}")
                .setSigVersion(2)
                .build();

        Proto3Writer proto = new Proto3Writer();
        proto.stringField(1, envelope.getType());
        proto.int64Field(2, envelope.getTsMs());
        proto.stringField(3, envelope.getNonce());
        proto.stringField(4, envelope.getSessionId());
        proto.stringField(5, envelope.getPteid());
        proto.stringField(6, envelope.getPayloadJson());
        proto.uint32Field(7, envelope.getSigVersion());
        return new Comparison("PaccEnvelope", PbpCodec.payloadOf(envelope).length, proto.toByteArray().length);
    }

    private static Comparison compareDetectionReport() {
        DetectionReport report = DetectionReport.newBuilder()
                .setPteid("PT00000001")
                .setTimestamp(1_700_000_000_000L)
                .setClientVersion("5.4.0")
                .setPlatform("windows")
                .addEvents(event(2, 0.87f, "pacc-probe", "内存段校验不一致"))
                .addEvents(event(3, 0.42f, "pacc-guard", "输入节奏异常"))
                .addEvents(event(4, 0.61f, "pacc-screen", "外挂特征命中"))
                .setApm(apmSnapshot())
                .setSignature(new byte[32])
                .build();

        Proto3Writer proto = new Proto3Writer();
        proto.stringField(1, report.getPteid());
        proto.int64Field(2, report.getTimestamp());
        proto.stringField(3, report.getClientVersion());
        proto.stringField(4, report.getPlatform());
        for (DetectionEvent event : report.getEvents()) {
            Proto3Writer nested = new Proto3Writer();
            nested.int64Field(1, event.getEventType());
            nested.floatField(2, event.getConfidence());
            nested.int64Field(3, event.getTimestamp());
            for (var entry : event.getEvidence().entrySet()) {
                nested.stringBytesMapEntry(4, entry.getKey(), entry.getValue());
            }
            nested.stringField(5, event.getDetail());
            proto.messageField(5, nested.toByteArray());
        }
        proto.messageField(6, protoApmSnapshot(report.getApm()));
        proto.bytesField(7, report.getSignature());
        return new Comparison("DetectionReport", PbpCodec.payloadOf(report).length, proto.toByteArray().length);
    }

    private static Comparison compareApmSnapshot() {
        ApmSnapshot apm = apmSnapshot();
        return new Comparison("ApmSnapshot", PbpCodec.payloadOf(apm).length,
                protoApmSnapshot(apm).length);
    }

    private static DetectionEvent event(int type, float confidence, String module, String detail) {
        return DetectionEvent.newBuilder()
                .setEventType(type)
                .setConfidence(confidence)
                .setTimestamp(1_700_000_000_000L)
                .putEvidence("module", module.getBytes(StandardCharsets.UTF_8))
                .putEvidence("hash", new byte[]{0x11, 0x22, 0x33, 0x44})
                .putEvidence("base", new byte[]{0x40, 0x00, 0x12})
                .putEvidence("size", new byte[]{0x00, 0x04})
                .setDetail(detail)
                .build();
    }

    private static ApmSnapshot apmSnapshot() {
        return ApmSnapshot.newBuilder()
                .setCpuUsage(23.5f)
                .setMemoryUsageKb(450_000)
                .setFps(120.0f)
                .setDetectionLatencyMs(12)
                .setActiveRules(50)
                .putCustomMetrics("gc_ms", 3.5f)
                .putCustomMetrics("heap_mb", 512.0f)
                .build();
    }

    private static byte[] protoApmSnapshot(ApmSnapshot apm) {
        Proto3Writer proto = new Proto3Writer();
        proto.floatField(1, apm.getCpuUsage());
        proto.int64Field(2, apm.getMemoryUsageKb());
        proto.floatField(3, apm.getFps());
        proto.int64Field(4, apm.getDetectionLatencyMs());
        proto.int64Field(5, apm.getActiveRules());
        for (var entry : apm.getCustomMetrics().entrySet()) {
            proto.stringFloatMapEntry(6, entry.getKey(), entry.getValue());
        }
        return proto.toByteArray();
    }
}