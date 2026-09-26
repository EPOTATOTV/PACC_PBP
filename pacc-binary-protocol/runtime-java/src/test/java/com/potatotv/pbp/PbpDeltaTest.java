package com.potatotv.pbp;

import com.potatotv.pbp.gen.ApmSnapshot;
import com.potatotv.pbp.gen.DetectionEvent;
import com.potatotv.pbp.gen.DetectionReport;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 差分链（设计文档 §3.10.2）的往返、节省率与协议规则测试。
 *
 * <p>消息相等性用「编码后的载荷字节」比较：生成类的字段序写入是确定的，
 * 字段值一致就能得到逐字节一致的载荷，比手写 equals 更贴近线上语义。</p>
 */
class PbpDeltaTest {

    private static DetectionEvent event(int type, float confidence, String module) {
        // 事件体不随时间变化：状态上报里"没变的部分"就是靠差分省下来的
        return DetectionEvent.newBuilder()
                .setEventType(type)
                .setConfidence(confidence)
                .setTimestamp(900L)
                .putEvidence("module", module.getBytes(StandardCharsets.UTF_8))
                .setDetail("可疑进程")
                .build();
    }

    private static DetectionReport report(long ts, int cpuPercent, int rules) {
        ApmSnapshot apm = ApmSnapshot.newBuilder()
                .setCpuUsage(cpuPercent / 100.0f)
                .setMemoryUsageKb(450_000)
                .setFps(120.0f)
                .setDetectionLatencyMs(12)
                .setActiveRules(rules)
                .putCustomMetrics("gc_ms", 3.5f)
                .putCustomMetrics("heap_mb", 512.0f)
                .build();
        return DetectionReport.newBuilder()
                .setPteid("PT0001")
                .setTimestamp(ts)
                .setClientVersion("5.4.0")
                .setPlatform("windows")
                .addEvents(event(2, 0.87f, "pacc-probe"))
                .addEvents(event(3, 0.42f, "pacc-guard"))
                .setApm(apm)
                .build();
    }

    private static PbpDeltaChain<DetectionReport> newChain() {
        return new PbpDeltaChain<>(DetectionReport.MESSAGE_ID, () -> DetectionReport.newBuilder().build());
    }

    private static byte[] payload(PbpMessage message) {
        return PbpCodec.payloadOf(message);
    }

    @Test
    void deltaChainReconstructsEveryMessageExactly() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        PbpDeltaChain<DetectionReport> receiver = newChain();

        List<DetectionReport> messages = new ArrayList<>();
        messages.add(report(1_000L, 23, 50));
        messages.add(report(1_001L, 24, 50));                                       // 只改 APM 与时间戳
        DetectionReport second = messages.get(1).toBuilder()
                .addEvents(DetectionEvent.newBuilder().setEventType(3).setConfidence(0.5f).build())
                .build();
        messages.add(second);                                                       // 列表增长
        messages.add(second.toBuilder().setApm(null).build());                      // 可空字段清空
        messages.add(messages.get(3).toBuilder().setSignature(new byte[]{1, 2, 3}).build());
        messages.add(messages.get(4).toBuilder()
                .setClientVersion("5.4.1")
                .setPlatform("android")
                .build());                                                          // 普通字符串变化

        for (int i = 0; i < messages.size(); i++) {
            PbpFrame frame = sender.encode(messages.get(i), 1_000L + i);
            DetectionReport decoded = receiver.decode(frame.encode());
            assertArrayEquals(payload(messages.get(i)), payload(decoded),
                    "第 " + i + " 条消息回放结果不一致");
        }
        assertTrue(sender.consecutive() > 0, "除首条外都应该是差分");
    }

    /** 验收项 B07 的"节省 ≥50%"：状态类消息只改少数字段时，差分载荷要显著小于完整载荷。 */
    @Test
    void deltaSavesAtLeastHalfForStatusUpdates() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        PbpDeltaChain<DetectionReport> receiver = newChain();

        DetectionReport first = report(2_000L, 20, 50);
        PbpFrame fullFrame = sender.encode(first, 2_000L);
        receiver.decode(fullFrame.encode());
        int fullSize = fullFrame.payloadLength();
        assertFalse(fullFrame.delta());

        for (int i = 1; i <= 8; i++) {
            DetectionReport next = report(2_000L + i, 20 + i, 50);
            PbpFrame deltaFrame = sender.encode(next, 2_000L + i);
            assertTrue(deltaFrame.delta(), "第 " + i + " 条应为差分帧");
            assertTrue(deltaFrame.payloadLength() * 2 <= fullSize,
                    "差分载荷 " + deltaFrame.payloadLength() + " 未达到完整载荷 " + fullSize + " 的一半");
            assertArrayEquals(payload(next), payload(receiver.decode(deltaFrame.encode())));
        }
    }

    /** 连续 10 条差分之后必须回到完整消息（设计文档 §3.10.2 的防累积误差规则）。 */
    @Test
    void chainForcesFullMessageAfterTenConsecutiveDeltas() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        List<PbpFrame> frames = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            frames.add(sender.encode(report(3_000L + i, 30 + i, 50), 3_000L + i));
        }
        assertFalse(frames.get(0).delta());
        for (int i = 1; i <= 10; i++) {
            assertTrue(frames.get(i).delta(), "第 " + i + " 条应为差分");
        }
        assertFalse(frames.get(11).delta(), "第 11 条差分之后必须重发完整消息");
        for (int i = 12; i <= 14; i++) {
            assertTrue(frames.get(i).delta());
        }
        assertEquals(3, sender.consecutive());
    }

    @Test
    void receiverRejectsDeltaWithoutBaseline() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        sender.encode(report(4_000L, 20, 50), 4_000L);
        PbpFrame delta = sender.encode(report(4_001L, 21, 50), 4_001L);
        assertTrue(delta.delta());

        PbpDeltaChain<DetectionReport> fresh = newChain();
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> fresh.decode(delta.encode())).code());
    }

    @Test
    void receiverRejectsEleventhConsecutiveDelta() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        PbpDeltaChain<DetectionReport> receiver = newChain();

        DetectionReport current = report(5_000L, 20, 50);
        receiver.decode(sender.encode(current, 5_000L).encode());
        for (int i = 1; i <= 10; i++) {
            DetectionReport next = report(5_000L + i, 20 + i, 50);
            receiver.decode(sender.encode(next, 5_000L + i).encode());
            current = next;
        }
        assertEquals(10, receiver.consecutive());

        // 手工造"第 11 条差分"：合规发送方不会发，接收侧必须拒绝
        DetectionReport eleventh = report(5_011L, 31, 50);
        PbpEncoder encoder = new PbpEncoder(64);
        eleventh.encodeDelta(encoder, current);
        byte[] raw = PbpFrame.of(DetectionReport.MESSAGE_ID, 5_011L, encoder.toByteArray())
                .withFlag(PbpFrame.FLAG_DELTA)
                .encode();
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> receiver.decode(raw)).code());
    }

    /** 差分载荷超过阈值时同样走压缩，两种标志可以同时出现。 */
    @Test
    void largeDeltaPayloadIsCompressedToo() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        PbpDeltaChain<DetectionReport> receiver = newChain();

        DetectionReport first = report(6_000L, 20, 50);
        receiver.decode(sender.encode(first, 6_000L).encode());

        StringBuilder big = new StringBuilder();
        big.append("windows-".repeat(400));
        DetectionReport second = first.toBuilder().setPlatform(big.toString()).build();
        PbpFrame frame = sender.encode(second, 6_001L);
        assertTrue(frame.delta());
        assertTrue(frame.compressed(), "变化字段近 3KB，差分载荷应当被压缩");
        assertArrayEquals(payload(second), payload(receiver.decode(frame.encode())));
    }

    @Test
    void resetDropsBaseline() {
        PbpDeltaChain<DetectionReport> sender = newChain();
        sender.encode(report(7_000L, 20, 50), 7_000L);
        assertTrue(sender.encode(report(7_001L, 21, 50), 7_001L).delta());
        sender.reset();
        assertFalse(sender.encode(report(7_002L, 22, 50), 7_002L).delta());
    }
}