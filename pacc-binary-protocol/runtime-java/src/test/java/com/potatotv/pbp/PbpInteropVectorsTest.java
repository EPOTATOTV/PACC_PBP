package com.potatotv.pbp;

import com.potatotv.pbp.gen.ApmSnapshot;
import com.potatotv.pbp.gen.DetectionEvent;
import com.potatotv.pbp.gen.DetectionReport;
import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 跨语言互操作向量的导出钩子（设计文档 §3.7/§3.8，验收项 B09/B11）。
 *
 * <p>默认跳过；由维护者带 {@code -Dpbp.vectors.dump=<path>} 手动运行一次，
 * 把 Java 参考实现的输出写入 {@code pacc-binary-protocol/test-vectors/interop.txt}。
 * 各语言运行时的测试读这个文件：能逐字节复现压缩输出、能解开参考帧，
 * 才算互操作成立——不然"多语言运行时行为不一致"就只是个风险条目。</p>
 *
 * <p>向量文件是生成物，不要手改：要变就改本类并重新导出，diff 里能看出协议行为的变化。</p>
 */
class PbpInteropVectorsTest {

    private static final String SECRET_TEXT = "000102030405060708090a0b0c0d0e0f";
    private static final long TS_MS = 1_700_000_000_000L;

    @Test
    void dumpInteropVectors() throws IOException {
        String dumpPath = System.getProperty("pbp.vectors.dump");
        Assumptions.assumeTrue(dumpPath != null,
                "未启用向量导出：用 -Dpbp.vectors.dump=<path> 运行");

        HexFormat hex = HexFormat.of();
        StringBuilder out = new StringBuilder();
        out.append("# PBP 跨语言互操作向量。由 runtime-java 的 PbpInteropVectorsTest 导出，勿手改。\n");
        out.append("# 每行 key = hex；空行与 # 注释忽略。所有多字节整数小端，VarInt 为 LEB128。\n");
        out.append("# HMAC 密钥是 secret_hex_text 这串文本的 UTF-8 字节（PACC 两侧的既有约定）。\n");
        out.append("\n");
        out.append("secret_hex_text = ").append(hex.formatHex(SECRET_TEXT.getBytes(StandardCharsets.UTF_8))).append('\n');

        // ---- 信封：未签名/已签名帧，帧头布局与 HMAC 覆盖面的锚点 ----
        PaccEnvelope envelope = PaccEnvelope.newBuilder()
                .setType("inspect_offer")
                .setTsMs(TS_MS)
                .setNonce("0123456789abcdef")
                .setSessionId("sess-1")
                .setPteid("PT0001")
                .setPayloadJson("{}")
                .setSigVersion(1)
                .build();
        byte[] payload = PbpCodec.payloadOf(envelope);
        byte[] unsigned = PbpCodec.frameOf(envelope, TS_MS).encode();
        byte[] signature = PbpCrypto.hmacSha256(SECRET_TEXT.getBytes(StandardCharsets.UTF_8),
                PbpCodec.frameOf(envelope, TS_MS).signingInput());
        byte[] signed = PbpCodec.frameOf(envelope, TS_MS).withSignature(signature).encode();
        out.append("envelope_ts_ms = ").append(hex.formatHex(longToBytes(TS_MS))).append('\n');
        out.append("envelope_payload = ").append(hex.formatHex(payload)).append('\n');
        out.append("envelope_frame = ").append(hex.formatHex(unsigned)).append('\n');
        out.append("envelope_signed_frame = ").append(hex.formatHex(signed)).append('\n');

        // ---- 编解码边界载荷：负数 ZigZag、UTF-8 多字节、浮点、集合、嵌套、可选 ----
        DetectionReport report = codecReport();
        out.append("codec_payload = ").append(hex.formatHex(PbpCodec.payloadOf(report))).append('\n');

        // ---- 压缩子集：多段不同形态的载荷，压缩输出必须逐字节可复现 ----
        appendZstd(out, hex, "zstd_repeat", repeatPayload());
        appendZstd(out, hex, "zstd_rle", rlePayload());
        appendZstd(out, hex, "zstd_ramp", rampPayload());
        appendZstd(out, hex, "zstd_noise", noisePayload());
        appendZstd(out, hex, "zstd_blocky", blockyPayload());
        appendZstd(out, hex, "zstd_mixed", mixedPayload());

        // ---- 大载荷消息：超阈值自动压缩的端到端锚点 ----
        PaccEnvelope big = PaccEnvelope.newBuilder()
                .setType("inspect_result")
                .setTsMs(TS_MS)
                .setNonce("0123456789abcdef")
                .setSessionId("sess-1")
                .setPteid("PT0001")
                .setPayloadJson("A".repeat(3000))
                .setSigVersion(1)
                .build();
        out.append("big_frame_compressed = ").append(hex.formatHex(big.toByteArray())).append('\n');

        // ---- 差分：msg1 完整帧 + msg2 差分帧 + msg2 的完整载荷 ----
        DetectionReport msg1 = statusReport(2_000L, 20, 50, 3.5f);
        DetectionReport msg2 = statusReport(2_001L, 24, 50, 4.5f);
        PbpDeltaChain<DetectionReport> chain = new PbpDeltaChain<>(DetectionReport.MESSAGE_ID,
                () -> DetectionReport.newBuilder().build());
        PbpFrame frame1 = chain.encode(msg1, 2_000L);
        PbpFrame frame2 = chain.encode(msg2, 2_001L);
        out.append("delta_frame1 = ").append(hex.formatHex(frame1.encode())).append('\n');
        out.append("delta_frame2 = ").append(hex.formatHex(frame2.encode())).append('\n');
        out.append("delta_payload2 = ").append(hex.formatHex(PbpCodec.payloadOf(msg2))).append('\n');

        out.append("\n");
        out.append("# 载荷生成规则（用不到提交明文，各语言按同一公式造数据）：\n");
        out.append("#   zstd_repeat  : 16384 字节，b[i] = \"pacc-pbp-zstd\"[i % 13]\n");
        out.append("#   zstd_rle     : 4096 字节，b[i] = 0x5A\n");
        out.append("#   zstd_ramp    : 4096 字节，b[i] = (i*i*31 + i*7 + 11) & 0xFF\n");
        out.append("#   zstd_noise   : 4096 字节，u32 xorshift：x=0x12345678；每次 b[i]=(x ^= x<<13, x ^= x>>>17, x ^= x<<5) & 0xFF\n");
        out.append("#   zstd_blocky  : 8192 字节，b[i] = (i % 37 < 20) ? (i & 0x0F) : ((i * 3) & 0xFF)\n");
        out.append("#   zstd_mixed   : 140000 字节，b[i] = (i*7 + 140000) & 0xFF（跨 128KB 块边界）\n");
        out.append("# big_frame_compressed：PaccEnvelope(type=inspect_result ts_ms=同一时间戳 nonce=0123456789abcdef\n");
        out.append("#   session_id=sess-1 pteid=PT0001 payload_json=\"A\"×3000 sig_version=1) 的 toByteArray()，\n");
        out.append("#   载荷超 1KB 触发自动压缩，帧头应带 FLAG_COMPRESSED。\n");
        out.append("# codec_payload 的字段（DetectionReport，见 PbpInteropVectorsTest#codecReport）：\n");
        out.append("#   pteid=PT0001 timestamp=-1700000000000 client_version=5.4.0-验证 platform=windows\n");
        out.append("#   events=[{event_type=2 confidence=0.75 timestamp=1700000000001\n");
        out.append("#            evidence={module:\"pacc-probe\"} detail=内存段校验不一致}]\n");
        out.append("#   apm={cpu_usage=23.5 memory_usage_kb=450000 fps=120.0\n");
        out.append("#        detection_latency_ms=12 active_rules=50 custom_metrics={gc_ms:3.5}}\n");
        out.append("#   signature=0x01..0x20\n");
        out.append("# delta 的两条消息见 PbpInteropVectorsTest#statusReport（msg2 只改了 timestamp 与 apm）。\n");

        Path target = Path.of(dumpPath);
        Files.createDirectories(target.getParent());
        Files.writeString(target, out.toString());
    }

    private static void appendZstd(StringBuilder out, HexFormat hex, String name, byte[] plain) {
        byte[] compressed = PbpZstd.compress(plain);
        out.append(name).append("_compressed = ").append(hex.formatHex(compressed)).append('\n');
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (v >>> (i * 8));
        }
        return b;
    }

    private static byte[] repeatPayload() {
        byte[] data = new byte[16_384];
        byte[] pattern = "pacc-pbp-zstd".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < data.length; i++) {
            data[i] = pattern[i % pattern.length];
        }
        return data;
    }

    private static byte[] rlePayload() {
        byte[] data = new byte[4096];
        java.util.Arrays.fill(data, (byte) 0x5A);
        return data;
    }

    private static byte[] rampPayload() {
        byte[] data = new byte[4096];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((i * i * 31 + i * 7 + 11) & 0xFF);
        }
        return data;
    }

    private static byte[] noisePayload() {
        byte[] data = new byte[4096];
        int x = 0x12345678;
        for (int i = 0; i < data.length; i++) {
            x ^= x << 13;
            x ^= x >>> 17;
            x ^= x << 5;
            data[i] = (byte) (x & 0xFF);
        }
        return data;
    }

    private static byte[] blockyPayload() {
        byte[] data = new byte[8192];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 37 < 20 ? (i & 0x0F) : ((i * 3) & 0xFF));
        }
        return data;
    }

    private static byte[] mixedPayload() {
        byte[] data = new byte[140_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((i * 7 + 140_000) & 0xFF);
        }
        return data;
    }

    private static DetectionReport codecReport() {
        byte[] signature = new byte[32];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) (i + 1);
        }
        Map<String, byte[]> evidence = new LinkedHashMap<>();
        evidence.put("module", "pacc-probe".getBytes(StandardCharsets.UTF_8));
        return DetectionReport.newBuilder()
                .setPteid("PT0001")
                .setTimestamp(-1_700_000_000_000L)
                .setClientVersion("5.4.0-验证")
                .setPlatform("windows")
                .addEvents(DetectionEvent.newBuilder()
                        .setEventType(2)
                        .setConfidence(0.75f)
                        .setTimestamp(1_700_000_000_001L)
                        .setEvidence(evidence)
                        .setDetail("内存段校验不一致")
                        .build())
                .setApm(ApmSnapshot.newBuilder()
                        .setCpuUsage(23.5f)
                        .setMemoryUsageKb(450_000)
                        .setFps(120.0f)
                        .setDetectionLatencyMs(12)
                        .setActiveRules(50)
                        .putCustomMetrics("gc_ms", 3.5f)
                        .build())
                .setSignature(signature)
                .build();
    }

    private static DetectionReport statusReport(long ts, int cpuPercent, int rules, float gcMs) {
        return DetectionReport.newBuilder()
                .setPteid("PT0001")
                .setTimestamp(ts)
                .setClientVersion("5.4.0")
                .setPlatform("windows")
                .addEvents(DetectionEvent.newBuilder()
                        .setEventType(2)
                        .setConfidence(0.87f)
                        .setTimestamp(900L)
                        .putEvidence("module", "pacc-probe".getBytes(StandardCharsets.UTF_8))
                        .setDetail("可疑进程")
                        .build())
                .setApm(ApmSnapshot.newBuilder()
                        .setCpuUsage(cpuPercent / 100.0f)
                        .setMemoryUsageKb(450_000)
                        .setFps(120.0f)
                        .setDetectionLatencyMs(12)
                        .setActiveRules(rules)
                        .putCustomMetrics("gc_ms", gcMs)
                        .build())
                .build();
    }
}