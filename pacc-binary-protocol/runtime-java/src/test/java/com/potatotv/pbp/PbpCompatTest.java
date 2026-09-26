package com.potatotv.pbp;

import com.potatotv.pbp.gen.DetectionReport;
import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 版本兼容测试（设计文档 §3.11，验收项 B08）。
 *
 * <p>两个方向都要能跑通：</p>
 * <ul>
 *   <li>向后兼容（旧端 → 新端）：旧端载荷缺末尾字段，新端解码取默认值；</li>
 *   <li>向前兼容（新端 → 旧端）：新端在末尾追加字段，旧端读完自己的字段后忽略未知尾巴。</li>
 * </ul>
 *
 * <p>帧头版本字段按"支持区间"解析：{@code [MIN_VERSION, VERSION]} 内的版本都接受，
 * 超出区间区分"过旧/过新"报错，为 §3.11.3 的双版本过渡留出落点。</p>
 */
class PbpCompatTest {

    /** 模拟旧端（schema 还没有 sig_version 字段）压出的信封载荷。 */
    private static byte[] legacyEnvelopePayload() {
        PbpEncoder enc = new PbpEncoder(64);
        enc.writeString("inspect_offer");
        enc.writeInt64(1_700_000_000_000L);
        enc.writeString("nonce-1");
        enc.writeString("sess-1");
        enc.writeString("PT0001");
        enc.writeString("{}");
        return enc.toByteArray();
    }

    @Test
    void newReaderAcceptsPayloadMissingTrailingField() {
        byte[] payload = legacyEnvelopePayload();
        byte[] raw = PbpFrame.of(PaccEnvelope.MESSAGE_ID, 1_700_000_000_000L, payload).encode();

        PaccEnvelope envelope = PaccEnvelope.parseFrom(raw);
        assertEquals("inspect_offer", envelope.getType());
        assertEquals("sess-1", envelope.getSessionId());
        assertEquals("PT0001", envelope.getPteid());
        assertEquals(0, envelope.getSigVersion(), "旧端没发末尾字段，新端要取默认值而不是报错");
    }

    @Test
    void newReaderAcceptsPayloadMissingTrailingBytesField() {
        // DetectionReport 的末尾字段是 bytes signature：缺省时默认空数组
        PbpEncoder enc = new PbpEncoder(64);
        enc.writeString("PT0001");
        enc.writeInt64(1_700_000_000_000L);
        enc.writeString("5.4.0");
        enc.writeString("windows");
        enc.writeMessageList(new ArrayList<>());   // 空的事件列表
        enc.writePresence(false);                  // 可空 apm 不存在
        byte[] payload = enc.toByteArray();
        byte[] raw = PbpFrame.of(DetectionReport.MESSAGE_ID, 1_700_000_000_000L, payload).encode();

        DetectionReport report = DetectionReport.parseFrom(raw);
        assertEquals("PT0001", report.getPteid());
        assertEquals(0, report.getSignature().length);
    }

    @Test
    void oldReaderIgnoresUnknownAppendedField() {
        PaccEnvelope known = PaccEnvelope.newBuilder()
                .setType("inspect_offer")
                .setTsMs(1_700_000_000_000L)
                .setNonce("nonce-1")
                .setSessionId("sess-1")
                .setPteid("PT0001")
                .setPayloadJson("{}")
                .setSigVersion(1)
                .build();
        byte[] payload = PbpCodec.payloadOf(known);

        // 新端追加的第 8 个字段：一段合法编码的尾巴
        PbpEncoder extra = new PbpEncoder(48);
        extra.writeString("field-added-by-a-newer-client");
        byte[] extraBytes = extra.toByteArray();
        byte[] extended = Arrays.copyOf(payload, payload.length + extraBytes.length);
        System.arraycopy(extraBytes, 0, extended, payload.length, extraBytes.length);

        PbpDecoder dec = new PbpDecoder(extended);
        PaccEnvelope envelope = PaccEnvelope.newBuilder().build();
        envelope.decode(dec);

        assertEquals("inspect_offer", envelope.getType());
        assertEquals(1, envelope.getSigVersion());
        assertTrue(dec.hasRemaining(), "旧端读到自己认识的字段后应把未知尾巴留下（忽略即可）");
    }

    @Test
    void frameVersionRangeAcceptsCurrentRejectsOutOfRange() {
        byte[] raw = PbpFrame.of(0x2001, 0L, new byte[]{0x00}).encode();
        assertEquals(PbpFrame.VERSION, PbpFrame.parse(raw).version());
        assertEquals(PbpFrame.MIN_VERSION, PbpFrame.VERSION, "当前实现同时是区间下界，双版本过渡时才会拉开");

        raw[2] = (byte) (PbpFrame.VERSION + 1);
        assertEquals(PbpException.Code.BAD_VERSION,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code(),
                "新于支持区间的版本要显式失败，而不是按 v1 猜着解析");

        raw[2] = (byte) (PbpFrame.MIN_VERSION - 1);
        assertEquals(PbpException.Code.BAD_VERSION,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code());
    }

    /** 新端追加字段后，旧的"读法"（只读已知字段）仍然拿到全部已知值。 */
    @Test
    void appendedFieldDoesNotShiftExistingFields() {
        PaccEnvelope original = PaccEnvelope.newBuilder()
                .setType("session_ready")
                .setTsMs(1_700_000_000_123L)
                .setNonce("n-1")
                .setSessionId("s-1")
                .setPteid("PT0009")
                .setPayloadJson("{\"keyId\":\"k\"}")
                .setSigVersion(2)
                .build();
        byte[] payload = PbpCodec.payloadOf(original);

        byte[] truncated = new byte[payload.length - 1];
        System.arraycopy(payload, 0, truncated, 0, truncated.length);
        PbpDecoder dec = new PbpDecoder(truncated);
        PaccEnvelope envelope = PaccEnvelope.newBuilder().build();
        envelope.decode(dec);

        assertEquals(original.getPayloadJson(), envelope.getPayloadJson());
        assertEquals(0, envelope.getSigVersion(), "被截掉的正是末尾字段，取值应回落到默认");
        assertFalse(dec.hasRemaining());
        assertArrayEquals(new byte[0], envelope.signatureBytes());
    }
}