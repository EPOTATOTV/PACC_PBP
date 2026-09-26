package com.potatotv.pbp;

import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 生成类 {@link PaccEnvelope} 的编解码测试。
 *
 * <p>这一层测的是「MDL 生成物」而不是手写代码：字段顺序、类型宽度、帧尾签名的挂载方式
 * 全部由 {@code mdl/pacc_wire.mdl} 决定，所以这里同时是生成器输出的回归测试。
 * 信封语义（时间戳窗口、nonce 去重、会话密钥）由后端的 PaccWireCodec 测试覆盖。</p>
 */
class PaccEnvelopeCodecTest {

    private static final byte[] KEY = "envelope-test-key".getBytes(StandardCharsets.UTF_8);

    private static PaccEnvelope sample() {
        return PaccEnvelope.newBuilder()
                .setType("inspect_offer")
                .setTsMs(1_700_000_000_000L)
                .setNonce("nonce-0001")
                .setSessionId("sid-1")
                .setPteid("PT0001")
                .setPayloadJson("{\"os\":\"win\"}")
                .setSigVersion(1)
                .build();
    }

    @Test
    void messageIdComesFromMdl() {
        assertEquals(0x2001, PaccEnvelope.MESSAGE_ID);
        assertEquals(0x2001, sample().messageId());
    }

    @Test
    void roundTripKeepsEveryField() {
        PaccEnvelope parsed = PaccEnvelope.parseFrom(sample().toByteArray());
        assertEquals("inspect_offer", parsed.getType());
        assertEquals(1_700_000_000_000L, parsed.getTsMs());
        assertEquals("nonce-0001", parsed.getNonce());
        assertEquals("sid-1", parsed.getSessionId());
        assertEquals("PT0001", parsed.getPteid());
        assertEquals("{\"os\":\"win\"}", parsed.getPayloadJson());
        assertEquals(1, parsed.getSigVersion());
        assertEquals("", parsed.getSignature());
        assertEquals(0, parsed.signatureBytes().length);
    }

    @Test
    void nullStringsFallBackToEmpty() {
        PaccEnvelope envelope = PaccEnvelope.newBuilder()
                .setType(null)
                .setNonce(null)
                .setPteid(null)
                .setPayloadJson(null)
                .build();
        assertEquals("", envelope.getType());
        assertEquals("", envelope.getNonce());
        assertEquals("", envelope.getPteid());
        assertEquals("", envelope.getPayloadJson());
    }

    @Test
    void unsignedFrameHasNoTrailer() {
        PaccEnvelope envelope = sample();
        byte[] raw = envelope.toByteArray();
        PbpFrame frame = PbpFrame.parse(raw);
        assertEquals(PbpFrame.HEADER_SIZE + envelope.encodedSize(), raw.length);
        assertTrue(!frame.signed());
        // 帧头时间戳镜像 MDL 里的 ts_ms
        assertEquals(envelope.getTsMs(), frame.timestampMs());
        assertEquals(0, frame.signature().length);
    }

    @Test
    void signedFrameCarriesThirtyTwoByteTrailer() {
        PaccEnvelope unsigned = sample();
        byte[] sig = PbpCrypto.hmacSha256(KEY, unsigned.signingInput());
        PaccEnvelope signed = unsigned.toBuilder().setSignatureBytes(sig).build();

        byte[] raw = signed.toByteArray();
        PbpFrame frame = PbpFrame.parse(raw);
        assertEquals(PbpFrame.HEADER_SIZE + unsigned.encodedSize() + PbpFrame.SIGNATURE_SIZE, raw.length);
        assertTrue(frame.signed());
        assertArrayEquals(sig, frame.signature());
        assertEquals(HexFormat.of().formatHex(sig), signed.getSignature());
    }

    /** 签名方与验签方必须拿到同一串待签字节，否则线上会整体验签失败。 */
    @Test
    void signingInputSurvivesFrameRoundTrip() {
        PaccEnvelope unsigned = sample();
        byte[] sig = PbpCrypto.hmacSha256(KEY, unsigned.signingInput());

        PaccEnvelope parsed = PaccEnvelope.parseFrom(unsigned.toBuilder().setSignatureBytes(sig).build().toByteArray());
        assertArrayEquals(unsigned.signingInput(), parsed.signingInput());
        byte[] expected = PbpCrypto.hmacSha256(KEY, parsed.signingInput());
        assertArrayEquals(expected, parsed.signatureBytes());
        assertTrue(PbpCrypto.verifyHmac(KEY, parsed.signingInput(), parsed.signatureBytes()));
    }

    /** 待签字节必须覆盖帧头：只盖载荷等于允许中间人改消息 ID 与时间戳。 */
    @Test
    void signingInputCoversFrameHeader() {
        PaccEnvelope first = PaccEnvelope.newBuilder().setType("ping").setTsMs(1L).build();
        PaccEnvelope second = first.toBuilder().setTsMs(2L).build();
        assertTrue(!Arrays.equals(first.signingInput(), second.signingInput()));
        assertEquals(PbpFrame.HEADER_SIZE + first.encodedSize(), first.signingInput().length);
    }

    @Test
    void hexSignatureRoundTrips() {
        byte[] sig = PbpCrypto.hmacSha256(KEY, sample().signingInput());
        PaccEnvelope signed = sample().toBuilder().setSignature(HexFormat.of().formatHex(sig)).build();
        assertEquals(HexFormat.of().formatHex(sig), signed.getSignature());
        assertArrayEquals(sig, signed.signatureBytes());

        PaccEnvelope cleared = signed.toBuilder().setSignature("").build();
        assertEquals("", cleared.getSignature());
    }

    @Test
    void misSizedSignatureIsRejected() {
        PaccEnvelope broken = sample().toBuilder().setSignatureBytes(new byte[5]).build();
        PbpException error = assertThrows(PbpException.class, broken::toByteArray);
        assertEquals(PbpException.Code.BAD_LENGTH, error.code());
    }

    @Test
    void invalidHexSignatureIsRejected() {
        PbpException error = assertThrows(PbpException.class,
                () -> sample().toBuilder().setSignature("zz").build());
        assertEquals(PbpException.Code.BAD_FORMAT, error.code());
    }

    @Test
    void parseFromRejectsForeignMessageId() {
        byte[] payload = sample().toByteArray();
        PbpFrame other = PbpFrame.of(0x1001, 0L, Arrays.copyOfRange(payload, PbpFrame.HEADER_SIZE, payload.length));
        PbpException error = assertThrows(PbpException.class, () -> PaccEnvelope.parseFrom(other.encode()));
        assertEquals(PbpException.Code.BAD_FORMAT, error.code());
    }

    @Test
    void parseFromRejectsBadMagic() {
        byte[] raw = sample().toByteArray();
        raw[0] = 'X';
        PbpException error = assertThrows(PbpException.class, () -> PaccEnvelope.parseFrom(raw));
        assertEquals(PbpException.Code.BAD_MAGIC, error.code());
    }

    /** 向前兼容：新端在末尾追加字段时，旧端读完已知字段即可，尾巴不再消费。 */
    @Test
    void trailingPayloadBytesAreIgnored() {
        PbpEncoder enc = new PbpEncoder();
        sample().encode(enc);
        byte[] extended = Arrays.copyOf(enc.toByteArray(), enc.size() + 3);

        PaccEnvelope parsed = PaccEnvelope.parseFrom(
                PbpFrame.of(PaccEnvelope.MESSAGE_ID, 1_700_000_000_000L, extended).encode());
        assertEquals("inspect_offer", parsed.getType());
        assertEquals("PT0001", parsed.getPteid());
        assertEquals(1, parsed.getSigVersion());
    }

    @Test
    void encodedSizeMatchesActualPayload() {
        PaccEnvelope envelope = sample();
        assertEquals(envelope.encodedSize(), PbpFrame.parse(envelope.toByteArray()).payload().length);
        // 空信封仍要写下 5 个空串的长度前缀、1 字节 int64 的 0、1 字节 uint8 的 0
        assertEquals(7, PaccEnvelope.newBuilder().build().encodedSize());
    }

    @Test
    void toStringShowsFieldNames() {
        String text = sample().toString();
        assertTrue(text.contains("type=inspect_offer"));
        assertTrue(text.contains("pteid=PT0001"));
    }
}