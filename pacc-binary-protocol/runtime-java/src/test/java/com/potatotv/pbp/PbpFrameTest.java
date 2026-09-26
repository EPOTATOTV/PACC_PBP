package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 帧布局、边界与签名覆盖面测试。 */
class PbpFrameTest {

    private static final byte[] PAYLOAD = {1, 2, 3, 4, 5};
    private static final byte[] HMAC_KEY = "frame-test-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void headerLayoutIsLittleEndian() {
        PbpFrame frame = new PbpFrame(PbpFrame.VERSION, 0, 0x2001, 0x0A0B0C0D,
                0x1122334455667788L, 0x0102030405060708L, new byte[0], null);
        // 逐字段锁定偏移与字节序：这段 hex 就是跨语言实现的契约
        assertEquals("5042"      // Magic "PB"
                + "01"           // Version
                + "00"           // Flags
                + "0120"         // MessageID 0x2001
                + "0d0c0b0a"     // Sequence
                + "8877665544332211"  // Timestamp
                + "0807060504030201"  // SessionID
                + "00000000",    // PayloadLen
                hex(frame.encode()));
        assertEquals(PbpFrame.HEADER_SIZE * 2, hex(frame.encode()).length());
    }

    @Test
    void roundTripUnsignedFrame() {
        PbpFrame frame = PbpFrame.of(0x2001, 1_700_000_000_000L, PAYLOAD);
        byte[] raw = frame.encode();
        assertEquals(PbpFrame.HEADER_SIZE + PAYLOAD.length, raw.length);

        PbpFrame parsed = PbpFrame.parse(raw);
        assertEquals(frame, parsed);
        assertFalse(parsed.signed());
        assertArrayEquals(PAYLOAD, parsed.payload());
        assertEquals(PbpFrame.VERSION, parsed.version());
        assertEquals(0x2001, parsed.messageId());
        assertEquals(1_700_000_000_000L, parsed.timestampMs());
        assertEquals(PAYLOAD.length, parsed.payloadLength());
    }

    @Test
    void emptyPayloadIsMinimalFrame() {
        PbpFrame frame = PbpFrame.of(0x0003, 0L, new byte[0]);
        byte[] raw = frame.encode();
        assertEquals(PbpFrame.HEADER_SIZE, raw.length);
        assertArrayEquals(new byte[0], PbpFrame.parse(raw).payload());
    }

    @Test
    void nullPayloadTreatedAsEmpty() {
        PbpFrame frame = new PbpFrame(PbpFrame.VERSION, 0, 1, 0, 0L, 0L, null, null);
        assertEquals(0, frame.payloadLength());
        assertEquals(PbpFrame.HEADER_SIZE, frame.encode().length);
    }

    @Test
    void badMagicRejected() {
        byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
        raw[0] = 0x00;
        assertEquals(PbpException.Code.BAD_MAGIC,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code());
    }

    @Test
    void unknownVersionRejected() {
        byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
        raw[2] = 2;
        assertEquals(PbpException.Code.BAD_VERSION,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code());
    }

    @Test
    void truncatedFrameRejected() {
        assertEquals(PbpException.Code.TRUNCATED,
                assertThrows(PbpException.class, () -> PbpFrame.parse(null)).code());
        assertEquals(PbpException.Code.TRUNCATED,
                assertThrows(PbpException.class, () -> PbpFrame.parse(new byte[PbpFrame.HEADER_SIZE - 1])).code());
    }

    @Test
    void payloadLenMustMatchActualBytes() {
        byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
        raw[26] = (byte) (raw[26] + 1);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code());
    }

    @Test
    void trailingBytesRejected() {
        // 帧尾多出未声明在 PayloadLen 里的字节：宁可失败也不默默忽略
        byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
        byte[] withTail = Arrays.copyOf(raw, raw.length + 1);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> PbpFrame.parse(withTail)).code());
    }

    @Test
    void oversizedPayloadLenRejectedBeforeAllocating() {
        byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
        Arrays.fill(raw, 26, 30, (byte) 0xFF);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code());
    }

    @Test
    void unimplementedFlagsRejected() {
        // 压缩 / 差分已经落地，置位是合法的；加密与保留位仍然拒绝
        int[] flags = {PbpFrame.FLAG_ENCRYPTED, 0x10};
        for (int flag : flags) {
            byte[] raw = PbpFrame.of(0x2001, 0L, PAYLOAD).encode();
            raw[3] = (byte) flag;
            assertEquals(PbpException.Code.UNSUPPORTED_FLAG,
                    assertThrows(PbpException.class, () -> PbpFrame.parse(raw)).code(),
                    "标志位 0x" + Integer.toHexString(flag) + " 应当被拒绝");
        }
        for (int flag : new int[]{PbpFrame.FLAG_COMPRESSED, PbpFrame.FLAG_DELTA}) {
            PbpFrame parsed = PbpFrame.parse(PbpFrame.of(0x2001, 0L, PAYLOAD).withFlag(flag).encode());
            assertEquals(flag, parsed.flags() & flag);
        }
    }

    @Test
    void unimplementedFlagsCannotBeEncodedEither() {
        PbpFrame frame = new PbpFrame(PbpFrame.VERSION, PbpFrame.FLAG_ENCRYPTED, 0x2001, 0, 0L, 0L, PAYLOAD, null);
        assertEquals(PbpException.Code.UNSUPPORTED_FLAG,
                assertThrows(PbpException.class, frame::encode).code());
    }

    @Test
    void signatureCoversHeaderAndPayload() {
        PbpFrame frame = PbpFrame.of(0x2001, 12345L, PAYLOAD);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(HMAC_KEY, frame.signingInput()));
        assertTrue(signed.signed());

        byte[] raw = signed.encode();
        assertEquals(PbpFrame.HEADER_SIZE + PAYLOAD.length + PbpFrame.SIGNATURE_SIZE, raw.length);

        PbpFrame parsed = PbpFrame.parse(raw);
        assertTrue(PbpCrypto.verifyHmac(HMAC_KEY, parsed.signingInput(), parsed.signature()));
    }

    @Test
    void signingInputUnaffectedBySignaturePresence() {
        // 签名与验签必须对同一串字节做 HMAC：未签名帧先算 signingInput，签完再算必须一模一样
        PbpFrame frame = PbpFrame.of(0x2001, 12345L, PAYLOAD);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(HMAC_KEY, frame.signingInput()));
        assertArrayEquals(frame.signingInput(), signed.signingInput());
    }

    @Test
    void tamperedPayloadBreaksSignature() {
        PbpFrame frame = PbpFrame.of(0x2001, 12345L, PAYLOAD);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(HMAC_KEY, frame.signingInput()));
        byte[] raw = signed.encode();
        raw[PbpFrame.HEADER_SIZE] ^= 0x01;

        PbpFrame parsed = PbpFrame.parse(raw);
        assertFalse(PbpCrypto.verifyHmac(HMAC_KEY, parsed.signingInput(), parsed.signature()));
    }

    @Test
    void tamperedHeaderBreaksSignature() {
        // 签名若只盖载荷，改时间戳/会话 ID 就能蒙混过关——这条用例专门盯住这点
        PbpFrame frame = PbpFrame.of(0x2001, 12345L, PAYLOAD);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(HMAC_KEY, frame.signingInput()));
        byte[] raw = signed.encode();
        raw[10] ^= 0x01;

        PbpFrame parsed = PbpFrame.parse(raw);
        assertFalse(PbpCrypto.verifyHmac(HMAC_KEY, parsed.signingInput(), parsed.signature()));
    }

    @Test
    void signatureLengthValidated() {
        PbpFrame frame = PbpFrame.of(0x2001, 0L, PAYLOAD);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> frame.withSignature(null)).code());
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> frame.withSignature(new byte[16])).code());
    }

    @Test
    void signedFlagWithoutSignatureRejected() {
        PbpFrame frame = new PbpFrame(PbpFrame.VERSION, PbpFrame.FLAG_SIGNED, 0x2001, 0, 0L, 0L, PAYLOAD, null);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, frame::encode).code());
    }

    @Test
    void signatureBytesWithoutFlagRejected() {
        PbpFrame frame = new PbpFrame(PbpFrame.VERSION, 0, 0x2001, 0, 0L, 0L, PAYLOAD, new byte[PbpFrame.SIGNATURE_SIZE]);
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, frame::encode).code());
    }

    @Test
    void payloadIsDefensivelyCopied() {
        byte[] payload = PAYLOAD.clone();
        PbpFrame frame = PbpFrame.of(0x2001, 0L, payload);
        payload[0] = 99;
        assertEquals(PAYLOAD[0], frame.payload()[0], "构造后修改入参不应影响帧内容");
    }
}