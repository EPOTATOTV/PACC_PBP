package com.potatotv.pbp;

import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 多语言实现的契约锚点。
 *
 * <p>这里锁的是一整帧字节：帧头逐字段偏移、载荷的 VarInt/UTF-8 编码、HMAC 覆盖面，
 * 三样任一被改动都会让这段 hex 变掉。Phase 2 的其它语言实现（Rust/Go/TS）只要拿
 * 同一组入参算出同一段 hex，就算对齐。</p>
 *
 * <p>入参刻意选成短且无多字节字符的字符串，方便人工在 hex 里核对每个长度前缀。</p>
 */
class PbpGoldenVectorTest {

    /** 两侧线上用的十六进制密钥字符串，HMAC 的 key 取它的 UTF-8 字节。 */
    private static final String SECRET = "000102030405060708090a0b0c0d0e0f";

    private static final long TS_MS = 1_700_000_000_000L;

    /** 载荷 hex，三段测试共用。 */
    private static final String PAYLOAD_HEX = "0d696e73706563745f6f66666572"
            + "80a0abfef962"
            + "1030313233343536373839616263646566"
            + "06736573732d31"
            + "06505430303031"
            + "027b7d"
            + "01";

    private static final String HEADER_UNSIGNED_HEX = "5042"
            + "01"
            + "00"
            + "0120"
            + "00000000"
            + "0068e5cf8b010000"
            + "0000000000000000"
            + "37000000";

    private static PaccEnvelope sample() {
        return PaccEnvelope.newBuilder()
            .setType("inspect_offer")
            .setTsMs(TS_MS)
            .setNonce("0123456789abcdef")
            .setSessionId("sess-1")
            .setPteid("PT0001")
            .setPayloadJson("{}")
            .setSigVersion(1)
            .build();
    }

    /** 字段按编号升序、无标签；字符串是 VarInt 长度前缀 + UTF-8，int64 是 ZigZag + VarInt。 */
    @Test
    void payloadBytesAreStable() {
        PaccEnvelope envelope = sample();
        assertEquals(PAYLOAD_HEX, hex(PbpFrame.parse(envelope.toByteArray()).payload()));
        assertEquals(55, envelope.encodedSize());
    }

    /** 帧头 30 字节 + 载荷；未签名时帧尾不带 32 字节。 */
    @Test
    void unsignedFrameBytesAreStable() {
        PaccEnvelope envelope = sample();
        assertEquals(HEADER_UNSIGNED_HEX + PAYLOAD_HEX, hex(envelope.toByteArray()));
        assertEquals(PbpFrame.HEADER_SIZE + envelope.encodedSize(), envelope.toByteArray().length);
    }

    /** 签名覆盖「帧头（FLAG_SIGNED 已置位）+ 载荷」，这段 HMAC 就是两端的验签依据。 */
    @Test
    void signedFrameBytesAreStable() {
        PaccEnvelope envelope = sample();
        byte[] signature = PbpCrypto.hmacSha256(
            SECRET.getBytes(StandardCharsets.UTF_8), envelope.signingInput());
        assertEquals("f3ae51a23a95c9c26b762839e39b493f5b74f3226f58ad28c55464b0266881e0", hex(signature));

        // 签名前后 signingInput 必须是同一串字节，否则签名方与验签方永远对不上
        PaccEnvelope signed = envelope.toBuilder().setSignatureBytes(signature).build();
        assertArrayEquals(envelope.signingInput(), signed.signingInput());

        assertEquals("5042"
                + "01"
                + "08"                       // Flags：仅 FLAG_SIGNED
                + "0120"
                + "00000000"
                + "0068e5cf8b010000"
                + "0000000000000000"
                + "37000000"
                + PAYLOAD_HEX
                + hex(signature),
                hex(signed.toByteArray()));
        assertTrue(signed.toByteArray().length > envelope.toByteArray().length);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }
}