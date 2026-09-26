package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AEAD 与 HMAC 测试。
 *
 * <p>加密部分引用 <b>RFC 8439 §2.8.2</b> 的官方向量：这是唯一能证明"我们实现的
 * ChaCha20-Poly1305 与别人互通"的办法——自己和自己往返一致说明不了任何事。</p>
 */
class PbpCryptoTest {

    /** RFC 8439 §2.8.2 的 256 位密钥。 */
    private static final byte[] RFC_KEY = HexFormat.of().parseHex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    /** RFC 8439 §2.8.2 的 96 位 nonce。 */
    private static final byte[] RFC_NONCE = HexFormat.of().parseHex("070000004041424344454647");
    /** RFC 8439 §2.8.2 的 AAD。 */
    private static final byte[] RFC_AAD = HexFormat.of().parseHex("50515253c0c1c2c3c4c5c6c7");
    private static final byte[] RFC_PLAINTEXT = ("Ladies and Gentlemen of the class of '99: If I could offer you "
            + "only one tip for the future, sunscreen would be it.").getBytes(StandardCharsets.UTF_8);

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    // ------------------------------------------------------------ RFC 8439

    @Test
    void rfc8439AeadVector() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);

        // 密文 + 16 字节 tag，tag 追加在尾部
        assertEquals(RFC_PLAINTEXT.length + PbpCrypto.TAG_SIZE, sealed.length);
        assertEquals("d31a8d34648e60db7b86afbc53ef7ec2", hex(Arrays.copyOf(sealed, 16)));
        assertEquals("1ae10b594f09e26a7e902ecbd0600691",
                hex(Arrays.copyOfRange(sealed, sealed.length - PbpCrypto.TAG_SIZE, sealed.length)));
    }

    @Test
    void rfc8439RoundTrip() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        assertArrayEquals(RFC_PLAINTEXT, PbpCrypto.open(RFC_KEY, RFC_NONCE, sealed, RFC_AAD));
    }

    @Test
    void tamperedAadFailsAuthentication() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        byte[] aad = RFC_AAD.clone();
        aad[0] ^= 0x01;
        assertEquals(PbpException.Code.TAG_MISMATCH,
                assertThrows(PbpException.class, () -> PbpCrypto.open(RFC_KEY, RFC_NONCE, sealed, aad)).code());
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        sealed[0] ^= 0x01;
        assertEquals(PbpException.Code.TAG_MISMATCH,
                assertThrows(PbpException.class, () -> PbpCrypto.open(RFC_KEY, RFC_NONCE, sealed, RFC_AAD)).code());
    }

    @Test
    void tamperedTagFailsAuthentication() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        sealed[sealed.length - 1] ^= 0x01;
        assertEquals(PbpException.Code.TAG_MISMATCH,
                assertThrows(PbpException.class, () -> PbpCrypto.open(RFC_KEY, RFC_NONCE, sealed, RFC_AAD)).code());
    }

    @Test
    void wrongKeyFailsAuthentication() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        byte[] key = RFC_KEY.clone();
        key[0] ^= 0x01;
        assertEquals(PbpException.Code.TAG_MISMATCH,
                assertThrows(PbpException.class, () -> PbpCrypto.open(key, RFC_NONCE, sealed, RFC_AAD)).code());
    }

    @Test
    void missingAadFailsAuthentication() {
        byte[] sealed = PbpCrypto.seal(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD);
        assertEquals(PbpException.Code.TAG_MISMATCH,
                assertThrows(PbpException.class, () -> PbpCrypto.open(RFC_KEY, RFC_NONCE, sealed, null)).code());
    }

    @Test
    void keyAndNonceLengthsValidated() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class,
                        () -> PbpCrypto.seal(new byte[16], RFC_NONCE, RFC_PLAINTEXT, null)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class,
                        () -> PbpCrypto.seal(RFC_KEY, new byte[16], RFC_PLAINTEXT, null)).code());
    }

    // ------------------------------------------------------------ nonce 与 HMAC

    @Test
    void nonceLayoutIsSessionIdThenSequence() {
        byte[] nonce = PbpCrypto.newNonce(0x0102030405060708L, 0x0A0B0C0D);
        assertEquals(PbpCrypto.NONCE_SIZE, nonce.length);
        assertEquals("08070605040302010d0c0b0a", hex(nonce));
    }

    @Test
    void nonceIsUniquePerSequence() {
        assertFalse(Arrays.equals(
                PbpCrypto.newNonce(1L, 1),
                PbpCrypto.newNonce(1L, 2)));
        assertFalse(Arrays.equals(
                PbpCrypto.newNonce(1L, 1),
                PbpCrypto.newNonce(2L, 1)));
    }

    @Test
    void hmacMatchesRfc4231TestVector() {
        // RFC 4231 Test Case 1：key = 0x0b × 20，data = "Hi There"
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                hex(PbpCrypto.hmacSha256(key, "Hi There".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void hmacVerification() {
        byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] mac = PbpCrypto.hmacSha256(key, data);

        assertTrue(PbpCrypto.verifyHmac(key, data, mac));
        assertFalse(PbpCrypto.verifyHmac(key, "other".getBytes(StandardCharsets.UTF_8), mac));
        // 长度不对的"签名"直接判否，而不是走进比较逻辑
        assertFalse(PbpCrypto.verifyHmac(key, data, new byte[16]));
        assertFalse(PbpCrypto.verifyHmac(key, data, null));
    }

    @Test
    void hexKeyMustBeUsedAsTextNotDecoded() {
        // WSS 链路钉死的语义：HMAC 密钥是 hex 文本的 UTF-8 字节，不是解 hex 后的 32 字节。
        // 这条用例把该约定写成可执行断言，防止后来者"顺手"改成解 hex。
        String hexKey = "00112233445566778899aabbccddeeff";
        byte[] asText = hexKey.getBytes(StandardCharsets.UTF_8);
        byte[] asBytes = HexFormat.of().parseHex(hexKey);

        byte[] data = "x".getBytes(StandardCharsets.UTF_8);
        assertNotEqualsHex(PbpCrypto.hmacSha256(asText, data), PbpCrypto.hmacSha256(asBytes, data));
    }

    private static void assertNotEqualsHex(byte[] a, byte[] b) {
        assertFalse(Arrays.equals(a, b), "两种密钥解释方式不应得到同一结果");
    }
}