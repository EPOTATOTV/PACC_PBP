package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * X25519 测试，引用 <b>RFC 7748 §6.1</b> 的官方向量。
 *
 * <p>重点不只是"能协商出相同的密钥"（自家生成的两对密钥协商业然相同，证明不了互通），
 * 而是用 RFC 给出的固定私钥与公钥算出 RFC 给出的那个共享密钥。</p>
 */
class PbpX25519Test {

    private static final HexFormat HEX = HexFormat.of();

    // RFC 7748 §6.1
    private static final byte[] ALICE_PRIVATE = HEX.parseHex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static final byte[] ALICE_PUBLIC = HEX.parseHex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static final byte[] BOB_PRIVATE = HEX.parseHex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    private static final byte[] BOB_PUBLIC = HEX.parseHex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static final byte[] SHARED_SECRET = HEX.parseHex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    private static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    @Test
    void rfc7748SharedSecretFromAliceSide() {
        byte[] shared = PbpX25519.sharedSecret(
                PbpX25519.privateKeyFromBytes(ALICE_PRIVATE),
                BOB_PUBLIC);
        assertEquals(hex(SHARED_SECRET), hex(shared));
    }

    @Test
    void rfc7748SharedSecretFromBobSide() {
        // 两侧算出的必须一致，否则实际链路上会出现"一边能解密一边不能"
        byte[] shared = PbpX25519.sharedSecret(
                PbpX25519.privateKeyFromBytes(BOB_PRIVATE),
                ALICE_PUBLIC);
        assertEquals(hex(SHARED_SECRET), hex(shared));
    }

    @Test
    void publicKeyBytesUseLittleEndianRawFormat() {
        // RFC 的 32 字节公钥就是 u 坐标的小端编码；JDK 给的是 BigInteger，转换写错就跨语言不通
        assertEquals(hex(ALICE_PUBLIC), hex(PbpX25519.publicKeyBytes(PbpX25519.publicKeyFromBytes(ALICE_PUBLIC))));
        assertEquals(hex(BOB_PUBLIC), hex(PbpX25519.publicKeyBytes(PbpX25519.publicKeyFromBytes(BOB_PUBLIC))));
    }

    @Test
    void privateKeyBytesRoundTrip() {
        // provider 在 KeyAgreement 内部做 clamp，这里保留传入的原始标量，不做二次加工
        assertEquals(hex(ALICE_PRIVATE),
                hex(PbpX25519.privateKeyBytes(PbpX25519.privateKeyFromBytes(ALICE_PRIVATE))));
    }

    @Test
    void generatedKeyPairIsUsable() {
        KeyPair a = PbpX25519.generateKeyPair();
        KeyPair b = PbpX25519.generateKeyPair();

        assertEquals(PbpX25519.KEY_SIZE, PbpX25519.publicKeyBytes(a.getPublic()).length);
        assertEquals(PbpX25519.KEY_SIZE, PbpX25519.privateKeyBytes(a.getPrivate()).length);
        assertFalse(Arrays.equals(PbpX25519.publicKeyBytes(a.getPublic()), PbpX25519.publicKeyBytes(b.getPublic())));

        byte[] ab = PbpX25519.sharedSecret(a.getPrivate(), b.getPublic());
        byte[] ba = PbpX25519.sharedSecret(b.getPrivate(), a.getPublic());
        assertArrayEquals(ab, ba);
    }

    @Test
    void generatedPublicKeyCanBeParsedBack() {
        // 线上只传裸 32 字节，对端必须能把它还原成可用的公钥对象
        KeyPair pair = PbpX25519.generateKeyPair();
        byte[] raw = PbpX25519.publicKeyBytes(pair.getPublic());
        assertEquals(hex(raw), hex(PbpX25519.publicKeyBytes(PbpX25519.publicKeyFromBytes(raw))));
    }

    @Test
    void smallUCoordinatePadsToThirtyTwoBytes() {
        // u = 1 时 BigInteger 只给 1 个字节，线上格式必须补齐到 32 字节，否则对端解出来的不是同一把公钥
        byte[] raw = new byte[PbpX25519.KEY_SIZE];
        raw[0] = 1;
        assertEquals(hex(raw), hex(PbpX25519.publicKeyBytes(PbpX25519.publicKeyFromBytes(raw))));
    }

    @Test
    void uCoordinateAbovePIsReducedButStaysThirtyTwoBytes() {
        // RFC 7748 规定 u 按 mod p 解释，所以不小于 p 的输入会被规整（2^255-1 变成 18）。
        // 这里只锁住线上格式恒为 32 字节这个不变量，不去规定具体规整值——那是 provider 的职责。
        byte[] allOnes = new byte[PbpX25519.KEY_SIZE];
        Arrays.fill(allOnes, (byte) 0xFF);
        allOnes[PbpX25519.KEY_SIZE - 1] = 0x7F;
        byte[] normalized = PbpX25519.publicKeyBytes(PbpX25519.publicKeyFromBytes(allOnes));
        assertEquals(PbpX25519.KEY_SIZE, normalized.length);
        assertFalse(Arrays.equals(allOnes, normalized));
    }

    @Test
    void invalidKeyLengthRejected() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpX25519.publicKeyFromBytes(new byte[31])).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpX25519.privateKeyFromBytes(null)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpX25519.publicKeyFromBytes(new byte[33])).code());
    }

    @Test
    void foreignKeyTypeRejected() throws Exception {
        // 传进来一把非 X25519 的密钥时必须报错，而不是当成 32 字节凑合着用
        KeyPair ec = java.security.KeyPairGenerator.getInstance("EC").generateKeyPair();
        assertThrows(PbpException.class, () -> PbpX25519.publicKeyBytes(ec.getPublic()));
        assertThrows(PbpException.class, () -> PbpX25519.privateKeyBytes(ec.getPrivate()));
    }
}