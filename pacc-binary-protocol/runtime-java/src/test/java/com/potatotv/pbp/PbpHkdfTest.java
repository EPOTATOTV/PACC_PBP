package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * HKDF-SHA256 测试，引用 <b>RFC 5869 Test Case 1 / 2 / 3</b>。
 *
 * <p>JDK 21 没有 HKDF API，实现是自己写的，所以必须逐字节对官方向量；
 * "我们能解出自己能读的密钥"这种事完全不能证明实现正确。</p>
 */
class PbpHkdfTest {

    private static final HexFormat HEX = HexFormat.of();

    private static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    /** 生成 [from, to] 闭区间内的连续字节，RFC 5869 Test Case 2 用它构造长输入。 */
    private static byte[] range(int from, int to) {
        byte[] out = new byte[to - from + 1];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (from + i);
        }
        return out;
    }

    private static byte[] repeated(int value, int count) {
        byte[] out = new byte[count];
        Arrays.fill(out, (byte) value);
        return out;
    }

    // ------------------------------------------------------------ RFC 5869

    @Test
    void rfc5869TestCase1() {
        byte[] ikm = repeated(0x0b, 22);
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");

        assertEquals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                hex(PbpHkdf.extract(salt, ikm)));
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865",
                hex(PbpHkdf.derive(ikm, salt, info, 42)));
    }

    @Test
    void rfc5869TestCase2() {
        byte[] ikm = range(0x00, 0x4f);
        byte[] salt = range(0x60, 0xaf);
        byte[] info = range(0xb0, 0xff);

        assertEquals("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                hex(PbpHkdf.extract(salt, ikm)));
        assertEquals("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                        + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                        + "cc30c58179ec3e87c14c01d5c1f3434f1d87",
                hex(PbpHkdf.derive(ikm, salt, info, 82)));
    }

    @Test
    void rfc5869TestCase3() {
        // salt 与 info 都为空：salt 退化成 32 个零字节，info 直接不参与
        byte[] ikm = repeated(0x0b, 22);
        assertEquals("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                hex(PbpHkdf.extract(null, ikm)));
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8",
                hex(PbpHkdf.derive(ikm, null, null, 42)));
    }

    // ------------------------------------------------------------ 语义

    @Test
    void emptySaltEqualsZeroSalt() {
        byte[] ikm = repeated(0x0b, 22);
        assertEquals(hex(PbpHkdf.extract(null, ikm)), hex(PbpHkdf.extract(new byte[0], ikm)));
    }

    @Test
    void emptyInfoEqualsNullInfo() {
        byte[] ikm = repeated(0x0b, 22);
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        assertEquals(hex(PbpHkdf.derive(ikm, salt, null, 32)),
                hex(PbpHkdf.derive(ikm, salt, new byte[0], 32)));
    }

    @Test
    void infoGivesDomainSeparation() {
        // 同一份输入密钥材料 + 不同 info → 两把互不相关的密钥。
        // 这是"加密密钥与签名密钥可以共用一次协商结果"的前提。
        byte[] ikm = repeated(0x42, 32);
        byte[] salt = "pacc-session".getBytes(StandardCharsets.UTF_8);
        byte[] aes = PbpHkdf.derive(ikm, salt, "aes-key".getBytes(StandardCharsets.UTF_8));
        byte[] mac = PbpHkdf.derive(ikm, salt, "mac-key".getBytes(StandardCharsets.UTF_8));

        assertEquals(32, aes.length);
        assertEquals(32, mac.length);
        assertFalse(Arrays.equals(aes, mac));
    }

    @Test
    void changeInSaltChangesOutput() {
        byte[] ikm = repeated(0x42, 32);
        assertFalse(Arrays.equals(
                PbpHkdf.derive(ikm, "salt-a", "info"),
                PbpHkdf.derive(ikm, "salt-b", "info")));
    }

    @Test
    void outputBeyondOneBlockIsChained() {
        // 35 字节跨两个 SHA-256 块，走的是 T(1) || T(2) 的串接路径
        byte[] ikm = repeated(1, 16);
        byte[] salt = "s".getBytes(StandardCharsets.UTF_8);
        byte[] info = "i".getBytes(StandardCharsets.UTF_8);
        byte[] long_ = PbpHkdf.derive(ikm, salt, info, 35);
        assertEquals(35, long_.length);
        // 前 32 字节应等于单块输出（同一 PRK 与 info 下）
        assertEquals(hex(Arrays.copyOf(long_, 32)), hex(PbpHkdf.derive(ikm, salt, info, 32)));
    }

    @Test
    void invalidArgumentsRejected() {
        byte[] ikm = repeated(1, 16);
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpHkdf.extract(null, null)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpHkdf.expand(new byte[0], null, 32)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpHkdf.expand(ikm, null, 0)).code());
        // 255 × 32 是 RFC 规定的上界
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpHkdf.expand(ikm, null, 255 * 32 + 1)).code());
    }
}