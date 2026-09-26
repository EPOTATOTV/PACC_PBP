package com.potatotv.pbp;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * X25519 密钥协商（RFC 7748），走 JDK 的 {@code XDH} 实现（JEP 324）。
 *
 * <p>裸字节格式统一定义为 <b>32 字节小端</b>：X25519 的 u 坐标与标量在 RFC 7748 里
 * 就是小端编码的，而 JDK 的 {@code XECPublicKey.getU()} 给的是 BigInteger，
 * 直接 {@code toByteArray()} 得到的是大端且可能带符号位补零，不能当线上格式用。
 * 这里的转换是跨语言互通的关键点，任何一侧改字节序都会导致协商出不同密钥却不报错。</p>
 *
 * <p>标量的 clamp（清低位、置高位）由 provider 在 {@link java.security.KeyAgreement}
 * 内部按 RFC 7748 完成，本类不再重复处理；{@link #privateKeyFromBytes} 保留传入的原始字节。</p>
 */
public final class PbpX25519 {

    /** X25519 公钥与私钥的裸字节长度。 */
    public static final int KEY_SIZE = 32;

    private static final String ALGORITHM = "X25519";

    private PbpX25519() {
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 密钥对生成失败", e);
        }
    }

    public static byte[] publicKeyBytes(PublicKey publicKey) {
        if (!(publicKey instanceof java.security.interfaces.XECPublicKey xec)) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "不是 X25519 公钥: " + publicKey);
        }
        return toLittleEndian32(xec.getU());
    }

    public static byte[] privateKeyBytes(PrivateKey privateKey) {
        if (!(privateKey instanceof java.security.interfaces.XECPrivateKey xec)) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "不是 X25519 私钥: " + privateKey);
        }
        byte[] scalar = xec.getScalar().orElseThrow(() -> new PbpException(
                PbpException.Code.BAD_FORMAT, "provider 未暴露 X25519 标量"));
        if (scalar.length != KEY_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 标量长度异常: " + scalar.length);
        }
        return scalar.clone();
    }

    public static PublicKey publicKeyFromBytes(byte[] raw) {
        requireKeySize(raw, "公钥");
        try {
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, fromLittleEndian(raw)));
        } catch (Exception e) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 公钥解析失败", e);
        }
    }

    public static PrivateKey privateKeyFromBytes(byte[] raw) {
        requireKeySize(raw, "私钥");
        try {
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, raw.clone()));
        } catch (Exception e) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 私钥解析失败", e);
        }
    }

    /** 计算共享密钥，输出 32 字节。 */
    public static byte[] sharedSecret(PrivateKey localPrivate, PublicKey peerPublic) {
        try {
            javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance(ALGORITHM);
            agreement.init(localPrivate);
            agreement.doPhase(peerPublic, true);
            byte[] secret = agreement.generateSecret();
            if (secret.length != KEY_SIZE) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 共享密钥长度异常: " + secret.length);
            }
            return secret;
        } catch (PbpException e) {
            throw e;
        } catch (Exception e) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 密钥协商失败", e);
        }
    }

    public static byte[] sharedSecret(PrivateKey localPrivate, byte[] peerPublicRaw) {
        return sharedSecret(localPrivate, publicKeyFromBytes(peerPublicRaw));
    }

    private static void requireKeySize(byte[] raw, String what) {
        if (raw == null || raw.length != KEY_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "X25519 " + what + "必须是 " + KEY_SIZE + " 字节");
        }
    }

    /** BigInt（大端、可能带符号位补零）→ 32 字节小端。 */
    private static byte[] toLittleEndian32(BigInteger u) {
        byte[] bigEndian = u.toByteArray();
        int start = 0;
        while (start < bigEndian.length - 1 && bigEndian[start] == 0) {
            start++;
        }
        int significant = bigEndian.length - start;
        if (significant > KEY_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "X25519 u 坐标超出 32 字节");
        }
        byte[] out = new byte[KEY_SIZE];
        for (int i = 0; i < significant; i++) {
            out[i] = bigEndian[bigEndian.length - 1 - i];
        }
        return out;
    }

    /** 32 字节小端 → BigInt（构造时补一个 0x00 前缀保证被当正数解释）。 */
    private static BigInteger fromLittleEndian(byte[] raw) {
        byte[] bigEndian = new byte[KEY_SIZE + 1];
        for (int i = 0; i < KEY_SIZE; i++) {
            bigEndian[KEY_SIZE - i] = raw[i];
        }
        return new BigInteger(bigEndian);
    }
}