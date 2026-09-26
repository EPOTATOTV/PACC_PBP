package com.potatotv.pbp;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/**
 * PBP 安全层的密码学原语：HMAC-SHA256 签名与 ChaCha20-Poly1305 加密。
 *
 * <p>只封装 JDK 自带实现（SunJCE / SunEC），不引第三方库，也不用反射
 * ——客户端产物要过 {@code -repackageclasses}，任何按类名找实现的写法都会在混淆后失效。</p>
 *
 * <p>ChaCha20-Poly1305 选的是 IETF 变体（12 字节 nonce + 16 字节 tag 追加在密文尾部），
 * JDK 的 {@code "ChaCha20-Poly1305"} 就是它。设计文档 §3.9.2 写的
 * {@code nonce = session_id(8) + sequence(4) + counter(4)} 是 16 字节，IETF 变体收不下，
 * 所以这里去掉 counter：session_id 与 sequence 已经保证同一密钥下 nonce 不重复。</p>
 */
public final class PbpCrypto {

    /** IETF ChaCha20-Poly1305 的 nonce 长度。 */
    public static final int NONCE_SIZE = 12;
    /** Poly1305 认证标签长度。 */
    public static final int TAG_SIZE = 16;
    /** ChaCha20-Poly1305 密钥长度（256 位）。 */
    public static final int KEY_SIZE = 32;

    private static final String AEAD = "ChaCha20-Poly1305";
    private static final String AEAD_KEY_ALGORITHM = "ChaCha20";
    private static final String HMAC = "HmacSHA256";

    private PbpCrypto() {
    }

    // ------------------------------------------------------------ 签名

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 初始化失败", e);
        }
    }

    /** 校验 HMAC，用恒定时间比较避免按字节提前返回泄漏签名前缀。 */
    public static boolean verifyHmac(byte[] key, byte[] data, byte[] expected) {
        if (expected == null || expected.length != 32) {
            return false;
        }
        return MessageDigest.isEqual(hmacSha256(key, data), expected);
    }

    /** 恒定时间比较任意等长字节串。 */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * 由会话 ID 与帧序号拼出 nonce：8 字节会话 ID + 4 字节序号（均小端）。
     *
     * <p>把序号写进 nonce 而不是额外维护计数器，是因为序号本身就保证同一会话内单调不重复，
     * 少一处需要两侧同步的状态。</p>
     */
    public static byte[] newNonce(long sessionId, int sequence) {
        byte[] nonce = new byte[NONCE_SIZE];
        for (int i = 0; i < 8; i++) {
            nonce[i] = (byte) (sessionId >>> (i * 8));
        }
        for (int i = 0; i < 4; i++) {
            nonce[8 + i] = (byte) (sequence >>> (i * 8));
        }
        return nonce;
    }

    // ------------------------------------------------------------ 加密

    /**
     * 加密：返回密文 + 16 字节 tag。
     *
     * @param aad 附加认证数据，应为帧头字节（不含签名），保证 header 不可被篡改
     */
    public static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        return doAead(Cipher.ENCRYPT_MODE, key, nonce, plaintext, aad,
                PbpException.Code.BAD_FORMAT, "加密失败");
    }

    /**
     * 解密并校验 tag；认证失败抛 {@link PbpException.Code#TAG_MISMATCH}。
     *
     * <p>与"长度不符""版本不符"区分开：tag 不匹配基本等于载荷被改过或密钥不对，
     * 调用方需要能把它记成安全事件而不是普通协议错误。</p>
     */
    public static byte[] open(byte[] key, byte[] nonce, byte[] sealed, byte[] aad) {
        return doAead(Cipher.DECRYPT_MODE, key, nonce, sealed, aad,
                PbpException.Code.TAG_MISMATCH, "认证标签校验失败");
    }

    private static byte[] doAead(int mode, byte[] key, byte[] nonce, byte[] input, byte[] aad,
                                 PbpException.Code failureCode, String failureMessage) {
        if (key == null || key.length != KEY_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "ChaCha20-Poly1305 密钥必须是 " + KEY_SIZE + " 字节");
        }
        if (nonce == null || nonce.length != NONCE_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "nonce 必须是 " + NONCE_SIZE + " 字节");
        }
        try {
            Cipher cipher = Cipher.getInstance(AEAD);
            cipher.init(mode, new SecretKeySpec(key, AEAD_KEY_ALGORITHM), new IvParameterSpec(nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input);
        } catch (AEADBadTagException e) {
            throw new PbpException(PbpException.Code.TAG_MISMATCH, failureMessage, e);
        } catch (Exception e) {
            throw new PbpException(failureCode, failureMessage, e);
        }
    }
}