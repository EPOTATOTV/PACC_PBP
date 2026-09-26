package com.potatotv.pbp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * HKDF-SHA256（RFC 5869）。
 *
 * <p>JDK 21 没有公开的 HKDF API（JEP 478 在更晚的版本才进），所以照 RFC 5869 用
 * {@link Mac} 手工实现 extract / expand。ptv-backend 里已有一份同构实现
 * （{@code service.security.Hkdf}），这里不能反向依赖后端，两份必须保持逐字节一致，
 * 由 {@code PbpHkdfParityTest} 锁住。</p>
 *
 * <p>用途：ECDHE 协商出的共享密钥是原始字节，直接当会话密钥用等于跳过了一次密钥提取；
 * HKDF 的 extract 步把弱分布的共享密钥压成均匀的 PRK，expand 步再用 {@code info}
 * 做用途隔离（同一份输入派生出加密密钥与签名密钥时不会互相泄漏）。</p>
 */
public final class PbpHkdf {

    /** SHA-256 输出长度。 */
    private static final int HASH_LEN = 32;

    /** RFC 5869 规定 OKM 最长 255 × HashLen。 */
    private static final int MAX_OKM_LEN = 255 * HASH_LEN;

    private PbpHkdf() {
    }

    /**
     * extract：把任意长度的输入密钥材料压成固定长度 PRK。
     *
     * <p>salt 为空（null 或零长度）按 RFC 规定退化成 HashLen 个零字节，
     * 不是"没有盐"——这两者在 HMAC 里结果相同但语义不同，显式写出来免得被优化掉。</p>
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        if (ikm == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "HKDF 输入密钥材料为 null");
        }
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        return hmac(effectiveSalt, ikm);
    }

    /** expand：从 PRK 与 info 导出 {@code length} 字节密钥；T(i) 链式串接并带上 1 起点计数器。 */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (prk == null || prk.length == 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "HKDF PRK 为空");
        }
        if (length <= 0 || length > MAX_OKM_LEN) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "HKDF 输出长度越界: " + length);
        }
        byte[] okm = new byte[length];
        byte[] block = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < length) {
            Mac mac = newMac(prk);
            mac.update(block);
            if (info != null && info.length > 0) {
                mac.update(info);
            }
            mac.update((byte) counter);
            block = mac.doFinal();
            int n = Math.min(HASH_LEN, length - pos);
            System.arraycopy(block, 0, okm, pos, n);
            pos += n;
            counter++;
        }
        return okm;
    }

    /** extract + expand。 */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        return expand(extract(salt, ikm), info, length);
    }

    /** 默认输出 32 字节（一个 SHA-256 块）。 */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info) {
        return derive(ikm, salt, info, HASH_LEN);
    }

    /** 字符串形式的 salt / info 按 UTF-8 取字节，与设计文档 §3.9.1 的写法对应。 */
    public static byte[] derive(byte[] ikm, String salt, String info) {
        return derive(ikm,
                salt == null ? null : salt.getBytes(StandardCharsets.UTF_8),
                info == null ? null : info.getBytes(StandardCharsets.UTF_8),
                HASH_LEN);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        return newMac(key).doFinal(data);
    }

    private static Mac newMac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 初始化失败", e);
        }
    }
}