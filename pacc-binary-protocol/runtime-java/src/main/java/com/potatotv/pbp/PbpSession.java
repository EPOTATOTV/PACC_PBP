package com.potatotv.pbp;

import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 一条 PBP 会话的密钥与序号状态。
 *
 * <p>密钥来源是 ECDHE：双方各自生成 X25519 密钥对，交换公钥后算出共享密钥，
 * 再经 {@link PbpHkdf} 派生会话密钥（设计文档 §3.9.1）。这一步的意义是把长期密钥的使用
 * 收敛到"每次连接一次协商"——共享密钥只存在于内存里，抓包抓不到。</p>
 *
 * <p>轮换用链式派生（HMAC 上一把密钥）而不是重新协商：某一把会话密钥泄露时推不出
 * 静态密钥，也推不出后续 epoch 的密钥（HMAC 单向），代价只有一次 HMAC 计算。</p>
 *
 * <p>对象内含可变状态（序号、活跃时间），按"一条连接一个实例、单线程使用"设计：
 * 序号自增这类复合操作没有加锁，并发调用 {@link #nextSequence()} 会丢号。
 * 需要按会话 ID 查密钥请用 {@link Registry}，它只保证登记与淘汰是安全的，
 * 取出的实例仍应归一条连接独占使用。</p>
 */
public final class PbpSession {

    /** 设计文档 §3.9.1 给出的默认派生参数。 */
    public static final String DEFAULT_SALT = "pacc-session";
    public static final String DEFAULT_INFO = "aes-key";

    private static final String ROTATE_DOMAIN = "pacc-pbp-rotate-v1";

    private final long sessionId;
    private final long createdMs;

    private final byte[] key;
    private final long epoch;

    // volatile：Registry 会把同一个实例交给多个线程（它是被推荐的跨线程用法），
    // 序号与活跃时间必须对其他线程可见，否则淘汰判定会读到过期值。
    private volatile int sequence;
    private volatile int lastAcceptedSequence;
    private volatile long lastSeenMs;

    private PbpSession(long sessionId, byte[] key, long epoch) {
        if (key == null || key.length != PbpCrypto.KEY_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "会话密钥必须是 " + PbpCrypto.KEY_SIZE + " 字节");
        }
        this.sessionId = sessionId;
        this.key = key.clone();
        this.epoch = epoch;
        this.createdMs = System.currentTimeMillis();
        this.lastSeenMs = this.createdMs;
    }

    /** 用已有的会话密钥直接构造（密钥已在别处派生好时使用）。 */
    public static PbpSession of(long sessionId, byte[] key, long epoch) {
        return new PbpSession(sessionId, key, epoch);
    }

    /** 由 ECDHE 共享密钥派生会话密钥，走设计文档 §3.9.1 的默认 salt / info。 */
    public static PbpSession fromSharedSecret(long sessionId, byte[] sharedSecret) {
        return fromSharedSecret(sessionId, sharedSecret, DEFAULT_SALT, DEFAULT_INFO);
    }

    public static PbpSession fromSharedSecret(long sessionId, byte[] sharedSecret, String salt, String info) {
        return new PbpSession(sessionId, PbpHkdf.derive(sharedSecret, salt, info), 0L);
    }

    /**
     * 带用途隔离的密钥派生。
     *
     * <p>同一份输入密钥材料配不同的 {@code info} 会得到互不相关的密钥，
     * 因此加密密钥与签名密钥可以共用一次协商结果而不会互相削弱。</p>
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info) {
        return PbpHkdf.derive(ikm, salt, info, PbpCrypto.KEY_SIZE);
    }

    public static byte[] derive(byte[] ikm, String salt, String info) {
        return PbpHkdf.derive(ikm, salt, info);
    }

    public long sessionId() {
        return sessionId;
    }

    /** 原始 32 字节会话密钥（ChaCha20-Poly1305 用）。 */
    public byte[] key() {
        return key.clone();
    }

    /**
     * 会话密钥的十六进制形式。
     *
     * <p>仅供与按 hex 字符串持有密钥的既有链路（{@code WssSessionKeys}）对接：
     * 那边的 HMAC 密钥是这段 hex 文本的 UTF-8 字节，不是解 hex 后的 32 字节，两者不可混用。</p>
     */
    public String keyHex() {
        return HexFormat.of().formatHex(key);
    }

    public long epoch() {
        return epoch;
    }

    /** 已发出的最后一个序号。 */
    public int sequence() {
        return sequence;
    }

    public long createdMs() {
        return createdMs;
    }

    public long lastSeenMs() {
        return lastSeenMs;
    }

    /** 取下一个发送序号；序号从 1 开始（0 保留给"未使用序号"的帧）。 */
    public int nextSequence() {
        sequence++;
        return sequence;
    }

    /**
     * 校验收到的序号，并把会话标记为活跃。
     *
     * <p>按无符号比较要求严格递增，重放或乱序回退的帧一律拒绝（设计文档 §3.9.3）。
     * 序号绕回 2^32 之后比较会失效，但会话在几小时量级就会过期，绕回意味着每秒上百万帧，不现实。</p>
     */
    public boolean acceptSequence(int received) {
        lastSeenMs = System.currentTimeMillis();
        if (Integer.compareUnsigned(received, lastAcceptedSequence) <= 0) {
            return false;
        }
        lastAcceptedSequence = received;
        return true;
    }

    /** 刷新活跃时间（收到不需要计序号的帧时用）。 */
    public void touch() {
        lastSeenMs = System.currentTimeMillis();
    }

    /**
     * 轮换到下一 epoch。
     *
     * @param expectedEpoch 调用方声明的当前 epoch，必须与本地一致，否则拒绝
     *                      —— 防止重放旧的轮换请求把密钥回退到历史版本
     * @return 新会话；epoch 不匹配返回 null
     */
    public PbpSession rotate(long expectedEpoch) {
        if (epoch != expectedEpoch) {
            return null;
        }
        long next = epoch + 1;
        byte[] nextKey = PbpCrypto.hmacSha256(key,
                (ROTATE_DOMAIN + "|" + sessionId + "|" + next).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new PbpSession(sessionId, nextKey, next);
    }

    /** 会话 ID 的十六进制形式，便于日志与登记表对齐。 */
    public String sessionIdHex() {
        return Long.toHexString(sessionId);
    }

    /**
     * 会话登记表：按会话 ID 查密钥，未知 ID 一律返回 null 由调用方拒绝。
     *
     * <p>只增不减的登记表会随重连次数无限堆积，所以带 TTL 与容量上限，
     * 与 {@code WssSessionKeys} 的处理方式一致。</p>
     */
    public static final class Registry {

        private final long ttlMs;
        private final int maxSessions;
        private final Map<Long, PbpSession> sessions = new ConcurrentHashMap<>();

        public Registry(long ttlMs, int maxSessions) {
            if (ttlMs <= 0 || maxSessions <= 0) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "TTL 与容量上限必须为正");
            }
            this.ttlMs = ttlMs;
            this.maxSessions = maxSessions;
        }

        /** 登记一条会话；容量已满则先清僵尸会话，仍满则拒绝。 */
        public PbpSession open(long sessionId, byte[] key) {
            evictStale();
            if (sessions.size() >= maxSessions) {
                return null;
            }
            PbpSession session = PbpSession.of(sessionId, key, 0L);
            sessions.put(sessionId, session);
            return session;
        }

        /** 查一条会话并刷新活跃时间；未知会话 ID 返回 null。 */
        public PbpSession get(long sessionId) {
            PbpSession session = sessions.get(sessionId);
            if (session != null) {
                session.touch();
            }
            return session;
        }

        /** 轮换；会话不存在或 epoch 不匹配返回 null。 */
        public PbpSession rotate(long sessionId, long expectedEpoch) {
            PbpSession current = sessions.get(sessionId);
            if (current == null) {
                return null;
            }
            PbpSession rotated = current.rotate(expectedEpoch);
            if (rotated != null) {
                sessions.put(sessionId, rotated);
            }
            return rotated;
        }

        /** 断开时立即销毁，不留在内存里等 TTL。 */
        public void close(long sessionId) {
            sessions.remove(sessionId);
        }

        public int size() {
            return sessions.size();
        }

        private void evictStale() {
            if (sessions.size() <= maxSessions / 2) {
                return;
            }
            long threshold = System.currentTimeMillis() - ttlMs;
            sessions.entrySet().removeIf(e -> e.getValue().lastSeenMs() < threshold);
        }
    }
}