package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 会话密钥派生、序号防重放、epoch 轮换与登记表测试。 */
class PbpSessionTest {

    private static final byte[] SHARED = HexFormat.of().parseHex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // ------------------------------------------------------------ 派生

    @Test
    void sharedSecretIsRunThroughHkdf() {
        PbpSession session = PbpSession.fromSharedSecret(7L, SHARED);
        assertEquals(PbpCrypto.KEY_SIZE, session.key().length);
        // 会话密钥不能等于共享密钥本身，否则等于跳过了一次密钥提取
        assertFalse(Arrays.equals(SHARED, session.key()));
        assertArrayEquals(PbpHkdf.derive(SHARED, PbpSession.DEFAULT_SALT, PbpSession.DEFAULT_INFO), session.key());
        assertEquals(0L, session.epoch());
    }

    @Test
    void differentSaltOrInfoGivesDifferentKey() {
        byte[] a = PbpSession.fromSharedSecret(7L, SHARED, "salt-a", "info").key();
        byte[] b = PbpSession.fromSharedSecret(7L, SHARED, "salt-b", "info").key();
        byte[] c = PbpSession.fromSharedSecret(7L, SHARED, "salt-a", "other").key();
        assertEquals(32, a.length);
        assertFalse(Arrays.equals(a, b));
        assertFalse(Arrays.equals(a, c));
    }

    @Test
    void keyHexMatchesRawKey() {
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        assertEquals(HexFormat.of().formatHex(SHARED), session.keyHex());
        assertEquals(64, session.keyHex().length());
        assertEquals("1", session.sessionIdHex());
    }

    @Test
    void invalidKeyLengthRejected() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpSession.of(1L, new byte[16], 0L)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpSession.of(1L, null, 0L)).code());
    }

    // ------------------------------------------------------------ 序号

    @Test
    void sequenceStartsAtOneAndIncreases() {
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        assertEquals(0, session.sequence());
        assertEquals(1, session.nextSequence());
        assertEquals(2, session.nextSequence());
        assertEquals(2, session.sequence());
    }

    @Test
    void replayAndOutOfOrderFramesRejected() {
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        assertTrue(session.acceptSequence(1));
        assertTrue(session.acceptSequence(2));
        // 重放刚收到的序号
        assertFalse(session.acceptSequence(2));
        // 回退到更小的序号
        assertFalse(session.acceptSequence(1));
        // 序号 0 是"未使用序号"的保留值
        assertFalse(session.acceptSequence(0));
        assertTrue(session.acceptSequence(3));
    }

    @Test
    void sequenceComparisonIsUnsigned() {
        // 序号是 uint32，高位置位后按有符号比较会整体判负，把正常帧全拒掉
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        assertTrue(session.acceptSequence(-1));
        assertFalse(session.acceptSequence(1));
    }

    // ------------------------------------------------------------ 轮换

    @Test
    void rotateRequiresMatchingEpoch() {
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        // 声明的 epoch 与本地不符 → 拒绝，防止重放旧的 rekey 把密钥回退
        assertNull(session.rotate(3L));
        assertNotNull(session.rotate(0L));
    }

    @Test
    void rotateChainsKeyAndBumpsEpoch() {
        PbpSession session = PbpSession.of(1L, SHARED, 0L);
        PbpSession rotated = session.rotate(0L);
        assertNotNull(rotated);
        assertEquals(1L, rotated.epoch());
        assertFalse(Arrays.equals(session.key(), rotated.key()));
        // 链式派生：新密钥不能再从共享密钥直接推出来
        assertFalse(Arrays.equals(PbpSession.fromSharedSecret(1L, SHARED).key(), rotated.key()));
        assertEquals(1L, rotated.rotate(1L).sessionId());
    }

    @Test
    void rotatedSessionKeepsSessionIdButResetsSequence() {
        PbpSession session = PbpSession.of(42L, SHARED, 5L);
        session.nextSequence();
        PbpSession rotated = session.rotate(5L);
        assertNotNull(rotated);
        assertEquals(42L, rotated.sessionId());
        assertEquals(0, rotated.sequence(), "轮换后的新密钥从序号 0 重新计");
    }

    // ------------------------------------------------------------ 登记表

    @Test
    void registryRejectsUnknownSession() {
        PbpSession.Registry registry = new PbpSession.Registry(60_000L, 100);
        registry.open(1L, SHARED);
        assertNotNull(registry.get(1L));
        // 未知 keyId：调用方必须拿到 null 并据此拒绝该帧
        assertNull(registry.get(99L));
        assertNull(registry.rotate(99L, 0L));
    }

    @Test
    void registryRotatesAndCloses() {
        PbpSession.Registry registry = new PbpSession.Registry(60_000L, 100);
        registry.open(1L, SHARED);

        assertNull(registry.rotate(1L, 7L), "epoch 不符不该轮换");
        PbpSession rotated = registry.rotate(1L, 0L);
        assertNotNull(rotated);
        assertEquals(1L, registry.get(1L).epoch());

        registry.close(1L);
        assertNull(registry.get(1L), "断开后密钥必须立即消失");
        assertEquals(0, registry.size());
    }

    @Test
    void registryRejectsWhenFull() {
        PbpSession.Registry registry = new PbpSession.Registry(60_000L, 2);
        assertNotNull(registry.open(1L, SHARED));
        assertNotNull(registry.open(2L, SHARED));
        // 容量满且没有可清理的僵尸会话时拒绝新会话，而不是无限增长
        assertNull(registry.open(3L, SHARED));
        assertEquals(2, registry.size());
    }

    @Test
    void registryRejectsNonPositiveBounds() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpSession.Registry(0L, 100)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpSession.Registry(1000L, 0)).code());
    }
}