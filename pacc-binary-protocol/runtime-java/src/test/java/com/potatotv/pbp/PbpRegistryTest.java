package com.potatotv.pbp;

import com.potatotv.pbp.gen.PaccEnvelope;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 消息 ID 注册表测试。
 *
 * <p>区间规则与 MDL 侧（{@code tools/pbpgen/pbpgen/model.py}）是同一份契约，两边得一起变：
 * 生成器拒掉的 ID，运行时注册表也必须拒，否则手写注册就能绕过 MDL 定义。</p>
 */
class PbpRegistryTest {

    private final PbpRegistry registry = new PbpRegistry();

    private static Supplier<PaccEnvelope> envelope() {
        return () -> PaccEnvelope.newBuilder().build();
    }

    @Test
    void acceptsBoundariesOfEveryAllowedRange() {
        int[] ids = {
                PbpRegistry.SYSTEM_MIN, PbpRegistry.SYSTEM_MAX,
                PbpRegistry.CLIENT_TO_SERVER_MIN, PbpRegistry.CLIENT_TO_SERVER_MAX,
                PbpRegistry.SERVER_TO_CLIENT_MIN, PbpRegistry.SERVER_TO_CLIENT_MAX,
                PbpRegistry.BIDIRECTIONAL_MIN, PbpRegistry.BIDIRECTIONAL_MAX,
                PbpRegistry.CUSTOM_MIN, PbpRegistry.CUSTOM_MAX,
        };
        for (int id : ids) {
            registry.register(id, envelope());
        }
        assertEquals(ids.length, registry.size());
    }

    @Test
    void reservedRangeRejected() {
        // 0x3000-0xEFFF 是设计文档 §3.5 明文禁止使用的预留区，两端与中点都要拦
        for (int id : new int[]{0x3000, 0x5000, 0xEFFF}) {
            assertRejected(id, "预留区间");
        }
    }

    @Test
    void outOfRangeRejected() {
        assertRejected(-1, "越界");
        assertRejected(0x1_0000, "越界");
    }

    @Test
    void duplicateRegistrationRejected() {
        registry.register(PbpRegistry.BIDIRECTIONAL_MIN, envelope());
        assertRejected(PbpRegistry.BIDIRECTIONAL_MIN, "重复注册");
    }

    @Test
    void newInstanceAndContains() {
        assertNull(registry.newInstance(PaccEnvelope.MESSAGE_ID), "未注册的 ID 应返回 null 而不是抛错");
        registry.register(PaccEnvelope.MESSAGE_ID, envelope());
        assertTrue(registry.contains(PaccEnvelope.MESSAGE_ID));
        assertNotNull(registry.newInstance(PaccEnvelope.MESSAGE_ID));
        assertNull(registry.newInstance(PbpRegistry.SYSTEM_MIN));
    }

    private void assertRejected(int messageId, String expectedPhrase) {
        PbpException e = assertThrows(PbpException.class, () -> registry.register(messageId, envelope()));
        assertEquals(PbpException.Code.BAD_FORMAT, e.code());
        String hex = "0x" + Integer.toHexString(messageId);
        assertTrue(e.getMessage().contains(expectedPhrase), hex + " 应以「" + expectedPhrase + "」拒绝，实际：" + e.getMessage());
    }
}