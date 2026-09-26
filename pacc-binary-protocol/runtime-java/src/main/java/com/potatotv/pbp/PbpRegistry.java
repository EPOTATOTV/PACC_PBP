package com.potatotv.pbp;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 消息 ID → 解码器工厂的注册表。
 *
 * <p>刻意只用显式注册，不扫描 classpath、不用反射：反射既破坏零依赖目标，
 * 又会在客户端 {@code -repackageclasses} 混淆后因类名变化而失效。</p>
 *
 * <p>注册时校验 ID 是否落在 MDL 允许的区间内，避免两条消息撞 ID 到线上才发现。</p>
 */
public final class PbpRegistry {

    /** 消息 ID 区间（设计文档 §3.3.3）。 */
    public static final int SYSTEM_MIN = 0x0000;
    public static final int SYSTEM_MAX = 0x00FF;
    public static final int CLIENT_TO_SERVER_MIN = 0x0100;
    public static final int CLIENT_TO_SERVER_MAX = 0x0FFF;
    public static final int SERVER_TO_CLIENT_MIN = 0x1000;
    public static final int SERVER_TO_CLIENT_MAX = 0x1FFF;
    public static final int BIDIRECTIONAL_MIN = 0x2000;
    public static final int BIDIRECTIONAL_MAX = 0x2FFF;
    /** 预留区间，禁止使用；同名的来源侧常量在 {@code tools/pbpgen/pbpgen/model.py}。 */
    public static final int RESERVED_MIN = 0x3000;
    public static final int RESERVED_MAX = 0xEFFF;
    public static final int CUSTOM_MIN = 0xF000;
    public static final int CUSTOM_MAX = 0xFFFF;

    private final Map<Integer, Supplier<? extends PbpMessage>> factories = new HashMap<>();

    /** 注册一个消息 ID 与它的空实例工厂。重复或越界 ID 直接抛错。 */
    public <T extends PbpMessage> void register(int messageId, Supplier<T> factory) {
        if (messageId < SYSTEM_MIN || messageId > CUSTOM_MAX) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "消息 ID 越界: " + Integer.toHexString(messageId));
        }
        // 已知区间彼此首尾相接（0x00FF→0x0100、0x0FFF→0x1000、0x1FFF→0x2000），没有窄缝，
        // 唯一的窟窿就是 0x3000-0xEFFF 这段预留区，别漏掉它。
        if (messageId >= RESERVED_MIN && messageId <= RESERVED_MAX) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "消息 ID 落在预留区间: " + Integer.toHexString(messageId));
        }
        Supplier<? extends PbpMessage> prev = factories.putIfAbsent(messageId, factory);
        if (prev != null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "消息 ID 重复注册: " + Integer.toHexString(messageId));
        }
    }

    /** 新建一条消息实例；未注册的 ID 返回 null（调用方决定是忽略还是断开）。 */
    public PbpMessage newInstance(int messageId) {
        Supplier<? extends PbpMessage> f = factories.get(messageId);
        return f == null ? null : f.get();
    }

    public boolean contains(int messageId) {
        return factories.containsKey(messageId);
    }

    public int size() {
        return factories.size();
    }
}