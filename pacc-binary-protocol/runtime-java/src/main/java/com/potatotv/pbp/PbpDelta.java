package com.potatotv.pbp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * 差分编码的公共工具：字段比较与基线拷贝。
 *
 * <p>生成的 {@code encodeDelta/applyDelta} 只写"哪个字段变了"，比较与深拷贝的细节
 * 集中在这里，避免每个生成类各写一份。</p>
 *
 * <p>比较分两条路：标量/字符串/字节数组直接比较值；嵌套消息、列表、映射按"同一套
 * 编码调用写出来的字节"比较——它们的相等性与字段顺序、元素顺序天然一致，
 * 不需要为每个生成类再写一遍 equals。</p>
 */
public final class PbpDelta {

    private PbpDelta() {
    }

    /**
     * 两个字段是否不同：把同一套 writer 调用分别写进临时编码器，比字节。
     *
     * <p>生成代码里这样用：
     * {@code PbpDelta.differs(enc -> enc.writeStringList(events),
     * enc -> enc.writeStringList(previous.events))}。</p>
     */
    public static boolean differs(Consumer<PbpEncoder> current, Consumer<PbpEncoder> previous) {
        PbpEncoder a = new PbpEncoder(32);
        PbpEncoder b = new PbpEncoder(32);
        current.accept(a);
        previous.accept(b);
        return !Arrays.equals(a.toByteArray(), b.toByteArray());
    }

    /** 深拷贝消息（编解码往返）；null 原样返回，配合可空字段使用。 */
    public static <T extends PbpMessage> T copy(T message, Supplier<T> factory) {
        if (message == null) {
            return null;
        }
        T clone = factory.get();
        clone.decode(new PbpDecoder(PbpCodec.payloadOf(message)));
        return clone;
    }

    /** 深拷贝消息列表；null 原样返回。 */
    public static <T extends PbpMessage> List<T> copyList(List<T> list, Supplier<T> factory) {
        if (list == null) {
            return null;
        }
        List<T> clone = new ArrayList<>(list.size());
        for (T element : list) {
            clone.add(copy(element, factory));
        }
        return clone;
    }

    /** 深拷贝消息映射的值；null 原样返回。 */
    public static <K, V extends PbpMessage> Map<K, V> copyMap(Map<K, V> map, Supplier<V> factory) {
        if (map == null) {
            return null;
        }
        Map<K, V> clone = new LinkedHashMap<>();
        for (Map.Entry<K, V> entry : map.entrySet()) {
            clone.put(entry.getKey(), copy(entry.getValue(), factory));
        }
        return clone;
    }
}