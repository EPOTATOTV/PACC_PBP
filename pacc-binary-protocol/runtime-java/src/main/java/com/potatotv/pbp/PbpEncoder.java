package com.potatotv.pbp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * PBP 二进制编码器。
 *
 * <p>字段按 MDL 定义顺序写入、不带标签（设计文档 §3.4.2）：省掉每个字段 1-2 字节的标签开销，
 * 代价是编解码双方必须持有同一份字段顺序定义，且新字段只能加在末尾。</p>
 *
 * <p>内部用可增长的 byte[] 而不是定长 ByteBuffer：编码前无法可靠预测长度，
 * {@code encodedSize()} 只是预分配提示，不能作为正确性依据。因此缓冲区按需扩容，
 * 由 {@link #toByteArray()} 截断出最终长度。</p>
 *
 * <p>所有多字节定长字段一律小端，与帧头保持一致；跨语言实现不需要再记两套字节序。</p>
 */
public final class PbpEncoder {

    /** VarInt 最多 10 字节（每 7 位一组，64 位需要 10 组）。 */
    static final int MAX_VARINT_BYTES = 10;

    private static final int DEFAULT_CAPACITY = 64;

    private byte[] buf;
    private int len;

    public PbpEncoder() {
        this(DEFAULT_CAPACITY);
    }

    public PbpEncoder(int initialCapacity) {
        this.buf = new byte[Math.max(16, initialCapacity)];
    }

    /** 已写入的字节数。 */
    public int size() {
        return len;
    }

    /** 复制出当前已写入的字节，长度正好等于 {@link #size()}。 */
    public byte[] toByteArray() {
        return Arrays.copyOf(buf, len);
    }

    /** 清空缓冲区以便复用；容量保留。 */
    public void reset() {
        len = 0;
    }

    // ------------------------------------------------------------ 标量

    public PbpEncoder writeBool(boolean v) {
        return writeRaw((byte) (v ? 1 : 0));
    }

    public PbpEncoder writeInt8(int v) {
        requireRange(v, Byte.MIN_VALUE, Byte.MAX_VALUE, "int8");
        return writeRaw((byte) v);
    }

    public PbpEncoder writeUInt8(int v) {
        requireRange(v, 0, 0xFF, "uint8");
        return writeRaw((byte) v);
    }

    public PbpEncoder writeInt16(int v) {
        requireRange(v, Short.MIN_VALUE, Short.MAX_VALUE, "int16");
        return writeRaw((byte) v).writeRaw((byte) (v >>> 8));
    }

    public PbpEncoder writeUInt16(int v) {
        requireRange(v, 0, 0xFFFF, "uint16");
        return writeRaw((byte) v).writeRaw((byte) (v >>> 8));
    }

    /** int32 走 ZigZag + VarInt（负数不会占满 10 字节）。 */
    public PbpEncoder writeInt32(int v) {
        writeVarInt(Integer.toUnsignedLong((v << 1) ^ (v >> 31)));
        return this;
    }

    /** uint32 走 VarInt，取值上界是 2^32-1，超出 int 范围故用 long 传参。 */
    public PbpEncoder writeUInt32(long v) {
        requireRange(v, 0, 0xFFFF_FFFFL, "uint32");
        writeVarInt(v);
        return this;
    }

    /** int64 走 ZigZag + VarInt。 */
    public PbpEncoder writeInt64(long v) {
        writeVarInt((v << 1) ^ (v >> 63));
        return this;
    }

    /** uint64 走 VarInt，long 的原始位模式即无符号值，无需额外处理。 */
    public PbpEncoder writeUInt64(long v) {
        writeVarInt(v);
        return this;
    }

    public PbpEncoder writeEnum(int v) {
        if (v < 0) throw badFormat("enum 值不能为负: " + v);
        writeVarInt(v);
        return this;
    }

    public PbpEncoder writeFloat32(float v) {
        int bits = Float.floatToRawIntBits(v);
        return writeRaw((byte) bits)
                .writeRaw((byte) (bits >>> 8))
                .writeRaw((byte) (bits >>> 16))
                .writeRaw((byte) (bits >>> 24));
    }

    public PbpEncoder writeFloat64(double v) {
        long bits = Double.doubleToRawLongBits(v);
        for (int i = 0; i < 8; i++) {
            writeRaw((byte) (bits >>> (i * 8)));
        }
        return this;
    }

    // ------------------------------------------------------------ 变长

    /** UTF-8 字符串：VarInt 字节长度 + 数据。null 必须走 {@link #writeOptionalString}。 */
    public PbpEncoder writeString(String s) {
        if (s == null) {
            throw badFormat("string 字段为 null，可空字段请用 writeOptionalString");
        }
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        writeVarInt(b.length);
        return writeRaw(b, 0, b.length);
    }

    public PbpEncoder writeBytes(byte[] b) {
        if (b == null) {
            throw badFormat("bytes 字段为 null，可空字段请用 writeOptionalBytes");
        }
        writeVarInt(b.length);
        return writeRaw(b, 0, b.length);
    }

    // ------------------------------------------------------------ 可空字段

    /**
     * 写入一段连续可空字段的存在位图（设计文档 §3.4.3）。
     *
     * <p>位图必须写在所有对应字段的值之前，所以调用方要把这一批可空字段的
     * 存在性一次性传进来。单个可空字段的位图正好是 1 字节，与"存在性字节"
     * 形式逐字节等价，因此 {@link #writeOptionalString} 等单字段便捷方法
     * 与位图形式可以混用而不产生两种编码。</p>
     */
    public PbpEncoder writePresence(boolean... present) {
        int byteCount = (present.length + 7) / 8;
        for (int i = 0; i < byteCount; i++) {
            int bits = 0;
            for (int bit = 0; bit < 8; bit++) {
                int idx = i * 8 + bit;
                if (idx < present.length && present[idx]) {
                    bits |= 1 << bit;
                }
            }
            writeRaw((byte) bits);
        }
        return this;
    }

    public PbpEncoder writeOptionalString(String s) {
        writePresence(s != null);
        return s == null ? this : writeString(s);
    }

    public PbpEncoder writeOptionalBytes(byte[] b) {
        writePresence(b != null);
        return b == null ? this : writeBytes(b);
    }

    public PbpEncoder writeOptionalMessage(PbpMessage m) {
        writePresence(m != null);
        return m == null ? this : writeMessage(m);
    }

    // ------------------------------------------------------------ 消息与集合

    /** 嵌套消息内联编码，不加长度前缀：字段顺序即边界，由最外层帧的 PayloadLen 兜底。 */
    public PbpEncoder writeMessage(PbpMessage m) {
        if (m == null) {
            throw badFormat("嵌套消息为 null，可空字段请用 writeOptionalMessage");
        }
        m.encode(this);
        return this;
    }

    public PbpEncoder writeMessageList(List<? extends PbpMessage> list) {
        if (list == null) {
            throw badFormat("消息列表为 null");
        }
        writeVarInt(list.size());
        for (PbpMessage m : list) {
            m.encode(this);
        }
        return this;
    }

    public PbpEncoder writeStringList(List<String> list) {
        return writeList(list, PbpEncoder::writeString);
    }

    /** 通用列表：元素为标量时用 {@code PbpEncoder::writeInt64} 这类方法引用传入。 */
    public <T> PbpEncoder writeList(List<T> list, BiConsumer<PbpEncoder, T> elementWriter) {
        if (list == null) {
            throw badFormat("列表为 null");
        }
        writeVarInt(list.size());
        for (T e : list) {
            elementWriter.accept(this, e);
        }
        return this;
    }

    /** 通用映射：键值对按 Map 迭代顺序写入，两侧需使用有序 Map 才能保证字节一致。 */
    public <K, V> PbpEncoder writeMap(Map<K, V> map,
                                      BiConsumer<PbpEncoder, K> keyWriter,
                                      BiConsumer<PbpEncoder, V> valueWriter) {
        if (map == null) {
            throw badFormat("map 为 null");
        }
        writeVarInt(map.size());
        for (Map.Entry<K, V> e : map.entrySet()) {
            keyWriter.accept(this, e.getKey());
            valueWriter.accept(this, e.getValue());
        }
        return this;
    }

    /** 键固定为 string 的映射（MDL 里绝大多数 map 都是这种）。 */
    public <V> PbpEncoder writeStringMap(Map<String, V> map, BiConsumer<PbpEncoder, V> valueWriter) {
        return writeMap(map, PbpEncoder::writeString, valueWriter);
    }

    // ------------------------------------------------------------ 长度预估（纯预分配提示）

    public static int varIntSize(long v) {
        int n = 1;
        while ((v & ~0x7FL) != 0) {
            v >>>= 7;
            n++;
        }
        return n;
    }

    public static int boolSize() {
        return 1;
    }

    public static int int8Size() {
        return 1;
    }

    public static int uint8Size() {
        return 1;
    }

    public static int int16Size() {
        return 2;
    }

    public static int uint16Size() {
        return 2;
    }

    public static int int32Size(int v) {
        return varIntSize(Integer.toUnsignedLong((v << 1) ^ (v >> 31)));
    }

    public static int uint32Size(long v) {
        return varIntSize(v);
    }

    public static int int64Size(long v) {
        return varIntSize((v << 1) ^ (v >> 63));
    }

    public static int uint64Size(long v) {
        return varIntSize(v);
    }

    public static int enumSize(int v) {
        return varIntSize(v);
    }

    public static int float32Size() {
        return 4;
    }

    public static int float64Size() {
        return 8;
    }

    public static int stringSize(String s) {
        if (s == null) {
            return 0;
        }
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        return varIntSize(utf8.length) + utf8.length;
    }

    public static int bytesSize(byte[] b) {
        return b == null ? 0 : varIntSize(b.length) + b.length;
    }

    public static int presenceSize(int fieldCount) {
        return (fieldCount + 7) / 8;
    }

    public static int optionalStringSize(String s) {
        return 1 + stringSize(s);
    }

    public static int optionalBytesSize(byte[] b) {
        return 1 + bytesSize(b);
    }

    public static int messageSize(PbpMessage m) {
        return m == null ? 0 : m.encodedSize();
    }

    public static int optionalMessageSize(PbpMessage m) {
        return 1 + messageSize(m);
    }

    public static int messageListSize(List<? extends PbpMessage> list) {
        if (list == null) {
            return 0;
        }
        int size = varIntSize(list.size());
        for (PbpMessage m : list) {
            size += m.encodedSize();
        }
        return size;
    }

    public static int stringListSize(List<String> list) {
        if (list == null) {
            return 0;
        }
        int size = varIntSize(list.size());
        for (String s : list) {
            size += stringSize(s);
        }
        return size;
    }

    public static <K, V> int mapSize(Map<K, V> map,
                                     java.util.function.ToIntFunction<K> keySize,
                                     java.util.function.ToIntFunction<V> valueSize) {
        if (map == null) {
            return 0;
        }
        int size = varIntSize(map.size());
        for (Map.Entry<K, V> e : map.entrySet()) {
            size += keySize.applyAsInt(e.getKey()) + valueSize.applyAsInt(e.getValue());
        }
        return size;
    }

    public static <V> int stringMapSize(Map<String, V> map, java.util.function.ToIntFunction<V> valueSize) {
        return mapSize(map, PbpEncoder::stringSize, valueSize);
    }

    // ------------------------------------------------------------ 落地

    private PbpEncoder writeRaw(byte b) {
        ensure(1);
        buf[len++] = b;
        return this;
    }

    private PbpEncoder writeRaw(byte[] src, int offset, int length) {
        if (length == 0) {
            return this;
        }
        ensure(length);
        System.arraycopy(src, offset, buf, len, length);
        len += length;
        return this;
    }

    /**
     * VarInt：每字节低 7 位有效、最高位表示续接。
     *
     * <p>形参按无符号处理（用 {@code >>>} 右移），所以负数 ZigZag 之后才能得到
     * 短编码，而 uint64 的原始位模式也能直接写入。</p>
     */
    private void writeVarInt(long value) {
        while ((value & ~0x7FL) != 0) {
            writeRaw((byte) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        writeRaw((byte) (value & 0x7F));
    }

    private void ensure(int extra) {
        int need = len + extra;
        if (need <= buf.length) {
            return;
        }
        int capacity = buf.length;
        while (capacity < need) {
            capacity = capacity < 1024 ? capacity * 2 : capacity + (capacity >> 1);
        }
        buf = Arrays.copyOf(buf, capacity);
    }

    private static void requireRange(long v, long min, long max, String type) {
        if (v < min || v > max) {
            throw badFormat(type + " 越界: " + v);
        }
    }

    private static PbpException badFormat(String message) {
        return new PbpException(PbpException.Code.BAD_FORMAT, message);
    }
}