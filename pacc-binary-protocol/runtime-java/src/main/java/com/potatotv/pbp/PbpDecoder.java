package com.potatotv.pbp;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * PBP 二进制解码器。
 *
 * <p>与 {@link PbpEncoder} 严格镜像：同样的字段顺序、同样的类型宽度。</p>
 *
 * <p>所有读取都做边界检查，越界一律抛 {@link PbpException} 而不是返回默认值 ——
 * 输入来自网络，静默截断会把"攻击者截断了载荷"变成"对端发了个全零消息"，
 * 后者在日志上完全看不出来。</p>
 */
public final class PbpDecoder {

    /** 集合元素个数上界：挡住伪造长度的循环消耗，正常载荷远远够用。 */
    private static final int MAX_COLLECTION_SIZE = 1 << 20;

    private final byte[] buf;
    private final int limit;
    private int pos;

    public PbpDecoder(byte[] buf) {
        this(buf, 0, buf.length);
    }

    public PbpDecoder(byte[] buf, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > buf.length) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "解码窗口越界: offset=" + offset + " length=" + length + " capacity=" + buf.length);
        }
        this.buf = buf;
        this.pos = offset;
        this.limit = offset + length;
    }

    /** 尚未读取的字节数。 */
    public int remaining() {
        return limit - pos;
    }

    public boolean hasRemaining() {
        return pos < limit;
    }

    /** 已消费的字节数（相对解码窗口起点）。 */
    public int position() {
        return pos;
    }

    /**
     * 丢弃剩余字节。
     *
     * <p>用于向前兼容：新客户端在末尾追加了字段、旧服务端不认识时，
     * 读完自己认识的字段后把尾巴丢掉即可（设计文档 §3.11.1）。</p>
     */
    public void skipRemaining() {
        pos = limit;
    }

    // ------------------------------------------------------------ 标量

    public boolean readBool() {
        byte b = readRaw();
        if (b != 0 && b != 1) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "bool 字段只能是 0/1，读到 " + b);
        }
        return b == 1;
    }

    public int readInt8() {
        return readRaw();
    }

    public int readUInt8() {
        return readRaw() & 0xFF;
    }

    public int readInt16() {
        int lo = readRaw() & 0xFF;
        int hi = readRaw() & 0xFF;
        return (short) ((hi << 8) | lo);
    }

    public int readUInt16() {
        int lo = readRaw() & 0xFF;
        int hi = readRaw() & 0xFF;
        return (hi << 8) | lo;
    }

    public int readInt32() {
        int z = (int) readVarInt();
        return (z >>> 1) ^ -(z & 1);
    }

    public long readUInt32() {
        long v = readVarInt();
        if (v > 0xFFFF_FFFFL) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "uint32 溢出: " + v);
        }
        return v;
    }

    public long readInt64() {
        long z = readVarInt();
        return (z >>> 1) ^ -(z & 1);
    }

    /** 返回 long 的原始位模式，调用方按无符号解释。 */
    public long readUInt64() {
        return readVarInt();
    }

    public int readEnum() {
        long v = readUInt32();
        if (v > Integer.MAX_VALUE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "enum 值溢出: " + v);
        }
        return (int) v;
    }

    public float readFloat32() {
        int bits = (readRaw() & 0xFF)
                | ((readRaw() & 0xFF) << 8)
                | ((readRaw() & 0xFF) << 16)
                | ((readRaw() & 0xFF) << 24);
        return Float.intBitsToFloat(bits);
    }

    public double readFloat64() {
        long bits = 0;
        for (int i = 0; i < 8; i++) {
            bits |= (long) (readRaw() & 0xFF) << (i * 8);
        }
        return Double.longBitsToDouble(bits);
    }

    // ------------------------------------------------------------ 变长

    public String readString() {
        int length = readLength();
        String s = decodeUtf8(pos, length);
        pos += length;
        return s;
    }

    public byte[] readBytes() {
        int length = readLength();
        byte[] out = new byte[length];
        System.arraycopy(buf, pos, out, 0, length);
        pos += length;
        return out;
    }

    // ------------------------------------------------------------ 可空字段

    /**
     * 读取 {@code fieldCount} 个连续可空字段的存在位图。
     *
     * <p>位图各字节的低位对应更靠前的字段，与 {@link PbpEncoder#writePresence} 一致。</p>
     */
    public boolean[] readPresence(int fieldCount) {
        if (fieldCount < 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "可空字段数为负: " + fieldCount);
        }
        int byteCount = (fieldCount + 7) / 8;
        boolean[] present = new boolean[fieldCount];
        for (int i = 0; i < byteCount; i++) {
            int bits = readRaw() & 0xFF;
            for (int bit = 0; bit < 8; bit++) {
                int idx = i * 8 + bit;
                if (idx < fieldCount) {
                    present[idx] = (bits & (1 << bit)) != 0;
                }
            }
        }
        return present;
    }

    public String readOptionalString() {
        return readPresence(1)[0] ? readString() : null;
    }

    public byte[] readOptionalBytes() {
        return readPresence(1)[0] ? readBytes() : null;
    }

    public <T extends PbpMessage> T readOptionalMessage(Supplier<T> factory) {
        return readPresence(1)[0] ? readMessage(factory) : null;
    }

    // ------------------------------------------------------------ 消息与集合

    public <T extends PbpMessage> T readMessage(Supplier<T> factory) {
        T msg = factory.get();
        msg.decode(this);
        return msg;
    }

    public <T extends PbpMessage> List<T> readMessageList(Supplier<T> factory) {
        int count = readCount("list");
        List<T> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(readMessage(factory));
        }
        return list;
    }

    public List<String> readStringList() {
        return readList(ArrayList::new, PbpDecoder::readString);
    }

    /**
     * 通用列表。
     *
     * <p>元素个数上界单独设限（见 {@link #MAX_COLLECTION_SIZE}）：不能拿"每元素至少 1 字节"
     * 去卡，因为无字段的嵌套消息合法地编码成 0 字节，那样会误杀正常载荷。</p>
     */
    public <T> List<T> readList(Supplier<List<T>> factory, Function<PbpDecoder, T> elementReader) {
        int count = readCount("list");
        List<T> list = factory.get();
        for (int i = 0; i < count; i++) {
            list.add(elementReader.apply(this));
        }
        return list;
    }

    public <K, V> Map<K, V> readMap(Supplier<Map<K, V>> factory,
                                    Function<PbpDecoder, K> keyReader,
                                    Function<PbpDecoder, V> valueReader) {
        int count = readCount("map");
        Map<K, V> map = factory.get();
        for (int i = 0; i < count; i++) {
            K key = keyReader.apply(this);
            V value = valueReader.apply(this);
            map.put(key, value);
        }
        return map;
    }

    /** 键固定为 string 的映射，默认用 LinkedHashMap 保持线上顺序（便于比对与复现）。 */
    public <V> Map<String, V> readStringMap(Function<PbpDecoder, V> valueReader) {
        return readMap(LinkedHashMap::new, PbpDecoder::readString, valueReader);
    }

    // ------------------------------------------------------------ 落地

    private byte readRaw() {
        if (pos >= limit) {
            throw new PbpException(PbpException.Code.TRUNCATED,
                    "读取越界: 位置 " + pos + " 已达上限 " + limit);
        }
        return buf[pos++];
    }

    /** VarInt 解码，最多 10 字节；超过 10 字节或第 10 字节溢出 64 位一律拒绝。 */
    private long readVarInt() {
        long value = 0;
        for (int i = 0; i < PbpEncoder.MAX_VARINT_BYTES; i++) {
            byte b = readRaw();
            if (i == 9 && (b & 0xFE) != 0) {
                throw new PbpException(PbpException.Code.BAD_VARINT, "VarInt 第 10 字节溢出 64 位");
            }
            value |= (long) (b & 0x7F) << (i * 7);
            if ((b & 0x80) == 0) {
                return value;
            }
        }
        throw new PbpException(PbpException.Code.BAD_VARINT, "VarInt 超过 10 字节");
    }

    private int readLength() {
        long length = readVarInt();
        if (length < 0 || length > remaining()) {
            throw new PbpException(PbpException.Code.TRUNCATED,
                    "变长字段声明长度 " + length + " 超出剩余 " + remaining() + " 字节");
        }
        return (int) length;
    }

    private int readCount(String what) {
        long count = readVarInt();
        if (count < 0 || count > MAX_COLLECTION_SIZE) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    what + " 元素个数越界: " + count);
        }
        return (int) count;
    }

    /** 严格 UTF-8 解码：非法字节序列直接失败，避免把篡改内容当有效字符串用下去。 */
    private String decodeUtf8(int offset, int length) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(buf, offset, length))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "字符串字段不是合法 UTF-8", e);
        }
    }
}