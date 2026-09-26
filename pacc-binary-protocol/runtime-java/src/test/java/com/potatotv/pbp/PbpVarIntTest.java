package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * VarInt / ZigZag 编码测试。
 *
 * <p>断言的是<strong>字节串</strong>而不是"编码再解码能还原"：往返一致对着一份错的实现
 * 也能通过（编码和解码一起错就互相抵消了），而字节串是跨语言互通的实际契约。</p>
 */
class PbpVarIntTest {

    private static String encodeHex(java.util.function.Consumer<PbpEncoder> writer) {
        PbpEncoder enc = new PbpEncoder();
        writer.accept(enc);
        return HexFormat.of().formatHex(enc.toByteArray());
    }

    // ------------------------------------------------------------ 正数 VarInt

    @Test
    void unsignedVarIntMatchesSpecExamples() {
        // 设计文档 §3.4.1 给出的四个例子
        assertEquals("01", encodeHex(e -> e.writeUInt64(1)));
        assertEquals("7f", encodeHex(e -> e.writeUInt64(127)));
        assertEquals("8001", encodeHex(e -> e.writeUInt64(128)));
        assertEquals("ac02", encodeHex(e -> e.writeUInt64(300)));
    }

    @Test
    void unsignedVarIntBoundaries() {
        assertEquals("ff7f", encodeHex(e -> e.writeUInt64(16383)));
        assertEquals("808001", encodeHex(e -> e.writeUInt64(16384)));
        assertEquals(5, PbpEncoder.varIntSize(Integer.MAX_VALUE));
        assertEquals("ffffffff07", encodeHex(e -> e.writeUInt64(Integer.MAX_VALUE)));
        // uint32 上界也要落在 5 字节内
        assertEquals("ffffffff0f", encodeHex(e -> e.writeUInt32(0xFFFF_FFFFL)));
    }

    @Test
    void unsignedVarIntLongBoundaries() {
        // 0x7FFFFFFFFFFFFFFF 是 63 位，ceil(63/7) = 9 字节
        assertEquals(9, PbpEncoder.varIntSize(Long.MAX_VALUE));
        assertEquals("ffffffffffffffff7f", encodeHex(e -> e.writeUInt64(Long.MAX_VALUE)));
        // long 的原始位模式按无符号写入：-1 是 64 位全 1，需要 10 字节
        assertEquals(10, PbpEncoder.varIntSize(-1L));
        assertEquals("ffffffffffffffffff01", encodeHex(e -> e.writeUInt64(-1L)));
    }

    // ------------------------------------------------------------ ZigZag

    @Test
    void zigZagMapsSignToLowBits() {
        // 设计文档 §3.4.1：负数 ZigZag 之后不该占满 10 字节
        assertEquals("01", encodeHex(e -> e.writeInt64(-1L)));
        assertEquals("03", encodeHex(e -> e.writeInt64(-2L)));
        assertEquals("02", encodeHex(e -> e.writeInt64(1L)));
        assertEquals("04", encodeHex(e -> e.writeInt64(2L)));
        // -1 与 1 的编码不同，且都不超过 1 字节
        assertEquals(1, PbpEncoder.int64Size(-1L));
    }

    @Test
    void zigZagExtremes() {
        assertEquals("ffffffffffffffffff01", encodeHex(e -> e.writeInt64(Long.MIN_VALUE)));
        // ZigZag(Long.MAX_VALUE) = 0xFFFFFFFFFFFFFFFE，与 varint(-2) 的位模式相同
        assertEquals("feffffffffffffffff01", encodeHex(e -> e.writeInt64(Long.MAX_VALUE)));
        assertEquals("ffffffff0f", encodeHex(e -> e.writeInt32(Integer.MIN_VALUE)));
        assertEquals("feffffff0f", encodeHex(e -> e.writeInt32(Integer.MAX_VALUE)));
    }

    // ------------------------------------------------------------ 往返

    @Test
    void signedValuesRoundTrip() {
        long[] values = {0L, 1L, -1L, 127L, -128L, 300L, -300L,
                Integer.MAX_VALUE, Integer.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE};
        for (long v : values) {
            PbpDecoder dec = new PbpDecoder(new PbpEncoder().writeInt64(v).toByteArray());
            assertEquals(v, dec.readInt64(), "int64 往返失败: " + v);
        }
    }

    @Test
    void unsignedValuesRoundTrip() {
        long[] values = {0, 1, 127, 128, 16383, 16384, Integer.MAX_VALUE, 0xFFFF_FFFFL};
        for (long v : values) {
            PbpDecoder dec = new PbpDecoder(new PbpEncoder().writeUInt32(v).toByteArray());
            assertEquals(v, dec.readUInt32(), "uint32 往返失败: " + v);
        }
        // uint32 的上界（4294967295）不能被当成负的 int 传进来
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeUInt32(-1L)).code());
    }

    // ------------------------------------------------------------ 非法输入

    @Test
    void truncatedVarIntRejected() {
        // 续接位为 1 但后面没有字节了
        PbpException e = assertThrows(PbpException.class,
                () -> new PbpDecoder(new byte[]{(byte) 0x80}).readUInt64());
        assertEquals(PbpException.Code.TRUNCATED, e.code());
    }

    @Test
    void overlongVarIntRejected() {
        byte[] eleven = new byte[11];
        java.util.Arrays.fill(eleven, (byte) 0x80);
        PbpException e = assertThrows(PbpException.class,
                () -> new PbpDecoder(eleven).readUInt64());
        assertEquals(PbpException.Code.BAD_VARINT, e.code());
    }

    @Test
    void varIntTenthByteOverflowRejected() {
        byte[] ten = new byte[10];
        java.util.Arrays.fill(ten, (byte) 0x80);
        ten[9] = 0x7F;
        PbpException e = assertThrows(PbpException.class,
                () -> new PbpDecoder(ten).readUInt64());
        assertEquals(PbpException.Code.BAD_VARINT, e.code());
    }

    @Test
    void outOfRangeScalarsRejected() {
        PbpException e = assertThrows(PbpException.class, () -> new PbpEncoder().writeInt8(128));
        assertEquals(PbpException.Code.BAD_FORMAT, e.code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeUInt8(-1)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeUInt32(0x1_0000_0000L)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeEnum(-1)).code());
    }

    // ------------------------------------------------------------ 定长与变长字段

    @Test
    void fixedWidthFieldsAreLittleEndian() {
        assertEquals("0102", encodeHex(e -> e.writeUInt16(0x0201)));
        assertEquals("feff", encodeHex(e -> e.writeInt16(-2)));
        assertEquals("3412", encodeHex(e -> e.writeUInt16(0x1234)));
        // float32 = 1.0f 的 IEEE 754 位模式 0x3F800000，小端下发为 0000803f
        assertEquals("0000803f", encodeHex(e -> e.writeFloat32(1.0f)));
    }

    @Test
    void stringAndBytesCarryVarIntLength() {
        assertEquals("03616263", encodeHex(e -> e.writeString("abc")));
        assertEquals("03010203", encodeHex(e -> e.writeBytes(new byte[]{1, 2, 3})));
        // 空串也是合法值：长度 0 前缀仍要写出来
        assertEquals("00", encodeHex(e -> e.writeString("")));
    }

    @Test
    void stringLengthIsByteCountNotCharCount() {
        // "中" 是 3 字节 UTF-8，长度前缀必须是 3 而不是 1
        assertEquals("03e4b8ad", encodeHex(e -> e.writeString("中")));
        PbpDecoder dec = new PbpDecoder(new PbpEncoder().writeString("中").toByteArray());
        assertEquals("中", dec.readString());
    }

    @Test
    void invalidUtf8Rejected() {
        // 0xFF 永远不是合法 UTF-8 首字节
        PbpException e = assertThrows(PbpException.class,
                () -> new PbpDecoder(new byte[]{0x01, (byte) 0xFF}).readString());
        assertEquals(PbpException.Code.BAD_FORMAT, e.code());
    }

    @Test
    void declaredLengthBeyondBufferRejected() {
        // 声明 5 字节但只剩 2 字节
        PbpException e = assertThrows(PbpException.class,
                () -> new PbpDecoder(new byte[]{0x05, 'a', 'b'}).readString());
        assertEquals(PbpException.Code.TRUNCATED, e.code());
    }

    @Test
    void nullReferenceTypesRejected() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeString(null)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> new PbpEncoder().writeBytes(null)).code());
    }
}