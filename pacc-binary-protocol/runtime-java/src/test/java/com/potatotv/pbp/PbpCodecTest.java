package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 载荷 ↔ 帧组装层的测试：压缩策略、标志位、以及"压缩决策必须可复算"这条签名前提。
 */
class PbpCodecTest {

    /** 最小消息实现：一个 bytes 字段，方便凑出超过阈值的大载荷。 */
    private static final class Blob implements PbpMessage {

        static final int MESSAGE_ID = 0x2001;
        private byte[] data = new byte[0];

        Blob(byte[] data) {
            this.data = data;
        }

        @Override
        public int messageId() {
            return MESSAGE_ID;
        }

        @Override
        public void encode(PbpEncoder enc) {
            enc.writeBytes(data);
        }

        @Override
        public void decode(PbpDecoder dec) {
            data = dec.readBytes();
        }

        @Override
        public int encodedSize() {
            return PbpEncoder.bytesSize(data);
        }
    }

    private static byte[] repetitive(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) ("pacc-pbp".charAt(i % 8));
        }
        return data;
    }

    /** 消息里的 bytes 字段，即帧载荷。 */
    private static byte[] encodedOf(byte[] data) {
        return PbpCodec.payloadOf(new Blob(data));
    }

    /** 从帧里解出的 bytes 字段内容。 */
    private static byte[] dataOf(PbpFrame frame) {
        Blob blob = new Blob(new byte[0]);
        blob.decode(new PbpDecoder(PbpCodec.payloadOf(frame)));
        return blob.data;
    }

    @Test
    void payloadAtOrBelowThresholdIsNotCompressed() {
        // bytesSize(1022) = 2 字节长度前缀 + 1022 = 1024，正好落在阈值上
        byte[] payload = encodedOf(repetitive(1022));
        assertEquals(PbpCodec.COMPRESS_THRESHOLD, payload.length);
        assertSame(payload, PbpCodec.maybeCompress(payload),
                "阈值以内必须原样返回，调用方用引用判断是否启用");

        PbpFrame frame = PbpCodec.frameOf(new Blob(repetitive(1022)), 123L);
        assertFalse(frame.compressed());
        assertArrayEquals(payload, frame.payload());
    }

    @Test
    void compressiblePayloadAboveThresholdIsCompressed() {
        Blob blob = new Blob(repetitive(64 * 1024));
        PbpFrame frame = PbpCodec.frameOf(blob, 123L);
        assertTrue(frame.compressed(), "重复载荷超过阈值应当启用压缩");
        assertTrue(frame.payloadLength() < 8 * 1024,
                "重复载荷应显著变小，实际 " + frame.payloadLength());
        assertArrayEquals(repetitive(64 * 1024), dataOf(frame));
    }

    @Test
    void incompressiblePayloadAboveThresholdStaysPlain() {
        byte[] data = new byte[4096];
        new Random(11).nextBytes(data);
        PbpFrame frame = PbpCodec.frameOf(new Blob(data), 1L);
        assertFalse(frame.compressed(), "压不小的载荷不该被标记为压缩");
        assertArrayEquals(encodedOf(data), frame.payload());
    }

    /** 压缩决策必须只依赖载荷：两次组装要得到逐字节相同的帧，否则签名无法复算。 */
    @Test
    void frameAssemblyIsDeterministic() {
        Blob blob = new Blob(repetitive(32 * 1024));
        byte[] first = PbpCodec.frameOf(blob, 999L).encode();
        byte[] second = PbpCodec.frameOf(blob, 999L).encode();
        assertArrayEquals(first, second);
    }

    /** 压缩帧走完整链路：签名覆盖面读的是压缩后的载荷，验签端能拿字段重算出同一串字节。 */
    @Test
    void signedCompressedFrameVerifiesFromFields() {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        Blob blob = new Blob(repetitive(20 * 1024));
        PbpFrame frame = PbpCodec.frameOf(blob, 555L);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(key, frame.signingInput()));
        byte[] raw = signed.encode();

        PbpFrame parsed = PbpFrame.parse(raw);
        assertTrue(parsed.compressed());
        assertTrue(PbpCrypto.verifyHmac(key, parsed.signingInput(), parsed.signature()));

        // 验签端只有字段时也走同一条组装路径
        assertArrayEquals(parsed.signingInput(), PbpCodec.frameOf(blob, 555L).signingInput());
        Blob decoded = new Blob(new byte[0]);
        decoded.decode(new PbpDecoder(PbpCodec.payloadOf(parsed)));
        assertArrayEquals(blob.data, decoded.data);
    }

    /**
     * 压缩载荷被改动后必须能被签名拦下。
     *
     * <p>注意 zstd 帧自身没有内容校验和（子集里也不发），改动 literals 字节可能只是解出
     * 不同内容而不报错——载荷完整性是 PBP 层 HMAC 的职责，所以这里验的是签名。</p>
     */
    @Test
    void tamperedCompressedPayloadFailsSignature() {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        PbpFrame frame = PbpCodec.frameOf(new Blob(repetitive(8 * 1024)), 7L);
        PbpFrame signed = frame.withSignature(PbpCrypto.hmacSha256(key, frame.signingInput()));
        byte[] raw = signed.encode();

        int flipAt = PbpFrame.HEADER_SIZE + frame.payloadLength() / 2;
        raw[flipAt] ^= 0x40;
        PbpFrame parsed = PbpFrame.parse(raw);
        assertFalse(PbpCrypto.verifyHmac(key, parsed.signingInput(), parsed.signature()),
                "改动压缩载荷后签名必须失效");
    }

    @Test
    void decompressionBombRejected() {
        byte[] plain = repetitive(1 << 20);
        byte[] packed = PbpZstd.compress(plain);
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class, () -> PbpZstd.decompress(packed, 1024)).code());
    }

    @Test
    void truncatedStreamRejected() {
        byte[] packed = PbpZstd.compress(repetitive(64 * 1024));
        byte[] truncated = Arrays.copyOf(packed, packed.length / 2);
        assertThrows(PbpException.class,
                () -> PbpZstd.decompress(truncated, 64 * 1024));
    }

    @Test
    void nullAndBadBoundsRejected() {
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpZstd.compress(null)).code());
        assertEquals(PbpException.Code.BAD_FORMAT,
                assertThrows(PbpException.class, () -> PbpZstd.decompress(null, 1024)).code());
        assertEquals(PbpException.Code.TRUNCATED,
                assertThrows(PbpException.class, () -> PbpZstd.decompress(new byte[]{1, 2, 3}, 1024)).code());
        assertEquals(PbpException.Code.BAD_LENGTH,
                assertThrows(PbpException.class,
                        () -> PbpZstd.decompress(PbpZstd.compress(repetitive(64)), 0)).code());
    }

    /** 压缩后的帧必须能被独立解析器识别出压缩标志，而不是只在组装层里"自说自话"。 */
    @Test
    void compressedFlagSurvivesRoundTripThroughBytes() {
        List<byte[]> sizes = new ArrayList<>();
        sizes.add(repetitive(1025));
        sizes.add(repetitive(70 * 1024));
        sizes.add(repetitive(PbpZstd.BLOCK_MAX * 2 + 17));
        for (byte[] data : sizes) {
            PbpFrame frame = PbpCodec.frameOf(new Blob(data), 42L);
            PbpFrame parsed = PbpFrame.parse(frame.encode());
            assertTrue(parsed.compressed(), "尺寸 " + data.length + " 的压缩标志在字节往返后丢了");
            assertArrayEquals(data, dataOf(parsed));
        }
    }
}