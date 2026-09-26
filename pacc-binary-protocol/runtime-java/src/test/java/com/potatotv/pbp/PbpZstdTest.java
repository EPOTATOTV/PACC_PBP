package com.potatotv.pbp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * zstd 子集的往返与边界测试。
 *
 * <p>互操作性的最终锚点是外部参考实现的交叉验证（见 tools 下的交叉校验脚本），
 * 这里先把自洽性与规范里能静态核对的部分锁住：预定义解码表要与 RFC 8878 附录 A
 * 的数值一致，位流/序列/重复偏移的组合不能只靠"能跑通"来判断。</p>
 */
class PbpZstdTest {

    private static final int MAX = PbpFrame.MAX_PAYLOAD_SIZE;

    // ------------------------------------------------------------ 往返

    @Test
    void roundTripSmallAndEdgeInputs() {
        assertArrayEquals(new byte[0], PbpZstd.decompress(PbpZstd.compress(new byte[0]), MAX));
        assertArrayEquals(new byte[]{42}, PbpZstd.decompress(PbpZstd.compress(new byte[]{42}), MAX));
        assertArrayEquals("hello pbp".getBytes(StandardCharsets.UTF_8),
                PbpZstd.decompress(PbpZstd.compress("hello pbp".getBytes(StandardCharsets.UTF_8)), MAX));
    }

    @Test
    void roundTripHighlyRepetitiveData() {
        byte[] data = new byte[100_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ("pacc-pbp-".charAt(i % 9));
        }
        byte[] frame = PbpZstd.compress(data);
        assertTrue(frame.length < data.length / 4,
                "高重复数据应显著变小：原 " + data.length + " 压缩后 " + frame.length);
        assertArrayEquals(data, PbpZstd.decompress(frame, MAX));
    }

    @Test
    void roundTripAllSameByteUsesRleBlock() {
        byte[] data = new byte[50_000];
        Arrays.fill(data, (byte) 0x5A);
        byte[] frame = PbpZstd.compress(data);
        assertTrue(frame.length < 32, "全同字节应走 RLE 块，实际帧长 " + frame.length);
        assertArrayEquals(data, PbpZstd.decompress(frame, MAX));
    }

    @Test
    void roundTripIncompressibleDataFallsBackToRaw() {
        byte[] data = new byte[8_000];
        new Random(7).nextBytes(data);
        byte[] frame = PbpZstd.compress(data);
        assertArrayEquals(data, PbpZstd.decompress(frame, MAX));
    }

    @Test
    void roundTripMultiBlockAndBoundaries() {
        int[] sizes = {
                PbpZstd.BLOCK_MAX - 1,
                PbpZstd.BLOCK_MAX,
                PbpZstd.BLOCK_MAX + 1,
                PbpZstd.BLOCK_MAX * 2 + 12345,
        };
        for (int size : sizes) {
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) ((i * 31) ^ (i >>> 7));
            }
            assertArrayEquals(data, PbpZstd.decompress(PbpZstd.compress(data), MAX),
                    "尺寸 " + size + " 往返失败");
        }
    }

    @Test
    void roundTripRandomBattery() {
        Random rnd = new Random(20260926);
        for (int round = 0; round < 60; round++) {
            int size = rnd.nextInt(20_000);
            byte[] data = new byte[size];
            int pattern = rnd.nextInt(4);
            for (int i = 0; i < size; i++) {
                data[i] = switch (pattern) {
                    case 0 -> (byte) rnd.nextInt(256);
                    case 1 -> (byte) (i & 0x0F);
                    case 2 -> (byte) (rnd.nextInt(8) + 0x41);
                    default -> (byte) (i < size / 2 ? 0x00 : 0x7F);
                };
            }
            byte[] frame = PbpZstd.compress(data);
            assertArrayEquals(data, PbpZstd.decompress(frame, MAX),
                    "第 " + round + " 轮（尺寸 " + size + "，模式 " + pattern + "）失败");
        }
    }

    @Test
    void decompressRejectsOversizedWindowAndGarbage() {
        byte[] frame = PbpZstd.compress("abcdefabcdefabcdef".getBytes(StandardCharsets.UTF_8));
        assertThrows(PbpException.class, () -> PbpZstd.decompress(frame, 4));

        assertThrows(PbpException.class, () -> PbpZstd.decompress(new byte[]{1, 2, 3}, MAX));
        assertThrows(PbpException.class, () -> PbpZstd.decompress(
                new byte[]{(byte) 0x28, (byte) 0xB5, (byte) 0x2F, (byte) 0xFD, (byte) 0xA0}, MAX));
    }

    /** 帧尾多一个字节应被拒绝（PBP 用法里不支持多帧拼接）。 */
    @Test
    void decompressRejectsTrailingBytes() {
        byte[] frame = PbpZstd.compress("tail check".getBytes(StandardCharsets.UTF_8));
        byte[] dirty = Arrays.copyOf(frame, frame.length + 1);
        assertThrows(PbpException.class, () -> PbpZstd.decompress(dirty, MAX));
    }

    // ------------------------------------------------------------ 规范核对

    /**
     * RFC 8878 附录 A.1 的预定义字面量长度解码表逐格比对。
     *
     * <p>表里的 64 行是手工从 RFC 抄进来的：一旦表构造（散布顺序、低概率符号占位、
     * nbBits/newState 计算）哪里写歪，这里会立刻炸，而不是等到某个特定输入才暴露。</p>
     */
    @Test
    void predefinedLiteralsLengthTableMatchesRfcAppendixA() {
        ZstdFse.DTable table = ZstdFse.buildDTable(ZstdFse.LL_DEFAULT_NORM, ZstdFse.LL_DEFAULT_LOG);
        // {state, symbol, nbBits, newState}
        int[][] expected = {
                {0, 0, 4, 0}, {1, 0, 4, 16}, {2, 1, 5, 32}, {3, 3, 5, 0},
                {4, 4, 5, 0}, {5, 6, 5, 0}, {6, 7, 5, 0}, {7, 9, 5, 0},
                {8, 10, 5, 0}, {9, 12, 5, 0}, {10, 14, 6, 0}, {11, 16, 5, 0},
                {12, 18, 5, 0}, {13, 19, 5, 0}, {14, 21, 5, 0}, {15, 22, 5, 0},
                {16, 24, 5, 0}, {17, 25, 5, 32}, {18, 26, 5, 0}, {19, 27, 6, 0},
                {20, 29, 6, 0}, {21, 31, 6, 0}, {22, 0, 4, 32}, {23, 1, 4, 0},
                {24, 2, 5, 0}, {25, 4, 5, 32}, {26, 5, 5, 0}, {27, 7, 5, 32},
                {28, 8, 5, 0}, {29, 10, 5, 32}, {30, 11, 5, 0}, {31, 13, 6, 0},
                {32, 16, 5, 32}, {33, 17, 5, 0}, {34, 19, 5, 32}, {35, 20, 5, 0},
                {36, 22, 5, 32}, {37, 23, 5, 0}, {38, 25, 4, 0}, {39, 25, 4, 16},
                {40, 26, 5, 32}, {41, 28, 6, 0}, {42, 30, 6, 0}, {43, 0, 4, 48},
                {44, 1, 4, 16}, {45, 2, 5, 32}, {46, 3, 5, 32}, {47, 5, 5, 32},
                {48, 6, 5, 32}, {49, 8, 5, 32}, {50, 9, 5, 32}, {51, 11, 5, 32},
                {52, 12, 5, 32}, {53, 15, 6, 0}, {54, 17, 5, 32}, {55, 18, 5, 32},
                {56, 20, 5, 32}, {57, 21, 5, 32}, {58, 23, 5, 32}, {59, 24, 5, 32},
                {60, 35, 6, 0}, {61, 34, 6, 0}, {62, 33, 6, 0}, {63, 32, 6, 0},
        };
        for (int[] row : expected) {
            int state = row[0];
            assertEquals(row[1], table.symbols[state], "状态 " + state + " 符号不符");
            assertEquals(row[2], table.nbBits[state], "状态 " + state + " 位数不符");
            assertEquals(row[3], table.newStates[state], "状态 " + state + " 基线不符");
        }
    }

    /** 三张预定义表的占位统计必须自洽：每个符号的格子数等于分布值（-1 记 1 格）。 */
    @Test
    void predefinedTablesCoverExactlyOneCellPerProbability() {
        assertCoverage(ZstdFse.buildDTable(ZstdFse.LL_DEFAULT_NORM, ZstdFse.LL_DEFAULT_LOG),
                ZstdFse.LL_DEFAULT_NORM);
        assertCoverage(ZstdFse.buildDTable(ZstdFse.ML_DEFAULT_NORM, ZstdFse.ML_DEFAULT_LOG),
                ZstdFse.ML_DEFAULT_NORM);
        assertCoverage(ZstdFse.buildDTable(ZstdFse.OF_DEFAULT_NORM, ZstdFse.OF_DEFAULT_LOG),
                ZstdFse.OF_DEFAULT_NORM);
    }

    private static void assertCoverage(ZstdFse.DTable table, short[] norm) {
        int[] counts = new int[norm.length];
        for (int symbol : table.symbols) {
            counts[symbol]++;
        }
        for (int s = 0; s < norm.length; s++) {
            int expected = norm[s] == -1 ? 1 : norm[s];
            assertEquals(expected, counts[s], "符号 " + s + " 的格子数不符");
        }
    }

    /** 序列码表基线由位数递推出来，这里与 RFC 表 16/17 的公开数值抽查核对。 */
    @Test
    void sequenceCodeBaselinesMatchRfc() {
        assertEquals(16, ZstdFse.LL_BASE[16]);
        assertEquals(24, ZstdFse.LL_BASE[20]);
        assertEquals(48, ZstdFse.LL_BASE[24]);
        assertEquals(64, ZstdFse.LL_BASE[25]);
        assertEquals(128, ZstdFse.LL_BASE[26]);
        assertEquals(65536, ZstdFse.LL_BASE[35]);
        assertEquals(35, ZstdFse.ML_BASE[32]);
        assertEquals(43, ZstdFse.ML_BASE[36]);
        assertEquals(131, ZstdFse.ML_BASE[43]);
        assertEquals(65539, ZstdFse.ML_BASE[52]);
        assertEquals(1, ZstdFse.ofBase(2));
        assertEquals(5, ZstdFse.ofBase(3));
        assertEquals(13, ZstdFse.ofBase(4));
        assertEquals((1 << 28) - 3, ZstdFse.ofBase(28));
    }
}