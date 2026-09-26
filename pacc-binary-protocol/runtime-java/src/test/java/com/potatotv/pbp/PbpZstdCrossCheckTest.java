package com.potatotv.pbp;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 与参考实现（libzstd）的交叉校验钩子，默认跳过。
 *
 * <p>自洽的往返测试能挡住大多数错误，但挡不住「编解码两侧犯同一个错」这种系统性偏差，
 * 所以必须有第三方锚点：本测试由 {@code tools/zstd-crosscheck/crosscheck.py} 带上
 * 系统属性触发，做两件事——</p>
 *
 * <ol>
 *   <li>读取参考实现压出的帧（{@code pbp.zstd.refVectors}），逐个用我们的解码器校验；
 *       子集之外（Huffman literals 等）的帧记入 unsupported 计数，其余必须逐字节一致。</li>
 *   <li>把确定性输入电池的压缩结果导出（{@code pbp.zstd.dumpFile}），由 Python 侧用
 *       libzstd 解开比对。</li>
 * </ol>
 *
 * <p>计数写到 {@code pbp.zstd.summaryFile}，脚本据此确认"解码成功的参考帧数量够多"，
 * 防止某天所有向量都掉进 unsupported 分支后测试仍然"绿"。</p>
 */
class PbpZstdCrossCheckTest {

    @Test
    void crossCheckWithReferenceImplementation() throws IOException {
        String refVectors = System.getProperty("pbp.zstd.refVectors");
        String dumpFile = System.getProperty("pbp.zstd.dumpFile");
        Assumptions.assumeTrue(refVectors != null || dumpFile != null,
                "交叉校验未启用：由 crosscheck.py 传 -Dpbp.zstd.* 属性运行");

        int decoded = 0;
        int unsupported = 0;
        if (refVectors != null) {
            for (String line : Files.readAllLines(Path.of(refVectors))) {
                if (line.isBlank()) {
                    continue;
                }
                // 空输入的首字段就是空串，不能 trim 掉行首分隔空格
                String[] parts = line.split(" ", 2);
                byte[] input = HexFormat.of().parseHex(parts[0]);
                byte[] frame = HexFormat.of().parseHex(parts[1]);
                try {
                    byte[] decodedBytes = PbpZstd.decompress(frame, PbpFrame.MAX_PAYLOAD_SIZE);
                    assertArrayEquals(input, decodedBytes, "参考帧解压结果与原文不符");
                    decoded++;
                } catch (PbpException e) {
                    if (e.code() == PbpException.Code.UNSUPPORTED) {
                        unsupported++;
                        continue;
                    }
                    throw new AssertionError("参考帧解码失败（非子集外原因）: " + e.getMessage(), e);
                }
            }
        }

        if (dumpFile != null) {
            HexFormat hex = HexFormat.of();
            StringBuilder sb = new StringBuilder();
            for (byte[] input : battery()) {
                byte[] frame = PbpZstd.compress(input);
                assertArrayEquals(input, PbpZstd.decompress(frame, PbpFrame.MAX_PAYLOAD_SIZE),
                        "导出前先自检往返");
                sb.append(hex.formatHex(input)).append(' ').append(hex.formatHex(frame)).append('\n');
            }
            Files.writeString(Path.of(dumpFile), sb.toString());
        }

        String summaryFile = System.getProperty("pbp.zstd.summaryFile");
        if (summaryFile != null) {
            Files.writeString(Path.of(summaryFile),
                    "refDecoded=" + decoded + "\nrefUnsupported=" + unsupported + "\n");
        }
        if (refVectors != null) {
            assertTrue(decoded > 0, "没有任何参考帧被成功解码，交叉校验没有实际生效");
        }
    }

    /** 确定性输入电池：覆盖空值、边界尺寸、可压缩与不可压缩、多块。 */
    private static List<byte[]> battery() {
        List<byte[]> list = new ArrayList<>();
        int[] sizes = {0, 1, 2, 3, 17, 100, 1023, 1024, 1025, 4095, 4096, 65535, 98213};
        for (int size : sizes) {
            for (int pattern = 0; pattern < 4; pattern++) {
                list.add(make(size, pattern));
            }
        }
        list.add(make(PbpZstd.BLOCK_MAX + 1, 1));
        list.add(make(PbpZstd.BLOCK_MAX * 2 + 777, 0));
        return list;
    }

    private static final String TEXT = "pacc-pbp-zstd-subset 0123456789";

    private static byte[] make(int size, int pattern) {
        byte[] data = new byte[size];
        Random rnd = new Random(size * 31L + pattern);
        for (int i = 0; i < size; i++) {
            data[i] = switch (pattern) {
                case 0 -> (byte) rnd.nextInt(256);
                case 1 -> (byte) (i % 7 * 13);
                case 2 -> (byte) TEXT.charAt(i % TEXT.length());
                default -> (byte) (i / 64);
            };
        }
        return data;
    }
}