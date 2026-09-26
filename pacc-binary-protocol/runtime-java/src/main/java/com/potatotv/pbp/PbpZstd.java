package com.potatotv.pbp;

import java.util.Arrays;

/**
 * PBP 内置的 zstd 压缩子集（RFC 8878），零第三方依赖。
 *
 * <p>设计文档 §3.10.1 指定 zstd level 3，但 PBP 运行时必须零第三方依赖（验收项 B10），
 * 而 JDK 标准库没有 zstd。决策是自研一个<b>受限子集</b>，边界写清楚：</p>
 *
 * <ul>
 *   <li>编码只输出：单段帧（无字典、无校验和）+ Raw / RLE / 压缩块；压缩块内部固定是
 *       「原始 literals + 预定义 FSE 序列表」，序列一律用显式偏移，不发 repeat 码。</li>
 *   <li>解码是编码输出集合的超集：接受 Raw / RLE 块、Raw / RLE literals、预定义 /
 *       RLE / Repeat 序列表；对 Huffman literals、FSE_Compressed 表、字典帧、
 *       内容校验和一律显式失败（{@link PbpException.Code#UNSUPPORTED}），不做静默降级。</li>
 * </ul>
 *
 * <p>这样输出的每个字节都是合法 zstd，libzstd 能解；代价是压缩率低于 libzstd level 3
 * （没有 Huffman 与自适应 FSE 表）。这个取舍在模块文档里也要写明。</p>
 *
 * <p>另外两处与 RFC 相关、但和"压缩"本身无关的约束：帧窗口（单段帧即内容长度）不得超过
 * 调用方给的 {@code maxSize}，防解压炸弹；每个块的解压结果不得超过
 * {@code min(windowSize, 128KB)}（RFC §3.1.1.2.4）。</p>
 */
public final class PbpZstd {

    /** zstd 帧魔数（小端字节序 28 B5 2F FD）。 */
    private static final long MAGIC = 0xFD2FB528L;
    /** skippable 帧魔数的高 28 位（低 4 位是版本号，RFC §3.1.2）。 */
    private static final long SKIPPABLE_PREFIX = 0x184D2A50L;

    /** 单块上限：RFC 规定块最大 128KB，压缩前后都按这个上限校验。 */
    static final int BLOCK_MAX = 128 * 1024;

    private static final int HASH_LOG = 16;
    private static final int MIN_MATCH = 4;
    /** 匹配长度上限。ML 码最大基线 65539，取 65536 对齐 2 的幂即可。 */
    private static final int MAX_MATCH = 65536;
    /** 预定义偏移分布支持的最大偏移码（码 28），更大的偏移走不了子集。 */
    private static final int MAX_OFFSET_CODE = ZstdFse.OF_MAX_CODE_DEFAULT;

    private static final ZstdFse.CTable CT_LL =
            ZstdFse.buildCTable(ZstdFse.LL_DEFAULT_NORM, ZstdFse.LL_DEFAULT_LOG);
    private static final ZstdFse.CTable CT_OF =
            ZstdFse.buildCTable(ZstdFse.OF_DEFAULT_NORM, ZstdFse.OF_DEFAULT_LOG);
    private static final ZstdFse.CTable CT_ML =
            ZstdFse.buildCTable(ZstdFse.ML_DEFAULT_NORM, ZstdFse.ML_DEFAULT_LOG);

    private static final ZstdFse.DTable DT_LL =
            ZstdFse.buildDTable(ZstdFse.LL_DEFAULT_NORM, ZstdFse.LL_DEFAULT_LOG);
    private static final ZstdFse.DTable DT_OF =
            ZstdFse.buildDTable(ZstdFse.OF_DEFAULT_NORM, ZstdFse.OF_DEFAULT_LOG);
    private static final ZstdFse.DTable DT_ML =
            ZstdFse.buildDTable(ZstdFse.ML_DEFAULT_NORM, ZstdFse.ML_DEFAULT_LOG);

    private PbpZstd() {
    }

    // ============================================================ 压缩

    /**
     * 压缩为单个 zstd 帧。
     *
     * <p>不用抛异常的报告方式告诉调用方"压不小"：结果可能比原文长（小输入加上帧头必然如此），
     * 是否采用由调用方比较长度决定（设计文档 §3.10.1 的"压缩后更小才启用"）。</p>
     */
    public static byte[] compress(byte[] src) {
        if (src == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "待压缩数据为 null");
        }
        if (src.length > PbpFrame.MAX_PAYLOAD_SIZE) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "待压缩数据超过 " + PbpFrame.MAX_PAYLOAD_SIZE + " 字节上限: " + src.length);
        }
        OutBuffer out = new OutBuffer(src.length / 2 + 32);
        writeU32(out, MAGIC);
        // Frame_Header_Descriptor：FCS_Flag=2（4 字节长度）+ Single_Segment=1。
        // 单段帧的窗口等于内容长度，是"解码只需一块连续内存"的形态，也免去窗口描述字节。
        out.writeByte(0xA0);
        writeU32(out, src.length);
        int blocks = Math.max(1, (src.length + BLOCK_MAX - 1) / BLOCK_MAX);
        int[] head = new int[1 << HASH_LOG];
        Arrays.fill(head, -1);
        for (int b = 0; b < blocks; b++) {
            int start = b * BLOCK_MAX;
            int end = Math.min(start + BLOCK_MAX, src.length);
            emitBlock(out, src, start, end, b == blocks - 1, head);
        }
        return out.toByteArray();
    }

    /** 单个块：全同字节走 RLE，无匹配走 Raw，否则压成「原始 literals + 预定义序列」。 */
    private static void emitBlock(OutBuffer out, byte[] src, int start, int end,
                                  boolean last, int[] head) {
        int blockLen = end - start;
        if (blockLen == 0) {
            writeBlockHeader(out, last, BlockType.RAW, 0);
            return;
        }
        if (isAllSame(src, start, end)) {
            writeBlockHeader(out, last, BlockType.RLE, blockLen);
            out.writeByte(src[start]);
            return;
        }

        int[] litLens = new int[16];
        int[] matchLens = new int[16];
        int[] offsets = new int[16];
        int seqCount = 0;
        byte[] literals = new byte[blockLen];
        int litPos = 0;

        int i = start;
        int litStart = start;
        while (i + MIN_MATCH <= end) {
            int h = hash((int) readU32(src, i));
            int cand = head[h];
            head[h] = i;
            if (cand >= 0 && i - cand <= (1 << MAX_OFFSET_CODE)
                    && src[cand] == src[i] && src[cand + 1] == src[i + 1]
                    && src[cand + 2] == src[i + 2] && src[cand + 3] == src[i + 3]) {
                int mlen = MIN_MATCH;
                while (i + mlen < end && mlen < MAX_MATCH && src[cand + mlen] == src[i + mlen]) {
                    mlen++;
                }
                System.arraycopy(src, litStart, literals, litPos, i - litStart);
                litPos += i - litStart;
                if (seqCount == litLens.length) {
                    litLens = Arrays.copyOf(litLens, seqCount * 2);
                    matchLens = Arrays.copyOf(matchLens, seqCount * 2);
                    offsets = Arrays.copyOf(offsets, seqCount * 2);
                }
                litLens[seqCount] = i - litStart;
                matchLens[seqCount] = mlen;
                offsets[seqCount] = i - cand;
                seqCount++;
                i += mlen;
                litStart = i;
            } else {
                i++;
            }
        }
        System.arraycopy(src, litStart, literals, litPos, end - litStart);
        litPos += end - litStart;

        if (seqCount == 0) {
            writeBlockHeader(out, last, BlockType.RAW, blockLen);
            out.write(src, start, blockLen);
            return;
        }

        byte[] literalsSection = encodeRawLiterals(literals, litPos);
        byte[] sequencesSection = encodeSequences(litLens, matchLens, offsets, seqCount);
        int payloadLen = literalsSection.length + sequencesSection.length;
        if (payloadLen >= blockLen) {
            // RFC 建议：压完不比原文短就发 Raw 块，别让解压方白做工
            writeBlockHeader(out, last, BlockType.RAW, blockLen);
            out.write(src, start, blockLen);
            return;
        }
        writeBlockHeader(out, last, BlockType.COMPRESSED, payloadLen);
        out.write(literalsSection);
        out.write(sequencesSection);
    }

    /** 原始 literals 段：1/2/3 字节头按 Regenerated_Size 选择（RFC §3.1.1.3.1.1）。 */
    private static byte[] encodeRawLiterals(byte[] literals, int len) {
        OutBuffer out = new OutBuffer(len + 4);
        if (len <= 31) {
            out.writeByte((len << 3) | (0 << 2) | 0);
        } else if (len <= 4095) {
            out.writeByte(((len & 0xF) << 4) | (1 << 2) | 0);
            out.writeByte(len >>> 4);
        } else {
            out.writeByte(((len & 0xF) << 4) | (3 << 2) | 0);
            out.writeByte((len >>> 4) & 0xFF);
            out.writeByte(len >>> 12);
        }
        out.write(literals, 0, len);
        return out.toByteArray();
    }

    /**
     * 序列段：序号 + 三张预定义表（模式字节全 0）+ 反向编码的位流。
     *
     * <p>编码顺序严格按 RFC §3.1.1.3.2.1.2 的逆序：解码是"先读偏移额外位、再匹配长度、
     * 最后字面量长度，然后按 LL→ML→OF 更新状态"，所以编码要反过来：最后一个序列先写
     * 初始化状态，倒着写每个序列的 FSE 符号与额外位，最后冲掉三个状态。</p>
     */
    private static byte[] encodeSequences(int[] litLens, int[] matchLens, int[] offsets, int seqCount) {
        ZstdFse.BitWriter writer = new ZstdFse.BitWriter();
        ZstdFse.CState mlState = new ZstdFse.CState();
        ZstdFse.CState ofState = new ZstdFse.CState();
        ZstdFse.CState llState = new ZstdFse.CState();

        int n = seqCount - 1;
        int llCode = llCode(litLens[n]);
        int mlCode = mlCode(matchLens[n]);
        int ofCode = ZstdFse.highBit(offsets[n] + 3);
        ZstdFse.initCState2(mlState, CT_ML, mlCode);
        ZstdFse.initCState2(ofState, CT_OF, ofCode);
        ZstdFse.initCState2(llState, CT_LL, llCode);
        writer.addBits(litLens[n], ZstdFse.LL_BITS[llCode]);
        writer.addBits(matchLens[n] - ZstdFse.ML_BASE[mlCode], ZstdFse.ML_BITS[mlCode]);
        writer.addBits(offsets[n] + 3 - (1 << ofCode), ofCode);

        for (int k = seqCount - 2; k >= 0; k--) {
            llCode = llCode(litLens[k]);
            mlCode = mlCode(matchLens[k]);
            ofCode = ZstdFse.highBit(offsets[k] + 3);
            ZstdFse.encodeSymbol(writer, ofState, CT_OF, ofCode);
            ZstdFse.encodeSymbol(writer, mlState, CT_ML, mlCode);
            ZstdFse.encodeSymbol(writer, llState, CT_LL, llCode);
            writer.addBits(litLens[k], ZstdFse.LL_BITS[llCode]);
            writer.addBits(matchLens[k] - ZstdFse.ML_BASE[mlCode], ZstdFse.ML_BITS[mlCode]);
            writer.addBits(offsets[k] + 3 - (1 << ofCode), ofCode);
        }
        ZstdFse.flushCState(writer, mlState, CT_ML);
        ZstdFse.flushCState(writer, ofState, CT_OF);
        ZstdFse.flushCState(writer, llState, CT_LL);
        byte[] bitstream = writer.finish();

        OutBuffer out = new OutBuffer(bitstream.length + 8);
        if (seqCount < 128) {
            out.writeByte(seqCount);
        } else if (seqCount <= 32511) {
            out.writeByte(128 + (seqCount >>> 8));
            out.writeByte(seqCount & 0xFF);
        } else {
            int v = seqCount - 0x7F00;
            out.writeByte(255);
            out.writeByte(v & 0xFF);
            out.writeByte((v >>> 8) & 0xFF);
        }
        // 三张表全部 Predefined_Mode（位 7-6 / 5-4 / 3-2 都为 0），保留位为 0
        out.writeByte(0);
        out.write(bitstream, 0, bitstream.length);
        return out.toByteArray();
    }

    private static int llCode(int ll) {
        for (int c = ZstdFse.LL_MAX_CODE; c > 0; c--) {
            if (ll >= ZstdFse.LL_BASE[c]) {
                return c;
            }
        }
        return 0;
    }

    private static int mlCode(int ml) {
        for (int c = ZstdFse.ML_MAX_CODE; c > 0; c--) {
            if (ml >= ZstdFse.ML_BASE[c]) {
                return c;
            }
        }
        return 0;
    }

    private static int hash(int v) {
        // 先按 32 位截断再做无符号右移：乘法是 64 位算的，不截断会把高位带进下标
        return (int) (((v * 2654435761L) & 0xFFFFFFFFL) >>> (32 - HASH_LOG));
    }

    private static boolean isAllSame(byte[] src, int start, int end) {
        byte first = src[start];
        for (int i = start + 1; i < end; i++) {
            if (src[i] != first) {
                return false;
            }
        }
        return true;
    }

    private enum BlockType {
        RAW, RLE, COMPRESSED
    }

    private static void writeBlockHeader(OutBuffer out, boolean last, BlockType type, int size) {
        int typeBits = switch (type) {
            case RAW -> 0;
            case RLE -> 1;
            case COMPRESSED -> 2;
        };
        int header = (last ? 1 : 0) | (typeBits << 1) | (size << 3);
        out.writeByte(header & 0xFF);
        out.writeByte((header >>> 8) & 0xFF);
        out.writeByte((header >>> 16) & 0xFF);
    }

    // ============================================================ 解压

    /**
     * 解压一个 zstd 帧。
     *
     * @param maxSize 允许的解压结果上限；帧声明的窗口与解压输出都不得超过它
     */
    public static byte[] decompress(byte[] raw, int maxSize) {
        if (raw == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "zstd 帧为 null");
        }
        if (raw.length < 4) {
            throw new PbpException(PbpException.Code.TRUNCATED, "zstd 帧长度不足");
        }
        if (maxSize <= 0) {
            throw new PbpException(PbpException.Code.BAD_LENGTH, "解压上限必须为正: " + maxSize);
        }
        int p = 0;
        while (p + 4 <= raw.length) {
            long magic = readU32(raw, p);
            if ((magic & 0xFFFFFFF0L) == SKIPPABLE_PREFIX) {
                if (p + 8 > raw.length) {
                    throw new PbpException(PbpException.Code.TRUNCATED, "skippable 帧头不完整");
                }
                long size = readU32(raw, p + 4);
                if (p + 8 + size > raw.length) {
                    throw new PbpException(PbpException.Code.TRUNCATED, "skippable 帧内容不完整");
                }
                p += 8 + (int) size;
                continue;
            }
            if (magic != MAGIC) {
                throw new PbpException(PbpException.Code.BAD_FORMAT,
                        "不是 zstd 帧: 0x" + Long.toHexString(magic));
            }
            return decodeFrame(raw, p + 4, maxSize);
        }
        throw new PbpException(PbpException.Code.BAD_FORMAT, "没有找到 zstd 帧");
    }

    private static byte[] decodeFrame(byte[] raw, int p, int maxSize) {
        if (p >= raw.length) {
            throw new PbpException(PbpException.Code.TRUNCATED, "帧头缺失");
        }
        int fhd = raw[p++] & 0xFF;
        int fcsFlag = fhd >>> 6;
        boolean singleSegment = (fhd & 0x20) != 0;
        if ((fhd & 0x08) != 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "帧头保留位被置位");
        }
        if ((fhd & 0x04) != 0) {
            throw new PbpException(PbpException.Code.UNSUPPORTED, "子集不支持带内容校验和的帧");
        }
        if ((fhd & 0x03) != 0) {
            throw new PbpException(PbpException.Code.UNSUPPORTED, "子集不支持字典帧");
        }
        long windowSize = -1;
        if (!singleSegment) {
            if (p >= raw.length) {
                throw new PbpException(PbpException.Code.TRUNCATED, "窗口描述字节缺失");
            }
            int wd = raw[p++] & 0xFF;
            int windowLog = 10 + (wd >>> 3);
            long windowBase = 1L << windowLog;
            windowSize = windowBase + (windowBase / 8) * (wd & 7);
        }
        long contentSize = -1;
        int fcsSize = switch (fcsFlag) {
            case 0 -> singleSegment ? 1 : 0;
            case 1 -> 2;
            case 2 -> 4;
            default -> 8;
        };
        if (fcsSize > 0) {
            if (p + fcsSize > raw.length) {
                throw new PbpException(PbpException.Code.TRUNCATED, "帧内容长度字段不完整");
            }
            contentSize = readU32Or64(raw, p, fcsSize);
            if (fcsSize == 2) {
                contentSize += 256;
            }
            p += fcsSize;
        }
        if (singleSegment) {
            windowSize = contentSize;
        }
        if (windowSize > maxSize) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "帧声明的窗口 " + windowSize + " 超过允许的解压上限 " + maxSize);
        }

        FrameState state = new FrameState();
        OutBuffer out = new OutBuffer((int) Math.min(Math.max(windowSize, 64), 64 * 1024));
        long blockMax = Math.min(windowSize, BLOCK_MAX);
        while (true) {
            if (p + 3 > raw.length) {
                throw new PbpException(PbpException.Code.TRUNCATED, "块头不完整");
            }
            int header = (raw[p] & 0xFF) | ((raw[p + 1] & 0xFF) << 8) | ((raw[p + 2] & 0xFF) << 16);
            p += 3;
            boolean last = (header & 1) != 0;
            int type = (header >>> 1) & 3;
            int size = header >>> 3;
            switch (type) {
                case 0 -> {
                    if (size > blockMax) {
                        throw new PbpException(PbpException.Code.BAD_LENGTH, "Raw 块超过块上限: " + size);
                    }
                    if (p + size > raw.length) {
                        throw new PbpException(PbpException.Code.TRUNCATED, "Raw 块内容不完整");
                    }
                    out.write(raw, p, size);
                    p += size;
                }
                case 1 -> {
                    if (size > blockMax) {
                        throw new PbpException(PbpException.Code.BAD_LENGTH, "RLE 块超过块上限: " + size);
                    }
                    if (p >= raw.length) {
                        throw new PbpException(PbpException.Code.TRUNCATED, "RLE 块内容缺失");
                    }
                    byte v = raw[p++];
                    for (int i = 0; i < size; i++) {
                        out.writeByte(v);
                    }
                }
                case 2 -> p = decodeCompressedBlock(raw, p, size, out, windowSize, blockMax, state);
                default -> throw new PbpException(PbpException.Code.BAD_FORMAT, "保留块类型");
            }
            if (out.size() > maxSize) {
                throw new PbpException(PbpException.Code.BAD_LENGTH,
                        "解压输出超过上限 " + maxSize);
            }
            if (last) {
                break;
            }
        }
        if (contentSize >= 0 && out.size() != contentSize) {
            throw new PbpException(PbpException.Code.BAD_LENGTH,
                    "解压长度与帧声明不符: 声明 " + contentSize + "，实际 " + out.size());
        }
        if (p != raw.length) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "帧尾还有多余字节（不支持多帧拼接）");
        }
        return out.toByteArray();
    }

    /**
     * 压缩块：先解 literals 段，再解序列段，然后执行。
     *
     * @return 块结束后的游标位置
     */
    private static int decodeCompressedBlock(byte[] raw, int p, int blockSize, OutBuffer out,
                                             long windowSize, long blockMax, FrameState state) {
        int blockEnd = p + blockSize;
        if (blockEnd > raw.length) {
            throw new PbpException(PbpException.Code.TRUNCATED, "压缩块内容不完整");
        }
        int lp = p;
        int litType = raw[lp] & 3;
        int sizeFormat = (raw[lp] >>> 2) & 3;
        long regenSize;
        long litContentSize;
        if (litType == 0 || litType == 1) {
            if (sizeFormat == 0 || sizeFormat == 2) {
                if (lp + 1 > blockEnd) {
                    throw new PbpException(PbpException.Code.TRUNCATED, "literals 段头不完整");
                }
                regenSize = (raw[lp] & 0xFF) >>> 3;
                lp += 1;
            } else if (sizeFormat == 1) {
                if (lp + 2 > blockEnd) {
                    throw new PbpException(PbpException.Code.TRUNCATED, "literals 段头不完整");
                }
                regenSize = ((raw[lp] & 0xFF) >>> 4) + ((raw[lp + 1] & 0xFF) << 4);
                lp += 2;
            } else {
                if (lp + 3 > blockEnd) {
                    throw new PbpException(PbpException.Code.TRUNCATED, "literals 段头不完整");
                }
                regenSize = ((raw[lp] & 0xFF) >>> 4) + ((raw[lp + 1] & 0xFF) << 4)
                        + ((raw[lp + 2] & 0xFF) << 12);
                lp += 3;
            }
            litContentSize = litType == 0 ? regenSize : 1;
        } else {
            throw new PbpException(PbpException.Code.UNSUPPORTED,
                    "子集不支持 Huffman literals（类型 " + litType + "）");
        }
        if (regenSize > blockMax) {
            throw new PbpException(PbpException.Code.BAD_LENGTH, "literals 长度超过块上限: " + regenSize);
        }
        if (lp + litContentSize > blockEnd) {
            throw new PbpException(PbpException.Code.TRUNCATED, "literals 内容不完整");
        }
        byte[] literals;
        if (litType == 0) {
            literals = Arrays.copyOfRange(raw, lp, lp + (int) regenSize);
        } else {
            literals = new byte[(int) regenSize];
            Arrays.fill(literals, raw[lp]);
        }
        lp += (int) litContentSize;

        int blockStart = out.size();
        int q = lp;
        if (q >= blockEnd) {
            throw new PbpException(PbpException.Code.TRUNCATED, "序列段缺失");
        }
        int b0 = raw[q++] & 0xFF;
        int nbSeq;
        if (b0 == 0) {
            nbSeq = 0;
        } else if (b0 < 128) {
            nbSeq = b0;
        } else if (b0 < 255) {
            if (q >= blockEnd) {
                throw new PbpException(PbpException.Code.TRUNCATED, "序列数不完整");
            }
            nbSeq = ((b0 - 128) << 8) + (raw[q++] & 0xFF);
        } else {
            if (q + 2 > blockEnd) {
                throw new PbpException(PbpException.Code.TRUNCATED, "序列数不完整");
            }
            nbSeq = (raw[q] & 0xFF) + ((raw[q + 1] & 0xFF) << 8) + 0x7F00;
            q += 2;
        }
        if (nbSeq == 0) {
            if (q != blockEnd) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "无序列时序列段仍有剩余字节");
            }
            out.write(literals, 0, literals.length);
            return blockEnd;
        }

        int modes = raw[q++] & 0xFF;
        if ((modes & 0x03) != 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "序列模式字节保留位非零");
        }
        int llMode = modes >>> 6;
        int ofMode = (modes >>> 4) & 3;
        int mlMode = (modes >>> 2) & 3;
        int[] cursor = {q};
        ZstdFse.DTable llTable = resolveTable(llMode, DT_LL, ZstdFse.LL_MAX_CODE, state.ll,
                raw, cursor, blockEnd, "字面量长度");
        ZstdFse.DTable ofTable = resolveTable(ofMode, DT_OF, ZstdFse.OF_MAX_CODE_DEFAULT, state.of,
                raw, cursor, blockEnd, "偏移");
        ZstdFse.DTable mlTable = resolveTable(mlMode, DT_ML, ZstdFse.ML_MAX_CODE, state.ml,
                raw, cursor, blockEnd, "匹配长度");
        state.ll = llTable;
        state.of = ofTable;
        state.ml = mlTable;
        q = cursor[0];
        if (q >= blockEnd) {
            throw new PbpException(PbpException.Code.TRUNCATED, "序列位流缺失");
        }

        ZstdFse.BitReader reader = new ZstdFse.BitReader(raw, q, blockEnd - q);
        int llState = reader.readBits(llTable.log);
        int ofState = reader.readBits(ofTable.log);
        int mlState = reader.readBits(mlTable.log);
        int litPos = 0;
        for (int s = 0; s < nbSeq; s++) {
            int llSymbol = llTable.symbols[llState];
            int ofSymbol = ofTable.symbols[ofState];
            int mlSymbol = mlTable.symbols[mlState];
            // 额外位读取顺序：偏移 → 匹配长度 → 字面量长度（RFC §3.1.1.3.2.1.2）
            long offsetValue = (1L << ofSymbol) + reader.readBits(ZstdFse.ofBits(ofSymbol));
            int matchLen = ZstdFse.ML_BASE[mlSymbol] + reader.readBits(ZstdFse.ML_BITS[mlSymbol]);
            int litLen = ZstdFse.LL_BASE[llSymbol] + reader.readBits(ZstdFse.LL_BITS[llSymbol]);

            long offset = resolveOffset(offsetValue, ofSymbol,
                    ZstdFse.LL_BASE[llSymbol] == 0, state.prevOffsets);

            if (litPos + (long) litLen > literals.length) {
                throw new PbpException(PbpException.Code.BAD_LENGTH, "字面量长度超出 literals 段");
            }
            out.write(literals, litPos, litLen);
            litPos += litLen;
            if (offset <= 0 || offset > out.size() || offset > windowSize) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "匹配偏移越界: " + offset);
            }
            if (out.size() + (long) matchLen - blockStart > blockMax) {
                throw new PbpException(PbpException.Code.BAD_LENGTH, "块解压尺寸超过块上限");
            }
            out.copyFromSelf((int) offset, matchLen);

            if (s + 1 < nbSeq) {
                // 状态更新顺序：字面量长度 → 匹配长度 → 偏移（RFC §3.1.1.3.2.1.2）
                llState = llTable.newStates[llState] + reader.readBits(llTable.nbBits[llState]);
                mlState = mlTable.newStates[mlState] + reader.readBits(mlTable.nbBits[mlState]);
                ofState = ofTable.newStates[ofState] + reader.readBits(ofTable.nbBits[ofState]);
            }
        }
        if (!reader.consumedAll()) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "序列位流未被完整消费");
        }
        out.write(literals, litPos, literals.length - litPos);
        if (out.size() - blockStart > blockMax) {
            throw new PbpException(PbpException.Code.BAD_LENGTH, "块解压尺寸超过块上限");
        }
        return blockEnd;
    }

    /**
     * 解析 offset 的实际值，含 repeat 偏移的历史维护。
     *
     * <p>规则按 RFC §3.1.1.5 与参考实现：code ≥ 2 是显式偏移（值 = 2^code + 额外位，实际偏移 = 值 - 3）；
     * code 0/1 是 repeat 码，当前序列字面量长度为 0 时整组 repeat 偏移要错一位
     * （值 1→repeat2、2→repeat3、3→repeat1 - 1）。</p>
     */
    private static long resolveOffset(long offsetValue, int ofCode, boolean litLenZero, long[] prev) {
        if (ofCode >= 2) {
            long offset = offsetValue - 3;
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = offset;
            return offset;
        }
        int shift = litLenZero ? 1 : 0;
        if (ofCode == 0) {
            long offset = prev[shift];
            prev[1] = prev[shift == 0 ? 1 : 0];
            prev[0] = offset;
            return offset;
        }
        // ofCode == 1：值 2 或 3
        long value = offsetValue + shift;
        long offset = value == 3 ? prev[0] - 1 : prev[(int) value];
        if (offset <= 0) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "repeat 偏移回退到 0，数据损坏");
        }
        if (value != 1) {
            prev[2] = prev[1];
        }
        prev[1] = prev[0];
        prev[0] = offset;
        return offset;
    }

    /** 解析序列表：预定义直接用、RLE 读一个符号字节、Repeat 复用上一块、自定义表在子集之外。 */
    private static ZstdFse.DTable resolveTable(int mode, ZstdFse.DTable predefined, int maxSymbol,
                                               ZstdFse.DTable previous, byte[] raw, int[] cursor,
                                               int blockEnd, String what) {
        int q = cursor[0];
        ZstdFse.DTable table;
        switch (mode) {
            case 0 -> table = predefined;
            case 1 -> {
                if (q >= blockEnd) {
                    throw new PbpException(PbpException.Code.TRUNCATED, what + " 表的 RLE 符号缺失");
                }
                int symbol = raw[q++] & 0xFF;
                if (symbol > maxSymbol) {
                    throw new PbpException(PbpException.Code.BAD_FORMAT,
                            what + " 表符号越界: " + symbol);
                }
                table = ZstdFse.DTable.rle(symbol);
            }
            case 3 -> {
                if (previous == null) {
                    throw new PbpException(PbpException.Code.BAD_FORMAT,
                            what + " 表声明 Repeat 模式，但没有可复用的表");
                }
                table = previous;
            }
            default -> throw new PbpException(PbpException.Code.UNSUPPORTED,
                    "子集不支持 " + what + " 的 FSE_Compressed 表");
        }
        cursor[0] = q;
        return table;
    }

    /** 跨块保留的帧级状态：repeat 偏移历史与上一组序列表。 */
    private static final class FrameState {
        final long[] prevOffsets = {1, 4, 8};
        ZstdFse.DTable ll;
        ZstdFse.DTable of;
        ZstdFse.DTable ml;
    }

    // ============================================================ 工具

    private static long readU32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private static long readU32Or64(byte[] b, int off, int size) {
        long v = 0;
        for (int i = 0; i < size; i++) {
            v |= (b[off + i] & 0xFFL) << (8 * i);
        }
        return v;
    }

    private static void writeU32(OutBuffer out, long v) {
        out.writeByte((int) (v & 0xFF));
        out.writeByte((int) ((v >>> 8) & 0xFF));
        out.writeByte((int) ((v >>> 16) & 0xFF));
        out.writeByte((int) ((v >>> 24) & 0xFF));
    }

    /** 可增长输出缓冲：解码侧要按字节下标回拷（匹配重叠），所以不用 ByteArrayOutputStream。 */
    private static final class OutBuffer {

        private byte[] buf;
        private int len;

        OutBuffer(int capacity) {
            this.buf = new byte[Math.max(64, capacity)];
        }

        int size() {
            return len;
        }

        void writeByte(int v) {
            ensure(1);
            buf[len++] = (byte) v;
        }

        void write(byte[] src) {
            write(src, 0, src.length);
        }

        void write(byte[] src, int off, int count) {
            if (count == 0) {
                return;
            }
            ensure(count);
            System.arraycopy(src, off, buf, len, count);
            len += count;
        }

        /** 从已输出内容里回拷一段（支持重叠，即匹配长度大于偏移的情况）。 */
        void copyFromSelf(int offset, int count) {
            ensure(count);
            int from = len - offset;
            for (int i = 0; i < count; i++) {
                buf[len + i] = buf[from + i];
            }
            len += count;
        }

        byte[] toByteArray() {
            return Arrays.copyOf(buf, len);
        }

        private void ensure(int extra) {
            if (len + extra <= buf.length) {
                return;
            }
            int capacity = buf.length;
            while (capacity < len + extra) {
                capacity = capacity < 1024 ? capacity * 2 : capacity + (capacity >> 1);
            }
            buf = Arrays.copyOf(buf, capacity);
        }
    }
}