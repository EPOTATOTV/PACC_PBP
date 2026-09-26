using System;

namespace Potatotv.Pbp;

/// <summary>
/// PBP 内置的 zstd 压缩子集（RFC 8878），零第三方依赖。
///
/// <p>编码只输出：单段帧（无字典、无校验和）+ Raw / RLE / 压缩块；压缩块内部固定是
/// 「原始 literals + 预定义 FSE 序列表」，序列一律用显式偏移，不发 repeat 码。</p>
///
/// <p>解码是编码输出集合的超集：接受 Raw / RLE 块、Raw / RLE literals、预定义 /
/// RLE / Repeat 序列表；对 Huffman literals、FSE_Compressed 表、字典帧、内容校验和
/// 一律显式失败（<see cref="PbpErrorCode.Unsupported"/>），不做静默降级。</p>
///
/// <p>帧窗口不得超过调用方给的 <c>maxSize</c>，防解压炸弹；每个块的解压结果不得超过
/// <c>min(windowSize, 128KB)</c>。</p>
/// </summary>
public static class PbpZstd
{
    /// <summary>zstd 帧魔数（小端字节序 28 B5 2F FD）。</summary>
    private const ulong Magic = 0xFD2FB528UL;

    /// <summary>skippable 帧魔数的高 28 位（低 4 位是版本号）。</summary>
    private const ulong SkippablePrefix = 0x184D2A50UL;

    /// <summary>单块上限：RFC 规定块最大 128KB。</summary>
    public const int BlockMax = 128 * 1024;

    private const int HashLog = 16;
    private const int MinMatch = 4;

    /// <summary>匹配长度上限。ML 码最大基线 65539，取 65536 对齐 2 的幂即可。</summary>
    private const int MaxMatch = 65536;

    /// <summary>预定义偏移分布支持的最大偏移码（码 28），更大的偏移走不了子集。</summary>
    private const int MaxOffsetCode = ZstdFse.OfMaxCodeDefault;

    private static readonly ZstdFse.CTable CtLl =
        ZstdFse.BuildCTable(ZstdFse.LlDefaultNorm, ZstdFse.LlDefaultLog);

    private static readonly ZstdFse.CTable CtOf =
        ZstdFse.BuildCTable(ZstdFse.OfDefaultNorm, ZstdFse.OfDefaultLog);

    private static readonly ZstdFse.CTable CtMl =
        ZstdFse.BuildCTable(ZstdFse.MlDefaultNorm, ZstdFse.MlDefaultLog);

    private static readonly ZstdFse.DTable DtLl =
        ZstdFse.BuildDTable(ZstdFse.LlDefaultNorm, ZstdFse.LlDefaultLog);

    private static readonly ZstdFse.DTable DtOf =
        ZstdFse.BuildDTable(ZstdFse.OfDefaultNorm, ZstdFse.OfDefaultLog);

    private static readonly ZstdFse.DTable DtMl =
        ZstdFse.BuildDTable(ZstdFse.MlDefaultNorm, ZstdFse.MlDefaultLog);

    // ============================================================ 压缩

    /// <summary>
    /// 压缩为单个 zstd 帧。
    ///
    /// <p>不用异常告诉调用方"压不小"：结果可能比原文长（小输入加上帧头必然如此），
    /// 是否采用由调用方比较长度决定。</p>
    /// </summary>
    public static byte[] Compress(byte[] src)
    {
        if (src == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "待压缩数据为 null");
        }
        if (src.Length > PbpFrame.MaxPayloadSize)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "待压缩数据超过 " + PbpFrame.MaxPayloadSize + " 字节上限: " + src.Length);
        }
        OutBuffer outBuf = new OutBuffer(src.Length / 2 + 32);
        WriteU32(outBuf, Magic);
        // Frame_Header_Descriptor：FCS_Flag=2（4 字节长度）+ Single_Segment=1。
        outBuf.WriteByte(0xA0);
        WriteU32(outBuf, (ulong)src.Length);
        int blocks = Math.Max(1, (src.Length + BlockMax - 1) / BlockMax);
        int[] head = new int[1 << HashLog];
        Array.Fill(head, -1);
        for (int b = 0; b < blocks; b++)
        {
            int start = b * BlockMax;
            int end = Math.Min(start + BlockMax, src.Length);
            EmitBlock(outBuf, src, start, end, b == blocks - 1, head);
        }
        return outBuf.ToByteArray();
    }

    /// <summary>单个块：全同字节走 RLE，无匹配走 Raw，否则压成「原始 literals + 预定义序列」。</summary>
    private static void EmitBlock(OutBuffer outBuf, byte[] src, int start, int end, bool last, int[] head)
    {
        int blockLen = end - start;
        if (blockLen == 0)
        {
            WriteBlockHeader(outBuf, last, BlockType.Raw, 0);
            return;
        }
        if (IsAllSame(src, start, end))
        {
            WriteBlockHeader(outBuf, last, BlockType.Rle, blockLen);
            outBuf.WriteByte(src[start]);
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
        while (i + MinMatch <= end)
        {
            int h = Hash(ReadU32(src, i));
            int cand = head[h];
            head[h] = i;
            if (cand >= 0 && i - cand <= (1 << MaxOffsetCode)
                && src[cand] == src[i] && src[cand + 1] == src[i + 1]
                && src[cand + 2] == src[i + 2] && src[cand + 3] == src[i + 3])
            {
                int mlen = MinMatch;
                while (i + mlen < end && mlen < MaxMatch && src[cand + mlen] == src[i + mlen])
                {
                    mlen++;
                }
                Array.Copy(src, litStart, literals, litPos, i - litStart);
                litPos += i - litStart;
                if (seqCount == litLens.Length)
                {
                    Array.Resize(ref litLens, seqCount * 2);
                    Array.Resize(ref matchLens, seqCount * 2);
                    Array.Resize(ref offsets, seqCount * 2);
                }
                litLens[seqCount] = i - litStart;
                matchLens[seqCount] = mlen;
                offsets[seqCount] = i - cand;
                seqCount++;
                i += mlen;
                litStart = i;
            }
            else
            {
                i++;
            }
        }
        Array.Copy(src, litStart, literals, litPos, end - litStart);
        litPos += end - litStart;

        if (seqCount == 0)
        {
            WriteBlockHeader(outBuf, last, BlockType.Raw, blockLen);
            outBuf.Write(src, start, blockLen);
            return;
        }

        byte[] literalsSection = EncodeRawLiterals(literals, litPos);
        byte[] sequencesSection = EncodeSequences(litLens, matchLens, offsets, seqCount);
        int payloadLen = literalsSection.Length + sequencesSection.Length;
        if (payloadLen >= blockLen)
        {
            // RFC 建议：压完不比原文短就发 Raw 块，别让解压方白做工
            WriteBlockHeader(outBuf, last, BlockType.Raw, blockLen);
            outBuf.Write(src, start, blockLen);
            return;
        }
        WriteBlockHeader(outBuf, last, BlockType.Compressed, payloadLen);
        outBuf.Write(literalsSection, 0, literalsSection.Length);
        outBuf.Write(sequencesSection, 0, sequencesSection.Length);
    }

    /// <summary>原始 literals 段：1/2/3 字节头按 Regenerated_Size 选择。</summary>
    private static byte[] EncodeRawLiterals(byte[] literals, int len)
    {
        OutBuffer outBuf = new OutBuffer(len + 4);
        if (len <= 31)
        {
            outBuf.WriteByte((len << 3) | (0 << 2) | 0);
        }
        else if (len <= 4095)
        {
            outBuf.WriteByte(((len & 0xF) << 4) | (1 << 2) | 0);
            outBuf.WriteByte(len >> 4);
        }
        else
        {
            outBuf.WriteByte(((len & 0xF) << 4) | (3 << 2) | 0);
            outBuf.WriteByte((len >> 4) & 0xFF);
            outBuf.WriteByte(len >> 12);
        }
        outBuf.Write(literals, 0, len);
        return outBuf.ToByteArray();
    }

    /// <summary>
    /// 序列段：序号 + 三张预定义表（模式字节全 0）+ 反向编码的位流。
    ///
    /// <p>编码顺序严格按 RFC 的逆序：解码是"先读偏移额外位、再匹配长度、最后字面量长度，
    /// 然后按 LL→ML→OF 更新状态"，所以编码反过来。</p>
    /// </summary>
    private static byte[] EncodeSequences(int[] litLens, int[] matchLens, int[] offsets, int seqCount)
    {
        ZstdFse.BitWriter writer = new ZstdFse.BitWriter();
        ZstdFse.CState mlState = new ZstdFse.CState();
        ZstdFse.CState ofState = new ZstdFse.CState();
        ZstdFse.CState llState = new ZstdFse.CState();

        int n = seqCount - 1;
        int llCode = LlCode(litLens[n]);
        int mlCode = MlCode(matchLens[n]);
        int ofCode = ZstdFse.HighBit(offsets[n] + 3);
        ZstdFse.InitCState2(mlState, CtMl, mlCode);
        ZstdFse.InitCState2(ofState, CtOf, ofCode);
        ZstdFse.InitCState2(llState, CtLl, llCode);
        writer.AddBits(litLens[n], ZstdFse.LlBits[llCode]);
        writer.AddBits(matchLens[n] - ZstdFse.MlBase[mlCode], ZstdFse.MlBits[mlCode]);
        writer.AddBits(offsets[n] + 3 - (1 << ofCode), ofCode);

        for (int k = seqCount - 2; k >= 0; k--)
        {
            llCode = LlCode(litLens[k]);
            mlCode = MlCode(matchLens[k]);
            ofCode = ZstdFse.HighBit(offsets[k] + 3);
            ZstdFse.EncodeSymbol(writer, ofState, CtOf, ofCode);
            ZstdFse.EncodeSymbol(writer, mlState, CtMl, mlCode);
            ZstdFse.EncodeSymbol(writer, llState, CtLl, llCode);
            writer.AddBits(litLens[k], ZstdFse.LlBits[llCode]);
            writer.AddBits(matchLens[k] - ZstdFse.MlBase[mlCode], ZstdFse.MlBits[mlCode]);
            writer.AddBits(offsets[k] + 3 - (1 << ofCode), ofCode);
        }
        ZstdFse.FlushCState(writer, mlState, CtMl);
        ZstdFse.FlushCState(writer, ofState, CtOf);
        ZstdFse.FlushCState(writer, llState, CtLl);
        byte[] bitstream = writer.Finish();

        OutBuffer outBuf = new OutBuffer(bitstream.Length + 8);
        if (seqCount < 128)
        {
            outBuf.WriteByte(seqCount);
        }
        else if (seqCount <= 32511)
        {
            outBuf.WriteByte(128 + (seqCount >> 8));
            outBuf.WriteByte(seqCount & 0xFF);
        }
        else
        {
            int v = seqCount - 0x7F00;
            outBuf.WriteByte(255);
            outBuf.WriteByte(v & 0xFF);
            outBuf.WriteByte((v >> 8) & 0xFF);
        }
        // 三张表全部 Predefined_Mode（位 7-6 / 5-4 / 3-2 都为 0），保留位为 0
        outBuf.WriteByte(0);
        outBuf.Write(bitstream, 0, bitstream.Length);
        return outBuf.ToByteArray();
    }

    private static int LlCode(int ll)
    {
        for (int c = ZstdFse.LlMaxCode; c > 0; c--)
        {
            if (ll >= ZstdFse.LlBase[c])
            {
                return c;
            }
        }
        return 0;
    }

    private static int MlCode(int ml)
    {
        for (int c = ZstdFse.MlMaxCode; c > 0; c--)
        {
            if (ml >= ZstdFse.MlBase[c])
            {
                return c;
            }
        }
        return 0;
    }

    private static int Hash(uint v)
    {
        // 先按 32 位截断再取高 16 位：乘法是 64 位算的，不截断会把高位带进下标
        return (int)((uint)((ulong)v * 2654435761UL) >> (32 - HashLog));
    }

    private static bool IsAllSame(byte[] src, int start, int end)
    {
        byte first = src[start];
        for (int i = start + 1; i < end; i++)
        {
            if (src[i] != first)
            {
                return false;
            }
        }
        return true;
    }

    private enum BlockType
    {
        Raw,
        Rle,
        Compressed,
    }

    private static void WriteBlockHeader(OutBuffer outBuf, bool last, BlockType type, int size)
    {
        int typeBits = type switch
        {
            BlockType.Raw => 0,
            BlockType.Rle => 1,
            _ => 2,
        };
        int header = (last ? 1 : 0) | (typeBits << 1) | (size << 3);
        outBuf.WriteByte(header & 0xFF);
        outBuf.WriteByte((header >> 8) & 0xFF);
        outBuf.WriteByte((header >> 16) & 0xFF);
    }

    // ============================================================ 解压

    /// <summary>解压一个 zstd 帧。</summary>
    /// <param name="raw">zstd 帧字节。</param>
    /// <param name="maxSize">允许的解压结果上限；帧声明的窗口与解压输出都不得超过它。</param>
    public static byte[] Decompress(byte[] raw, int maxSize)
    {
        if (raw == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "zstd 帧为 null");
        }
        if (raw.Length < 4)
        {
            throw new PbpException(PbpErrorCode.Truncated, "zstd 帧长度不足");
        }
        if (maxSize <= 0)
        {
            throw new PbpException(PbpErrorCode.BadLength, "解压上限必须为正: " + maxSize);
        }
        int p = 0;
        while (p + 4 <= raw.Length)
        {
            ulong magic = ReadU32(raw, p);
            if ((magic & 0xFFFFFFF0UL) == SkippablePrefix)
            {
                if (p + 8 > raw.Length)
                {
                    throw new PbpException(PbpErrorCode.Truncated, "skippable 帧头不完整");
                }
                ulong size = ReadU32(raw, p + 4);
                if ((ulong)p + 8 + size > (ulong)raw.Length)
                {
                    throw new PbpException(PbpErrorCode.Truncated, "skippable 帧内容不完整");
                }
                p += 8 + (int)size;
                continue;
            }
            if (magic != Magic)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "不是 zstd 帧: 0x" + magic.ToString("x"));
            }
            return DecodeFrame(raw, p + 4, maxSize);
        }
        throw new PbpException(PbpErrorCode.BadFormat, "没有找到 zstd 帧");
    }

    private static byte[] DecodeFrame(byte[] raw, int p, int maxSize)
    {
        if (p >= raw.Length)
        {
            throw new PbpException(PbpErrorCode.Truncated, "帧头缺失");
        }
        int fhd = raw[p++] & 0xFF;
        int fcsFlag = fhd >> 6;
        bool singleSegment = (fhd & 0x20) != 0;
        if ((fhd & 0x08) != 0)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "帧头保留位被置位");
        }
        if ((fhd & 0x04) != 0)
        {
            throw new PbpException(PbpErrorCode.Unsupported, "子集不支持带内容校验和的帧");
        }
        if ((fhd & 0x03) != 0)
        {
            throw new PbpException(PbpErrorCode.Unsupported, "子集不支持字典帧");
        }
        long windowSize = -1;
        if (!singleSegment)
        {
            if (p >= raw.Length)
            {
                throw new PbpException(PbpErrorCode.Truncated, "窗口描述字节缺失");
            }
            int wd = raw[p++] & 0xFF;
            int windowLog = 10 + (wd >> 3);
            long windowBase = 1L << windowLog;
            windowSize = windowBase + (windowBase / 8) * (wd & 7);
        }
        long contentSize = -1;
        int fcsSize = fcsFlag switch
        {
            0 => singleSegment ? 1 : 0,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if (fcsSize > 0)
        {
            if (p + fcsSize > raw.Length)
            {
                throw new PbpException(PbpErrorCode.Truncated, "帧内容长度字段不完整");
            }
            contentSize = ReadU32Or64(raw, p, fcsSize);
            if (fcsSize == 2)
            {
                contentSize += 256;
            }
            p += fcsSize;
        }
        if (singleSegment)
        {
            windowSize = contentSize;
        }
        if (windowSize > maxSize)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "帧声明的窗口 " + windowSize + " 超过允许的解压上限 " + maxSize);
        }

        FrameState state = new FrameState();
        OutBuffer outBuf = new OutBuffer((int)Math.Min(Math.Max(windowSize, 64), 64 * 1024));
        long blockMax = Math.Min(windowSize, BlockMax);
        while (true)
        {
            if (p + 3 > raw.Length)
            {
                throw new PbpException(PbpErrorCode.Truncated, "块头不完整");
            }
            int header = (raw[p] & 0xFF) | ((raw[p + 1] & 0xFF) << 8) | ((raw[p + 2] & 0xFF) << 16);
            p += 3;
            bool last = (header & 1) != 0;
            int type = (header >> 1) & 3;
            int size = header >> 3;
            switch (type)
            {
                case 0:
                    if (size > blockMax)
                    {
                        throw new PbpException(PbpErrorCode.BadLength, "Raw 块超过块上限: " + size);
                    }
                    if ((long)p + size > raw.Length)
                    {
                        throw new PbpException(PbpErrorCode.Truncated, "Raw 块内容不完整");
                    }
                    outBuf.Write(raw, p, size);
                    p += size;
                    break;
                case 1:
                    if (size > blockMax)
                    {
                        throw new PbpException(PbpErrorCode.BadLength, "RLE 块超过块上限: " + size);
                    }
                    if (p >= raw.Length)
                    {
                        throw new PbpException(PbpErrorCode.Truncated, "RLE 块内容缺失");
                    }
                    byte v = raw[p++];
                    for (int k = 0; k < size; k++)
                    {
                        outBuf.WriteByte(v);
                    }
                    break;
                case 2:
                    p = DecodeCompressedBlock(raw, p, size, outBuf, windowSize, blockMax, state);
                    break;
                default:
                    throw new PbpException(PbpErrorCode.BadFormat, "保留块类型");
            }
            if (outBuf.Size > maxSize)
            {
                throw new PbpException(PbpErrorCode.BadLength, "解压输出超过上限 " + maxSize);
            }
            if (last)
            {
                break;
            }
        }
        if (contentSize >= 0 && outBuf.Size != contentSize)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "解压长度与帧声明不符: 声明 " + contentSize + "，实际 " + outBuf.Size);
        }
        if (p != raw.Length)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "帧尾还有多余字节（不支持多帧拼接）");
        }
        return outBuf.ToByteArray();
    }

    /// <summary>压缩块：先解 literals 段，再解序列段，然后执行。返回块结束后的游标位置。</summary>
    private static int DecodeCompressedBlock(byte[] raw, int p, int blockSize, OutBuffer outBuf,
                                             long windowSize, long blockMax, FrameState state)
    {
        int blockEnd = p + blockSize;
        if (blockEnd > raw.Length)
        {
            throw new PbpException(PbpErrorCode.Truncated, "压缩块内容不完整");
        }
        int lp = p;
        int litType = raw[lp] & 3;
        int sizeFormat = (raw[lp] >> 2) & 3;
        long regenSize;
        long litContentSize;
        if (litType == 0 || litType == 1)
        {
            if (sizeFormat == 0 || sizeFormat == 2)
            {
                if (lp + 1 > blockEnd)
                {
                    throw new PbpException(PbpErrorCode.Truncated, "literals 段头不完整");
                }
                regenSize = (raw[lp] & 0xFF) >> 3;
                lp += 1;
            }
            else if (sizeFormat == 1)
            {
                if (lp + 2 > blockEnd)
                {
                    throw new PbpException(PbpErrorCode.Truncated, "literals 段头不完整");
                }
                regenSize = ((raw[lp] & 0xFF) >> 4) + ((raw[lp + 1] & 0xFF) << 4);
                lp += 2;
            }
            else
            {
                if (lp + 3 > blockEnd)
                {
                    throw new PbpException(PbpErrorCode.Truncated, "literals 段头不完整");
                }
                regenSize = ((raw[lp] & 0xFF) >> 4) + ((raw[lp + 1] & 0xFF) << 4)
                    + ((raw[lp + 2] & 0xFF) << 12);
                lp += 3;
            }
            litContentSize = litType == 0 ? regenSize : 1;
        }
        else
        {
            throw new PbpException(PbpErrorCode.Unsupported,
                "子集不支持 Huffman literals（类型 " + litType + "）");
        }
        if (regenSize > blockMax)
        {
            throw new PbpException(PbpErrorCode.BadLength, "literals 长度超过块上限: " + regenSize);
        }
        if (lp + litContentSize > blockEnd)
        {
            throw new PbpException(PbpErrorCode.Truncated, "literals 内容不完整");
        }
        byte[] literals;
        if (litType == 0)
        {
            literals = new byte[(int)regenSize];
            Array.Copy(raw, lp, literals, 0, (int)regenSize);
        }
        else
        {
            literals = new byte[(int)regenSize];
            Array.Fill(literals, raw[lp]);
        }
        lp += (int)litContentSize;

        int blockStart = outBuf.Size;
        int q = lp;
        if (q >= blockEnd)
        {
            throw new PbpException(PbpErrorCode.Truncated, "序列段缺失");
        }
        int b0 = raw[q++] & 0xFF;
        int nbSeq;
        if (b0 == 0)
        {
            nbSeq = 0;
        }
        else if (b0 < 128)
        {
            nbSeq = b0;
        }
        else if (b0 < 255)
        {
            if (q >= blockEnd)
            {
                throw new PbpException(PbpErrorCode.Truncated, "序列数不完整");
            }
            nbSeq = ((b0 - 128) << 8) + (raw[q++] & 0xFF);
        }
        else
        {
            if (q + 2 > blockEnd)
            {
                throw new PbpException(PbpErrorCode.Truncated, "序列数不完整");
            }
            nbSeq = (raw[q] & 0xFF) + ((raw[q + 1] & 0xFF) << 8) + 0x7F00;
            q += 2;
        }
        if (nbSeq == 0)
        {
            if (q != blockEnd)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "无序列时序列段仍有剩余字节");
            }
            outBuf.Write(literals, 0, literals.Length);
            return blockEnd;
        }

        int modes = raw[q++] & 0xFF;
        if ((modes & 0x03) != 0)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "序列模式字节保留位非零");
        }
        int llMode = modes >> 6;
        int ofMode = (modes >> 4) & 3;
        int mlMode = (modes >> 2) & 3;
        int[] cursor = { q };
        ZstdFse.DTable llTable = ResolveTable(llMode, DtLl, ZstdFse.LlMaxCode, state.Ll,
            raw, cursor, blockEnd, "字面量长度");
        ZstdFse.DTable ofTable = ResolveTable(ofMode, DtOf, ZstdFse.OfMaxCodeDefault, state.Of,
            raw, cursor, blockEnd, "偏移");
        ZstdFse.DTable mlTable = ResolveTable(mlMode, DtMl, ZstdFse.MlMaxCode, state.Ml,
            raw, cursor, blockEnd, "匹配长度");
        state.Ll = llTable;
        state.Of = ofTable;
        state.Ml = mlTable;
        q = cursor[0];
        if (q >= blockEnd)
        {
            throw new PbpException(PbpErrorCode.Truncated, "序列位流缺失");
        }

        ZstdFse.BitReader reader = new ZstdFse.BitReader(raw, q, blockEnd - q);
        int llState = reader.ReadBits(llTable.Log);
        int ofState = reader.ReadBits(ofTable.Log);
        int mlState = reader.ReadBits(mlTable.Log);
        int litPos = 0;
        for (int s = 0; s < nbSeq; s++)
        {
            int llSymbol = llTable.Symbols[llState];
            int ofSymbol = ofTable.Symbols[ofState];
            int mlSymbol = mlTable.Symbols[mlState];
            // 额外位读取顺序：偏移 → 匹配长度 → 字面量长度
            long offsetValue = (1L << ofSymbol) + reader.ReadBits(ZstdFse.OfBits(ofSymbol));
            int matchLen = ZstdFse.MlBase[mlSymbol] + reader.ReadBits(ZstdFse.MlBits[mlSymbol]);
            int litLen = ZstdFse.LlBase[llSymbol] + reader.ReadBits(ZstdFse.LlBits[llSymbol]);

            long offset = ResolveOffset(offsetValue, ofSymbol,
                ZstdFse.LlBase[llSymbol] == 0, state.PrevOffsets);

            if (litPos + (long)litLen > literals.Length)
            {
                throw new PbpException(PbpErrorCode.BadLength, "字面量长度超出 literals 段");
            }
            outBuf.Write(literals, litPos, litLen);
            litPos += litLen;
            if (offset <= 0 || offset > outBuf.Size || offset > windowSize)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "匹配偏移越界: " + offset);
            }
            if (outBuf.Size + (long)matchLen - blockStart > blockMax)
            {
                throw new PbpException(PbpErrorCode.BadLength, "块解压尺寸超过块上限");
            }
            outBuf.CopyFromSelf((int)offset, matchLen);

            if (s + 1 < nbSeq)
            {
                // 状态更新顺序：字面量长度 → 匹配长度 → 偏移
                llState = llTable.NewStates[llState] + reader.ReadBits(llTable.NbBits[llState]);
                mlState = mlTable.NewStates[mlState] + reader.ReadBits(mlTable.NbBits[mlState]);
                ofState = ofTable.NewStates[ofState] + reader.ReadBits(ofTable.NbBits[ofState]);
            }
        }
        if (!reader.ConsumedAll())
        {
            throw new PbpException(PbpErrorCode.BadFormat, "序列位流未被完整消费");
        }
        outBuf.Write(literals, litPos, literals.Length - litPos);
        if (outBuf.Size - blockStart > blockMax)
        {
            throw new PbpException(PbpErrorCode.BadLength, "块解压尺寸超过块上限");
        }
        return blockEnd;
    }

    /// <summary>
    /// 解析 offset 的实际值，含 repeat 偏移的历史维护。
    ///
    /// <p>code ≥ 2 是显式偏移（值 = 2^code + 额外位，实际偏移 = 值 - 3）；code 0/1 是
    /// repeat 码，当前序列字面量长度为 0 时整组 repeat 偏移要错一位。</p>
    /// </summary>
    private static long ResolveOffset(long offsetValue, int ofCode, bool litLenZero, long[] prev)
    {
        if (ofCode >= 2)
        {
            long offset = offsetValue - 3;
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = offset;
            return offset;
        }
        int shift = litLenZero ? 1 : 0;
        if (ofCode == 0)
        {
            long offset = prev[shift];
            prev[1] = prev[shift == 0 ? 1 : 0];
            prev[0] = offset;
            return offset;
        }
        // ofCode == 1：值 2 或 3
        long value = offsetValue + shift;
        long resolved = value == 3 ? prev[0] - 1 : prev[(int)value];
        if (resolved <= 0)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "repeat 偏移回退到 0，数据损坏");
        }
        if (value != 1)
        {
            prev[2] = prev[1];
        }
        prev[1] = prev[0];
        prev[0] = resolved;
        return resolved;
    }

    /// <summary>解析序列表：预定义直接用、RLE 读一个符号字节、Repeat 复用上一块、自定义表在子集之外。</summary>
    private static ZstdFse.DTable ResolveTable(int mode, ZstdFse.DTable predefined, int maxSymbol,
                                               ZstdFse.DTable? previous, byte[] raw, int[] cursor,
                                               int blockEnd, string what)
    {
        int q = cursor[0];
        ZstdFse.DTable table;
        switch (mode)
        {
            case 0:
                table = predefined;
                break;
            case 1:
                if (q >= blockEnd)
                {
                    throw new PbpException(PbpErrorCode.Truncated, what + " 表的 RLE 符号缺失");
                }
                int symbol = raw[q++] & 0xFF;
                if (symbol > maxSymbol)
                {
                    throw new PbpException(PbpErrorCode.BadFormat, what + " 表符号越界: " + symbol);
                }
                table = ZstdFse.DTable.Rle(symbol);
                break;
            case 3:
                if (previous == null)
                {
                    throw new PbpException(PbpErrorCode.BadFormat,
                        what + " 表声明 Repeat 模式，但没有可复用的表");
                }
                table = previous;
                break;
            default:
                throw new PbpException(PbpErrorCode.Unsupported,
                    "子集不支持 " + what + " 的 FSE_Compressed 表");
        }
        cursor[0] = q;
        return table;
    }

    /// <summary>跨块保留的帧级状态：repeat 偏移历史与上一组序列表。</summary>
    private sealed class FrameState
    {
        internal readonly long[] PrevOffsets = { 1, 4, 8 };
        internal ZstdFse.DTable? Ll;
        internal ZstdFse.DTable? Of;
        internal ZstdFse.DTable? Ml;
    }

    // ============================================================ 工具

    private static uint ReadU32(byte[] b, int off) =>
        (uint)((b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24));

    private static long ReadU32Or64(byte[] b, int off, int size)
    {
        long v = 0;
        for (int i = 0; i < size; i++)
        {
            v |= (long)(b[off + i] & 0xFF) << (8 * i);
        }
        return v;
    }

    private static void WriteU32(OutBuffer outBuf, ulong v)
    {
        outBuf.WriteByte((int)(v & 0xFF));
        outBuf.WriteByte((int)((v >> 8) & 0xFF));
        outBuf.WriteByte((int)((v >> 16) & 0xFF));
        outBuf.WriteByte((int)((v >> 24) & 0xFF));
    }

    /// <summary>可增长输出缓冲：解码侧要按字节下标回拷（匹配重叠），所以不用 MemoryStream。</summary>
    private sealed class OutBuffer
    {
        private byte[] buf;
        private int len;

        internal OutBuffer(int capacity)
        {
            buf = new byte[Math.Max(64, capacity)];
        }

        internal int Size => len;

        internal void WriteByte(int v)
        {
            Ensure(1);
            buf[len++] = (byte)v;
        }

        internal void Write(byte[] src, int off, int count)
        {
            if (count == 0)
            {
                return;
            }
            Ensure(count);
            Array.Copy(src, off, buf, len, count);
            len += count;
        }

        /// <summary>从已输出内容里回拷一段（支持重叠，即匹配长度大于偏移的情况）。</summary>
        internal void CopyFromSelf(int offset, int count)
        {
            Ensure(count);
            int from = len - offset;
            for (int i = 0; i < count; i++)
            {
                buf[len + i] = buf[from + i];
            }
            len += count;
        }

        internal byte[] ToByteArray()
        {
            byte[] outBytes = new byte[len];
            Array.Copy(buf, outBytes, len);
            return outBytes;
        }

        private void Ensure(int extra)
        {
            if (len + extra <= buf.Length)
            {
                return;
            }
            int capacity = buf.Length;
            while (capacity < len + extra)
            {
                capacity = capacity < 1024 ? capacity * 2 : capacity + (capacity >> 1);
            }
            byte[] grown = new byte[capacity];
            Array.Copy(buf, grown, len);
            buf = grown;
        }
    }
}