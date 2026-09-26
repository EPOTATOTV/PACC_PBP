using System;
using System.Numerics;

namespace Potatotv.Pbp;

/// <summary>
/// zstd 子集（RFC 8878）用到的熵编码与比特流原语。
///
/// <p>编码侧只输出「原始 literals + 预定义 FSE 序列表」，解码侧在此之上额外认
/// Raw / RLE 块与 RLE / Repeat 序列表。不认 Huffman literals、FSE_Compressed 表、
/// 字典与内容校验和，遇到就显式失败。</p>
///
/// <p>位流约定容易搞反：编码侧按「先写的位在低位」把比特流正向写入字节数组；
/// 解码侧从最后一个字节的最高有效位开始反向读取，读到结束标记位后的 0 填充为止。
/// 反读时先读到的位是字段的高位。</p>
/// </summary>
internal static class ZstdFse
{
    // ------------------------------------------------------------ 序列码表

    /// <summary>字面量长度码的额外位数（RFC 8878 表 16）。</summary>
    internal static readonly int[] LlBits =
    {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3,
        4, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 16,
    };

    /// <summary>匹配长度码的额外位数（RFC 8878 表 17）。</summary>
    internal static readonly int[] MlBits =
    {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3,
        4, 4, 5, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    };

    /// <summary>字面量长度码的基线，由上一段的基线 + 跨度累加出来。</summary>
    internal static readonly int[] LlBase = BuildBase(LlBits, 0);

    /// <summary>匹配长度码的基线（码 0 表示匹配长度 3）。</summary>
    internal static readonly int[] MlBase = BuildBase(MlBits, 3);

    /// <summary>偏移码的基线：码 0/1 用于 repeat 偏移，码 ≥2 时基线是 2^code - 3。</summary>
    internal static int OfBase(int code) => code < 2 ? code : (1 << code) - 3;

    /// <summary>偏移码的额外位数等于码值本身。</summary>
    internal static int OfBits(int code) => code;

    internal const int LlMaxCode = 35;

    internal const int MlMaxCode = 52;

    /// <summary>预定义偏移分布只到码 28，更大的偏移必须走自定义表，子集里不支持。</summary>
    internal const int OfMaxCodeDefault = 28;

    private static int[] BuildBase(int[] bits, int first)
    {
        int[] baseValues = new int[bits.Length];
        baseValues[0] = first;
        for (int i = 1; i < bits.Length; i++)
        {
            baseValues[i] = baseValues[i - 1] + (bits[i - 1] == 0 ? 1 : (1 << bits[i - 1]));
        }
        return baseValues;
    }

    // ------------------------------------------------------------ 预定义分布

    /// <summary>字面量长度码的预定义分布（精度 6）。</summary>
    internal static readonly short[] LlDefaultNorm =
    {
        4, 3, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2,
        2, 3, 2, 1, 1, 1, 1, 1,
        -1, -1, -1, -1,
    };

    /// <summary>匹配长度码的预定义分布（精度 6）。</summary>
    internal static readonly short[] MlDefaultNorm =
    {
        1, 4, 3, 2, 2, 2, 2, 2,
        2, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, -1, -1,
        -1, -1, -1, -1, -1,
    };

    /// <summary>偏移码的预定义分布（精度 5，最大码 28）。</summary>
    internal static readonly short[] OfDefaultNorm =
    {
        1, 1, 1, 1, 1, 1, 2, 2,
        2, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
        -1, -1, -1, -1, -1,
    };

    internal const int LlDefaultLog = 6;
    internal const int MlDefaultLog = 6;
    internal const int OfDefaultLog = 5;

    /// <summary>32 位值的最高有效位下标；入参为 0 时返回 0。</summary>
    internal static int HighBit(int v) => 31 - BitOperations.LeadingZeroCount((uint)v);

    // ------------------------------------------------------------ 比特流写入

    /// <summary>
    /// 比特流写入器：按「先写的位在低位」累积，字节小端落到缓冲。
    /// 写完所有数据后调用 <see cref="Finish"/> 补结束标记位并补零。
    /// </summary>
    internal sealed class BitWriter
    {
        private byte[] buf = new byte[64];
        private int len;
        private long acc;
        private int accBits;

        /// <summary>写入 <paramref name="n"/> 位（取 value 的低 n 位）；单次最多 32 位。</summary>
        internal void AddBits(long value, int n)
        {
            if (n < 0 || n > 32)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "位流写入长度非法: " + n);
            }
            if (n == 0)
            {
                return;
            }
            acc |= (value & ((1L << n) - 1)) << accBits;
            accBits += n;
            while (accBits >= 8)
            {
                Ensure(1);
                buf[len++] = (byte)acc;
                acc = (long)((ulong)acc >> 8);
                accBits -= 8;
            }
        }

        /// <summary>收尾：写结束标记位（单个 1），把剩余位补零成整字节。</summary>
        internal byte[] Finish()
        {
            AddBits(1, 1);
            if (accBits > 0)
            {
                Ensure(1);
                buf[len++] = (byte)acc;
                acc = 0;
                accBits = 0;
            }
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
                capacity *= 2;
            }
            byte[] grown = new byte[capacity];
            Array.Copy(buf, grown, len);
            buf = grown;
        }
    }

    // ------------------------------------------------------------ 比特流读取

    /// <summary>
    /// 比特流读取器：从指定区间的末字节开始反向读取。
    ///
    /// <p>末字节必须含结束标记位（最高的一个 1），标记之上的 0 是填充、不参与取值；
    /// 读到区间起点以下即视为损坏，直接抛错而不是继续读零。</p>
    /// </summary>
    internal sealed class BitReader
    {
        private readonly byte[] src;
        private readonly int minBit;
        private int pos;

        internal BitReader(byte[] src, int offset, int length)
        {
            if (length <= 0)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "位流长度为 0");
            }
            if (offset < 0 || offset + length > src.Length)
            {
                throw new PbpException(PbpErrorCode.Truncated, "位流区间越界");
            }
            int last = src[offset + length - 1] & 0xFF;
            if (last == 0)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "位流末字节为 0：缺少结束标记位");
            }
            this.src = src;
            minBit = offset * 8;
            pos = (offset + length - 1) * 8 + HighBit(last) - 1;
        }

        /// <summary>读取 <paramref name="n"/> 位；先读到的位是高位。</summary>
        internal int ReadBits(int n)
        {
            if (n == 0)
            {
                return 0;
            }
            if (pos - n + 1 < minBit)
            {
                throw new PbpException(PbpErrorCode.BadFormat,
                    "位流越界：需要 " + n + " 位，实际只剩 " + (pos - minBit + 1));
            }
            int v = 0;
            for (int i = 0; i < n; i++)
            {
                v = (v << 1) | ((src[pos >> 3] >> (pos & 7)) & 1);
                pos--;
            }
            return v;
        }

        /// <summary>位流是否已被恰好读完。</summary>
        internal bool ConsumedAll() => pos < minBit;
    }

    // ------------------------------------------------------------ 解码表

    /// <summary>
    /// FSE 解码表：每个状态给出符号、下一状态的额外位数与基线。
    /// 构造按 RFC §4.1.1：概率 &lt;1 的符号各占一个格子、从表尾倒退分配；
    /// 其余符号按自然序、以 step 散布占格。
    /// </summary>
    internal sealed class DTable
    {
        internal readonly int Log;
        internal readonly int[] Symbols;
        internal readonly int[] NbBits;
        internal readonly int[] NewStates;

        internal DTable(int log, int[] symbols, int[] nbBits, int[] newStates)
        {
            Log = log;
            Symbols = symbols;
            NbBits = nbBits;
            NewStates = newStates;
        }

        /// <summary>RLE_Mode 的表：只有一个符号，不消费任何状态位。</summary>
        internal static DTable Rle(int symbol) => new DTable(0, new[] { symbol }, new[] { 0 }, new[] { 0 });
    }

    internal static DTable BuildDTable(short[] norm, int tableLog)
    {
        int maxSymbol = norm.Length - 1;
        int tableSize = 1 << tableLog;
        int[] symbols = new int[tableSize];
        int[] symbolNext = new int[maxSymbol + 1];
        int highThreshold = tableSize - 1;
        for (int s = 0; s <= maxSymbol; s++)
        {
            if (norm[s] == -1)
            {
                symbols[highThreshold--] = s;
                symbolNext[s] = 1;
            }
            else
            {
                symbolNext[s] = norm[s];
            }
        }
        int step = (tableSize >> 1) + (tableSize >> 3) + 3;
        int mask = tableSize - 1;
        int position = 0;
        for (int s = 0; s <= maxSymbol; s++)
        {
            for (int i = 0; i < norm[s]; i++)
            {
                symbols[position] = s;
                position = (position + step) & mask;
                while (position > highThreshold)
                {
                    position = (position + step) & mask;
                }
            }
        }
        int[] nbBits = new int[tableSize];
        int[] newStates = new int[tableSize];
        for (int u = 0; u < tableSize; u++)
        {
            int next = symbolNext[symbols[u]]++;
            int bits = tableLog - HighBit(next);
            nbBits[u] = bits;
            newStates[u] = (next << bits) - tableSize;
        }
        return new DTable(tableLog, symbols, nbBits, newStates);
    }

    // ------------------------------------------------------------ 编码表

    /// <summary>
    /// FSE 编码表：状态迁移用 <see cref="StateTable"/> 与每个符号的位宽/偏移描述。
    /// deltaNbBits 同时编码「输出位数」与「下一状态基址」。
    /// </summary>
    internal sealed class CTable
    {
        internal readonly int Log;
        internal readonly int[] StateTable;
        internal readonly long[] DeltaNbBits;
        internal readonly int[] DeltaFindState;

        internal CTable(int log, int[] stateTable, long[] deltaNbBits, int[] deltaFindState)
        {
            Log = log;
            StateTable = stateTable;
            DeltaNbBits = deltaNbBits;
            DeltaFindState = deltaFindState;
        }
    }

    internal static CTable BuildCTable(short[] norm, int tableLog)
    {
        int maxSymbol = norm.Length - 1;
        int tableSize = 1 << tableLog;
        int mask = tableSize - 1;
        int step = (tableSize >> 1) + (tableSize >> 3) + 3;

        int[] cumul = new int[maxSymbol + 2];
        int[] tableSymbol = new int[tableSize];
        int highThreshold = tableSize - 1;
        for (int s = 0; s <= maxSymbol; s++)
        {
            if (norm[s] == -1)
            {
                cumul[s + 1] = cumul[s] + 1;
                tableSymbol[highThreshold--] = s;
            }
            else
            {
                cumul[s + 1] = cumul[s] + norm[s];
            }
        }
        int position = 0;
        for (int s = 0; s <= maxSymbol; s++)
        {
            for (int i = 0; i < norm[s]; i++)
            {
                tableSymbol[position] = s;
                position = (position + step) & mask;
                while (position > highThreshold)
                {
                    position = (position + step) & mask;
                }
            }
        }
        int[] stateTable = new int[tableSize];
        int[] running = (int[])cumul.Clone();
        for (int u = 0; u < tableSize; u++)
        {
            stateTable[running[tableSymbol[u]]++] = tableSize + u;
        }

        long[] deltaNbBits = new long[maxSymbol + 1];
        int[] deltaFindState = new int[maxSymbol + 1];
        int total = 0;
        for (int s = 0; s <= maxSymbol; s++)
        {
            int freq = norm[s];
            if (freq == 0)
            {
                // 不会用到，但留一个上界值，避免误用时算出越界下标
                deltaNbBits[s] = ((long)(tableLog + 1) << 16) - tableSize;
            }
            else if (freq == 1 || freq == -1)
            {
                deltaNbBits[s] = ((long)tableLog << 16) - tableSize;
                deltaFindState[s] = total - 1;
                total++;
            }
            else
            {
                int maxBitsOut = tableLog - HighBit(freq - 1);
                int minStatePlus = freq << maxBitsOut;
                deltaNbBits[s] = ((long)maxBitsOut << 16) - minStatePlus;
                deltaFindState[s] = total - freq;
                total += freq;
            }
        }
        return new CTable(tableLog, stateTable, deltaNbBits, deltaFindState);
    }

    // ------------------------------------------------------------ 编码状态机

    /// <summary>FSE 编码状态：一个长整型状态值，按参考实现的方式携带「已输出位数」。</summary>
    internal sealed class CState
    {
        internal long Value;
    }

    internal static void InitCState2(CState st, CTable table, int symbol)
    {
        long nbBitsOut = (table.DeltaNbBits[symbol] + (1L << 15)) >> 16;
        long v = (nbBitsOut << 16) - table.DeltaNbBits[symbol];
        st.Value = table.StateTable[(int)((v >> (int)nbBitsOut) + table.DeltaFindState[symbol])];
    }

    internal static void EncodeSymbol(BitWriter writer, CState st, CTable table, int symbol)
    {
        long nbBitsOut = (st.Value + table.DeltaNbBits[symbol]) >> 16;
        writer.AddBits(st.Value, (int)nbBitsOut);
        st.Value = table.StateTable[(int)((st.Value >> (int)nbBitsOut) + table.DeltaFindState[symbol])];
    }

    internal static void FlushCState(BitWriter writer, CState st, CTable table)
    {
        writer.AddBits(st.Value, table.Log);
    }
}