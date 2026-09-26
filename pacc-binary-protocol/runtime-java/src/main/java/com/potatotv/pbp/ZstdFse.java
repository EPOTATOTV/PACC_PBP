package com.potatotv.pbp;

import java.util.Arrays;

/**
 * zstd 子集（RFC 8878）用到的熵编码与比特流原语。
 *
 * <p>设计文档 §3.10.1 指定 zstd level 3，但 PBP 运行时必须零第三方依赖（验收项 B10），
 * 而 JDK 标准库没有 zstd。经决策采用「自研零依赖 zstd 子集」：编码侧只输出
 * 「原始 literals + 预定义 FSE 序列表」，解码侧在此之上额外认 Raw / RLE 块。
 * 不认 Huffman literals、FSE_Compressed 表、字典与内容校验和，遇到就显式失败
 * ——宁可不支持，也不把没校验过的数据当有效载荷用下去。</p>
 *
 * <p>本类里的常量与算法都来自 RFC 8878：序列码表是 §3.1.1.3.2.1.1 的表 16/17，
 * 预定义分布是 §3.1.1.3.2.2 的三张表，FSE 表构造是 §4.1.1。附录 A 给出的预定义
 * 解码表在单测里逐格比对，确保按分布构造出来的表与规范一致。</p>
 *
 * <p>位流的约定容易搞反，这里写清楚：编码侧按「先写的位在低位」把比特流正向写入
 * 字节数组；解码侧从最后一个字节的最高有效位开始反向读取，读到结束标记位后的
 * 0 填充为止。反读时<b>先读到的位是字段的高位</b>，所以 {@link BitReader#readBits}
 * 的取值是「按读取顺序高位在前」。</p>
 */
final class ZstdFse {

    private ZstdFse() {
    }

    // ------------------------------------------------------------ 序列码表

    /** 字面量长度码的额外位数（RFC 8878 表 16）。 */
    static final int[] LL_BITS = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 3, 3,
            4, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16,
    };

    /** 匹配长度码的额外位数（RFC 8878 表 17）。 */
    static final int[] ML_BITS = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 3, 3,
            4, 4, 5, 7, 8, 9, 10, 11,
            12, 13, 14, 15, 16,
    };

    /**
     * 字面量长度码的基线。
     *
     * <p>不手抄数字，而是由「上一段的基线 + 上一段的跨度」累加出来：码表的定义就是
     * 按取值范围首尾相接，累加式写法不会出现手抄错一位的经典事故。</p>
     */
    static final int[] LL_BASE = buildBase(LL_BITS, 0);

    /** 匹配长度码的基线（码 0 表示匹配长度 3，RFC 里 MINMATCH=3）。 */
    static final int[] ML_BASE = buildBase(ML_BITS, 3);

    /** 偏移码的基线：码 0/1 用于 repeat 偏移，码 ≥2 时基线是 2^code - 3（RFC §3.1.1.3.2.1.1）。 */
    static int ofBase(int code) {
        return code < 2 ? code : (1 << code) - 3;
    }

    /** 偏移码的额外位数等于码值本身。 */
    static int ofBits(int code) {
        return code;
    }

    static final int LL_MAX_CODE = LL_BITS.length - 1;
    static final int ML_MAX_CODE = ML_BITS.length - 1;
    /** 预定义偏移分布只到码 28，更大的偏移必须走自定义表，子集里不支持。 */
    static final int OF_MAX_CODE_DEFAULT = 28;

    private static int[] buildBase(int[] bits, int first) {
        int[] base = new int[bits.length];
        base[0] = first;
        for (int i = 1; i < bits.length; i++) {
            base[i] = base[i - 1] + (bits[i - 1] == 0 ? 1 : (1 << bits[i - 1]));
        }
        return base;
    }

    // ------------------------------------------------------------ 预定义分布

    /** 字面量长度码的预定义分布（RFC §3.1.1.3.2.2.1，精度 6）。 */
    static final short[] LL_DEFAULT_NORM = {
            4, 3, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 1, 1, 1,
            2, 2, 2, 2, 2, 2, 2, 2,
            2, 3, 2, 1, 1, 1, 1, 1,
            -1, -1, -1, -1,
    };

    /** 匹配长度码的预定义分布（RFC §3.1.1.3.2.2.2，精度 6）。 */
    static final short[] ML_DEFAULT_NORM = {
            1, 4, 3, 2, 2, 2, 2, 2,
            2, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, -1, -1,
            -1, -1, -1, -1, -1,
    };

    /** 偏移码的预定义分布（RFC §3.1.1.3.2.2.3，精度 5，最大码 28）。 */
    static final short[] OF_DEFAULT_NORM = {
            1, 1, 1, 1, 1, 1, 2, 2,
            2, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            -1, -1, -1, -1, -1,
    };

    static final int LL_DEFAULT_LOG = 6;
    static final int ML_DEFAULT_LOG = 6;
    static final int OF_DEFAULT_LOG = 5;

    /** 32 位值的最高有效位下标；入参为 0 时抛异常（调用点都在已校验的分支里）。 */
    static int highBit(int v) {
        return 31 - Integer.numberOfLeadingZeros(v);
    }

    // ------------------------------------------------------------ 比特流写入

    /**
     * 比特流写入器：按「先写的位在低位」累积，字节小端落到缓冲。
     *
     * <p>与参考实现的 {@code BIT_CStream} 语义一致：{@code addBits} 只保证低位
     * {@code n} 位有效；写完所有数据后调用 {@link #finish()} 补结束标记位并补零。</p>
     */
    static final class BitWriter {

        private byte[] buf = new byte[64];
        private int len;
        private long acc;
        private int accBits;

        /** 写入 {@code n} 位（取 {@code value} 的低 n 位）；单次最多 32 位。 */
        void addBits(long value, int n) {
            if (n < 0 || n > 32) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "位流写入长度非法: " + n);
            }
            if (n == 0) {
                return;
            }
            acc |= (value & ((1L << n) - 1)) << accBits;
            accBits += n;
            while (accBits >= 8) {
                ensure(1);
                buf[len++] = (byte) acc;
                acc >>>= 8;
                accBits -= 8;
            }
        }

        /** 收尾：写结束标记位（单个 1），把剩余位补零成整字节。 */
        byte[] finish() {
            addBits(1, 1);
            if (accBits > 0) {
                ensure(1);
                buf[len++] = (byte) acc;
                acc = 0;
                accBits = 0;
            }
            return Arrays.copyOf(buf, len);
        }

        private void ensure(int extra) {
            if (len + extra <= buf.length) {
                return;
            }
            int capacity = buf.length;
            while (capacity < len + extra) {
                capacity *= 2;
            }
            buf = Arrays.copyOf(buf, capacity);
        }
    }

    // ------------------------------------------------------------ 比特流读取

    /**
     * 比特流读取器：从指定区间的末字节开始反向读取。
     *
     * <p>末字节必须含结束标记位（最高的一个 1），标记之上的 0 是填充、不参与取值；
     * 读到区间起点以下即视为损坏，直接抛错而不是继续读零。</p>
     */
    static final class BitReader {

        private final byte[] src;
        private final int minBit;
        private int pos;

        BitReader(byte[] src, int offset, int length) {
            if (length <= 0) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "位流长度为 0");
            }
            if (offset < 0 || offset + length > src.length) {
                throw new PbpException(PbpException.Code.TRUNCATED, "位流区间越界");
            }
            int last = src[offset + length - 1] & 0xFF;
            if (last == 0) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "位流末字节为 0：缺少结束标记位");
            }
            this.src = src;
            this.minBit = offset * 8;
            this.pos = (offset + length - 1) * 8 + highBit(last) - 1;
        }

        /**
         * 读取 {@code n} 位；先读到的位是高位。
         *
         * @throws PbpException 位流已被读空时抛出，避免把补零当成有效数据
         */
        int readBits(int n) {
            if (n == 0) {
                return 0;
            }
            if (pos - n + 1 < minBit) {
                throw new PbpException(PbpException.Code.BAD_FORMAT,
                        "位流越界：需要 " + n + " 位，实际只剩 " + (pos - minBit + 1));
            }
            int v = 0;
            for (int i = 0; i < n; i++) {
                v = (v << 1) | ((src[pos >> 3] >>> (pos & 7)) & 1);
                pos--;
            }
            return v;
        }

        /** 位流是否已被恰好读完（RFC 要求序列位流必须精确消费）。 */
        boolean consumedAll() {
            return pos < minBit;
        }
    }

    // ------------------------------------------------------------ 解码表

    /**
     * FSE 解码表：每个状态给出符号、下一状态的额外位数与基线。
     *
     * <p>构造过程按 RFC §4.1.1：概率 &lt;1 的符号各占一个格子、从表尾倒退分配；
     * 其余符号按自然序、以 step 散布占格；最后按符号统计下一个状态，算出
     * {@code nbBits = tableLog - highBit(nextState)} 与
     * {@code newState = (nextState << nbBits) - tableSize}。</p>
     */
    static final class DTable {

        final int log;
        final int[] symbols;
        final int[] nbBits;
        final int[] newStates;

        private DTable(int log, int[] symbols, int[] nbBits, int[] newStates) {
            this.log = log;
            this.symbols = symbols;
            this.nbBits = nbBits;
            this.newStates = newStates;
        }

        /** RLE_Mode 的表：只有一个符号，不消费任何状态位。 */
        static DTable rle(int symbol) {
            return new DTable(0, new int[]{symbol}, new int[]{0}, new int[]{0});
        }
    }

    static DTable buildDTable(short[] norm, int tableLog) {
        int maxSymbol = norm.length - 1;
        int tableSize = 1 << tableLog;
        int[] symbols = new int[tableSize];
        int[] symbolNext = new int[maxSymbol + 1];
        int highThreshold = tableSize - 1;
        for (int s = 0; s <= maxSymbol; s++) {
            if (norm[s] == -1) {
                symbols[highThreshold--] = s;
                symbolNext[s] = 1;
            } else {
                symbolNext[s] = norm[s];
            }
        }
        int step = (tableSize >> 1) + (tableSize >> 3) + 3;
        int mask = tableSize - 1;
        int position = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            for (int i = 0; i < norm[s]; i++) {
                symbols[position] = s;
                position = (position + step) & mask;
                while (position > highThreshold) {
                    position = (position + step) & mask;
                }
            }
        }
        int[] nbBits = new int[tableSize];
        int[] newStates = new int[tableSize];
        for (int u = 0; u < tableSize; u++) {
            int next = symbolNext[symbols[u]]++;
            int bits = tableLog - highBit(next);
            nbBits[u] = bits;
            newStates[u] = (next << bits) - tableSize;
        }
        return new DTable(tableLog, symbols, nbBits, newStates);
    }

    // ------------------------------------------------------------ 编码表

    /**
     * FSE 编码表：状态迁移用 {@code stateTable} 与每个符号的位宽/偏移描述。
     *
     * <p>与解码表一样按 RFC §4.1.1 的散布规则构造，但布局取参考实现的形态：
     * 每个符号的 {@code deltaNbBits} 同时编码「输出位数」与「下一状态基址」，
     * 这样 {@link #encodeSymbol} 只做一次加法一次移位。</p>
     */
    static final class CTable {

        final int log;
        final int[] stateTable;
        final long[] deltaNbBits;
        final int[] deltaFindState;

        private CTable(int log, int[] stateTable, long[] deltaNbBits, int[] deltaFindState) {
            this.log = log;
            this.stateTable = stateTable;
            this.deltaNbBits = deltaNbBits;
            this.deltaFindState = deltaFindState;
        }
    }

    static CTable buildCTable(short[] norm, int tableLog) {
        int maxSymbol = norm.length - 1;
        int tableSize = 1 << tableLog;
        int mask = tableSize - 1;
        int step = (tableSize >> 1) + (tableSize >> 3) + 3;

        int[] cumul = new int[maxSymbol + 2];
        int[] tableSymbol = new int[tableSize];
        int highThreshold = tableSize - 1;
        for (int s = 0; s <= maxSymbol; s++) {
            if (norm[s] == -1) {
                cumul[s + 1] = cumul[s] + 1;
                tableSymbol[highThreshold--] = s;
            } else {
                cumul[s + 1] = cumul[s] + norm[s];
            }
        }
        int position = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            for (int i = 0; i < norm[s]; i++) {
                tableSymbol[position] = s;
                position = (position + step) & mask;
                while (position > highThreshold) {
                    position = (position + step) & mask;
                }
            }
        }
        int[] stateTable = new int[tableSize];
        int[] running = cumul.clone();
        for (int u = 0; u < tableSize; u++) {
            stateTable[running[tableSymbol[u]]++] = tableSize + u;
        }

        long[] deltaNbBits = new long[maxSymbol + 1];
        int[] deltaFindState = new int[maxSymbol + 1];
        int total = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            int freq = norm[s];
            if (freq == 0) {
                // 不会用到，但留一个上界值，避免误用时算出越界下标
                deltaNbBits[s] = ((long) (tableLog + 1) << 16) - tableSize;
            } else if (freq == 1 || freq == -1) {
                deltaNbBits[s] = ((long) tableLog << 16) - tableSize;
                deltaFindState[s] = total - 1;
                total++;
            } else {
                int maxBitsOut = tableLog - highBit(freq - 1);
                int minStatePlus = freq << maxBitsOut;
                deltaNbBits[s] = ((long) maxBitsOut << 16) - minStatePlus;
                deltaFindState[s] = total - freq;
                total += freq;
            }
        }
        return new CTable(tableLog, stateTable, deltaNbBits, deltaFindState);
    }

    // ------------------------------------------------------------ 编码状态机

    /** FSE 编码状态：一个长整型状态值，按参考实现的方式携带「已输出位数」。 */
    static final class CState {
        long value;
    }

    static void initCState2(CState st, CTable table, int symbol) {
        long nbBitsOut = (table.deltaNbBits[symbol] + (1L << 15)) >> 16;
        long v = (nbBitsOut << 16) - table.deltaNbBits[symbol];
        st.value = table.stateTable[(int) ((v >> nbBitsOut) + table.deltaFindState[symbol])];
    }

    static void encodeSymbol(BitWriter writer, CState st, CTable table, int symbol) {
        long nbBitsOut = (st.value + table.deltaNbBits[symbol]) >> 16;
        writer.addBits(st.value, (int) nbBitsOut);
        st.value = table.stateTable[(int) ((st.value >> nbBitsOut) + table.deltaFindState[symbol])];
    }

    static void flushCState(BitWriter writer, CState st, CTable table) {
        writer.addBits(st.value, table.log);
    }
}