using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Potatotv.Pbp;
using Potatotv.Pbp.Gen;

namespace Potatotv.Pbp.Tests;

/// <summary>
/// 控制台互操作测试：不引测试框架，失败用非 0 退出码。
///
/// <p>锚点是 <c>pacc-binary-protocol/test-vectors/interop.txt</c>（Java 参考实现导出的向量）：
/// 能逐字节复现压缩输出、能解开参考帧、能回放差分链，才算 C# 这一路和 Java 互操作成立。</p>
/// </summary>
internal static class Program
{
    private const string SecretText = "000102030405060708090a0b0c0d0e0f";
    private const long TsMs = 1_700_000_000_000L;

    private static int failures;

    private static int Main()
    {
        Dictionary<string, byte[]> vectors;
        try
        {
            vectors = LoadVectors();
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("无法加载互操作向量：" + e.Message);
            return 2;
        }

        RunEnvelope(vectors);
        RunCodecPayload(vectors);
        RunBigFrame(vectors);
        RunZstd(vectors);
        RunDelta(vectors);
        RunSelfConsistency();

        if (failures > 0)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"{failures} 个断言失败");
            return 1;
        }
        Console.WriteLine();
        Console.WriteLine("全部通过");
        return 0;
    }

    // ============================================================ 互操作向量

    private static void RunEnvelope(Dictionary<string, byte[]> vectors)
    {
        Section("envelope");
        byte[] secret = vectors["secret_hex_text"];
        CheckBytes(Encoding.UTF8.GetBytes(SecretText), secret, "secret_hex_text 是明文密钥的 UTF-8 字节");

        PaccEnvelope envelope = Envelope("inspect_offer", "{}");
        CheckBytes(vectors["envelope_payload"], PbpCodec.PayloadOf(envelope), "envelope_payload");
        CheckBytes(vectors["envelope_frame"], envelope.ToByteArray(), "envelope_frame");

        byte[] signature = PbpCrypto.HmacSha256(secret, envelope.SigningInput());
        byte[] signed = envelope.ToBuilder().SetSignatureBytes(signature).Build().ToByteArray();
        CheckBytes(vectors["envelope_signed_frame"], signed, "envelope_signed_frame");

        PaccEnvelope parsed = PaccEnvelope.ParseFrom(vectors["envelope_signed_frame"]);
        CheckEquals(Convert.ToHexString(signature).ToLowerInvariant(), parsed.SignatureHex, "解析签名帧回读签名");
    }

    private static void RunCodecPayload(Dictionary<string, byte[]> vectors)
    {
        Section("codec");
        CheckBytes(vectors["codec_payload"], PbpCodec.PayloadOf(CodecReport()), "codec_payload");
    }

    private static void RunBigFrame(Dictionary<string, byte[]> vectors)
    {
        Section("big_frame");
        PaccEnvelope big = Envelope("inspect_result", new string('A', 3000));
        CheckBytes(vectors["big_frame_compressed"], big.ToByteArray(), "big_frame_compressed");
        Check(PbpFrame.Parse(vectors["big_frame_compressed"]).Compressed, "大帧带 FLAG_COMPRESSED");
        Check(PbpFrame.Parse(vectors["big_frame_compressed"]).PayloadLength < 128, "压缩后载荷显著变小");
    }

    private static void RunZstd(Dictionary<string, byte[]> vectors)
    {
        Section("zstd");
        foreach ((string name, byte[] plain) in new (string, byte[])[]
                 {
                     ("zstd_repeat", RepeatPayload()),
                     ("zstd_rle", RlePayload()),
                     ("zstd_ramp", RampPayload()),
                     ("zstd_noise", NoisePayload()),
                     ("zstd_blocky", BlockyPayload()),
                     ("zstd_mixed", MixedPayload()),
                 })
        {
            byte[] compressed = PbpZstd.Compress(plain);
            CheckBytes(vectors[name + "_compressed"], compressed, name + "_compressed");
            CheckBytes(plain, PbpZstd.Decompress(vectors[name + "_compressed"], PbpFrame.MaxPayloadSize),
                name + " 解压向量 == 明文");
        }
    }

    private static void RunDelta(Dictionary<string, byte[]> vectors)
    {
        Section("delta");
        PbpDeltaChain<DetectionReport> sender = NewChain();
        DetectionReport msg1 = StatusReport(2_000L, 20, 50, 3.5f);
        DetectionReport msg2 = StatusReport(2_001L, 24, 50, 4.5f);
        PbpFrame frame1 = sender.Encode(msg1, 2_000L);
        PbpFrame frame2 = sender.Encode(msg2, 2_001L);
        CheckBytes(vectors["delta_frame1"], frame1.Encode(), "delta_frame1");
        CheckBytes(vectors["delta_frame2"], frame2.Encode(), "delta_frame2");
        Check(frame2.Delta, "delta_frame2 带 FLAG_DELTA");

        PbpDeltaChain<DetectionReport> receiver = NewChain();
        DetectionReport decoded1 = receiver.Decode(vectors["delta_frame1"]);
        DetectionReport decoded2 = receiver.Decode(vectors["delta_frame2"]);
        CheckEquals(2_000L, decoded1.Timestamp, "frame1 → msg1 timestamp");
        CheckEquals(2_001L, decoded2.Timestamp, "frame2 → msg2 timestamp");
        CheckEquals(24 / 100.0f, decoded2.Apm!.CpuUsage, "frame2 → msg2 apm.cpu_usage");
        CheckBytes(vectors["delta_payload2"], PbpCodec.PayloadOf(decoded2), "msg2 重编码载荷 == delta_payload2");
    }

    // ============================================================ 自洽

    private static void RunSelfConsistency()
    {
        Section("self-consistency");

        CheckRoundTrip("空默认消息", DetectionReport.NewBuilder().Build());

        DetectionReport utf8 = DetectionReport.NewBuilder()
            .SetPteid("PT0001")
            .SetTimestamp(-1_700_000_000_000L)
            .SetClientVersion("5.4.0-验证")
            .SetPlatform("windows")
            .AddEvents(DetectionEvent.NewBuilder()
                .SetEventType(-5)
                .SetConfidence(0.75f)
                .SetTimestamp(-1L)
                .PutEvidence("模块", Encoding.UTF8.GetBytes("证据"))
                .SetDetail("内存段校验不一致")
                .Build())
            .SetApm(ApmSnapshot.NewBuilder()
                .SetCpuUsage(23.5f)
                .SetMemoryUsageKb(450_000)
                .SetFps(120.0f)
                .SetDetectionLatencyMs(12)
                .SetActiveRules(50)
                .PutCustomMetrics("gc_ms", 3.5f)
                .PutCustomMetrics("heap_ms", -1.5f)
                .Build())
            .SetSignature(new byte[] { 1, 2, 3, 4, 5 })
            .Build();
        CheckRoundTrip("多字节 UTF-8 / 负数 ZigZag / 集合映射可选", utf8);

        CheckZigZag();
        CheckCompressRoundTrip();
        CheckDeltaTenRule();
        CheckDecompressRejects();
    }

    private static void CheckRoundTrip(string name, IPbpMessage message)
    {
        byte[] payload = PbpCodec.PayloadOf(message);
        PbpDecoder decoder = new PbpDecoder(payload);
        IPbpMessage clone = EmptyLike(message);
        clone.Decode(decoder);
        CheckBytes(payload, PbpCodec.PayloadOf(clone), name + " 载荷往返");
    }

    private static void CheckZigZag()
    {
        PbpEncoder enc = new PbpEncoder();
        enc.WriteInt32(-1).WriteInt32(int.MinValue).WriteInt32(0)
            .WriteInt64(-1L).WriteInt64(long.MinValue).WriteInt64(0L)
            .WriteUInt32(0xFFFF_FFFFu).WriteUInt64(0xFFFF_FFFF_FFFF_FFFFUL);
        PbpDecoder dec = new PbpDecoder(enc.ToByteArray());
        CheckEquals(-1, dec.ReadInt32(), "ZigZag int32 -1");
        CheckEquals(int.MinValue, dec.ReadInt32(), "ZigZag int32 MinValue");
        CheckEquals(0, dec.ReadInt32(), "ZigZag int32 0");
        CheckEquals(-1L, dec.ReadInt64(), "ZigZag int64 -1");
        CheckEquals(long.MinValue, dec.ReadInt64(), "ZigZag int64 MinValue");
        CheckEquals(0L, dec.ReadInt64(), "ZigZag int64 0");
        CheckEquals(0xFFFF_FFFFu, dec.ReadUInt32(), "uint32 上界");
        CheckEquals(0xFFFF_FFFF_FFFF_FFFFUL, dec.ReadUInt64(), "uint64 上界");
    }

    private static void CheckCompressRoundTrip()
    {
        byte[] plain = Encoding.UTF8.GetBytes(new string('B', 40_000));
        byte[] compressed = PbpZstd.Compress(plain);
        Check(compressed.Length < plain.Length, "高重复数据压缩变小");
        CheckBytes(plain, PbpZstd.Decompress(compressed, PbpFrame.MaxPayloadSize), "压缩往返");

        byte[] packed = PbpCodec.MaybeCompress(plain);
        Check(!ReferenceEquals(packed, plain), "超阈值载荷被压缩");
        byte[] small = Encoding.UTF8.GetBytes("small");
        Check(ReferenceEquals(small, PbpCodec.MaybeCompress(small)), "阈值以下原样返回");
    }

    private static void CheckDeltaTenRule()
    {
        PbpDeltaChain<DetectionReport> sender = NewChain();
        List<byte[]> frames = new List<byte[]> { sender.Encode(StatusReport(0L, 1, 1, 1.0f), 0L).Encode() };
        for (int i = 1; i <= PbpDeltaChain<DetectionReport>.MaxConsecutive; i++)
        {
            PbpFrame frame = sender.Encode(StatusReport(i, 1 + i, 1, 1.0f), i);
            Check(frame.Delta, $"第 {i} 条应为差分");
            frames.Add(frame.Encode());
        }
        CheckEquals(PbpDeltaChain<DetectionReport>.MaxConsecutive, sender.Consecutive, "连续差分计数到上限");
        PbpFrame forcedFull = sender.Encode(StatusReport(99L, 9, 9, 9.0f), 99L);
        Check(!forcedFull.Delta, "上限之后强制发完整消息");
        CheckEquals(0, sender.Consecutive, "强制完整后计数归零");

        PbpDeltaChain<DetectionReport> receiver = NewChain();
        foreach (byte[] frameBytes in frames)
        {
            receiver.Decode(frameBytes);
        }
        CheckEquals(PbpDeltaChain<DetectionReport>.MaxConsecutive, receiver.Consecutive, "接收侧差分计数到上限");
        CheckThrows(() => receiver.Decode(frames[^1]), "接收侧拒绝超限的连续差分");

        CheckThrows(() => NewChain().Decode(frames[1]), "接收侧拒绝无基线的差分帧");
    }

    private static void CheckDecompressRejects()
    {
        byte[] frame = PbpZstd.Compress(Encoding.UTF8.GetBytes("abcdefabcdefabcdef"));
        CheckThrows(() => PbpZstd.Decompress(frame, 4), "解压上限拒绝");
        CheckThrows(() => PbpZstd.Decompress(new byte[] { 1, 2, 3 }, PbpFrame.MaxPayloadSize), "长度不足拒绝");
        byte[] dirty = new byte[frame.Length + 1];
        Array.Copy(frame, dirty, frame.Length);
        CheckThrows(() => PbpZstd.Decompress(dirty, PbpFrame.MaxPayloadSize), "帧尾多余字节拒绝");
    }

    // ============================================================ 载荷构造

    private static PaccEnvelope Envelope(string type, string payloadJson) =>
        PaccEnvelope.NewBuilder()
            .SetType(type)
            .SetTsMs(TsMs)
            .SetNonce("0123456789abcdef")
            .SetSessionId("sess-1")
            .SetPteid("PT0001")
            .SetPayloadJson(payloadJson)
            .SetSigVersion(1)
            .Build();

    private static byte[] Ascii(string s) => Encoding.UTF8.GetBytes(s);

    private static DetectionReport CodecReport()
    {
        byte[] signature = new byte[32];
        for (int i = 0; i < signature.Length; i++)
        {
            signature[i] = (byte)(i + 1);
        }
        return DetectionReport.NewBuilder()
            .SetPteid("PT0001")
            .SetTimestamp(-1_700_000_000_000L)
            .SetClientVersion("5.4.0-验证")
            .SetPlatform("windows")
            .AddEvents(DetectionEvent.NewBuilder()
                .SetEventType(2)
                .SetConfidence(0.75f)
                .SetTimestamp(1_700_000_000_001L)
                .PutEvidence("module", Ascii("pacc-probe"))
                .SetDetail("内存段校验不一致")
                .Build())
            .SetApm(ApmSnapshot.NewBuilder()
                .SetCpuUsage(23.5f)
                .SetMemoryUsageKb(450_000)
                .SetFps(120.0f)
                .SetDetectionLatencyMs(12)
                .SetActiveRules(50)
                .PutCustomMetrics("gc_ms", 3.5f)
                .Build())
            .SetSignature(signature)
            .Build();
    }

    private static DetectionReport StatusReport(long ts, int cpuPercent, int rules, float gcMs) =>
        DetectionReport.NewBuilder()
            .SetPteid("PT0001")
            .SetTimestamp(ts)
            .SetClientVersion("5.4.0")
            .SetPlatform("windows")
            .AddEvents(DetectionEvent.NewBuilder()
                .SetEventType(2)
                .SetConfidence(0.87f)
                .SetTimestamp(900L)
                .PutEvidence("module", Ascii("pacc-probe"))
                .SetDetail("可疑进程")
                .Build())
            .SetApm(ApmSnapshot.NewBuilder()
                .SetCpuUsage(cpuPercent / 100.0f)
                .SetMemoryUsageKb(450_000)
                .SetFps(120.0f)
                .SetDetectionLatencyMs(12)
                .SetActiveRules(rules)
                .PutCustomMetrics("gc_ms", gcMs)
                .Build())
            .Build();

    private static DetectionReport NewReport() => DetectionReport.NewBuilder().Build();

    private static PbpDeltaChain<DetectionReport> NewChain() =>
        new PbpDeltaChain<DetectionReport>(DetectionReport.MessageId, NewReport);

    private static byte[] RepeatPayload()
    {
        byte[] data = new byte[16_384];
        byte[] pattern = Ascii("pacc-pbp-zstd");
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = pattern[i % pattern.Length];
        }
        return data;
    }

    private static byte[] RlePayload()
    {
        byte[] data = new byte[4096];
        Array.Fill(data, (byte)0x5A);
        return data;
    }

    private static byte[] RampPayload()
    {
        byte[] data = new byte[4096];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)((i * i * 31 + i * 7 + 11) & 0xFF);
        }
        return data;
    }

    private static byte[] NoisePayload()
    {
        byte[] data = new byte[4096];
        uint x = 0x12345678;
        for (int i = 0; i < data.Length; i++)
        {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data[i] = (byte)(x & 0xFF);
        }
        return data;
    }

    private static byte[] BlockyPayload()
    {
        byte[] data = new byte[8192];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 37 < 20 ? (i & 0x0F) : ((i * 3) & 0xFF));
        }
        return data;
    }

    private static byte[] MixedPayload()
    {
        byte[] data = new byte[140_000];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)((i * 7 + 140_000) & 0xFF);
        }
        return data;
    }

    /// <summary>按编码类型建一个同类型的空对象，用于往返解码。</summary>
    private static IPbpMessage EmptyLike(IPbpMessage message) => message switch
    {
        DetectionReport => NewReport(),
        _ => throw new InvalidOperationException("未覆盖的消息类型: " + message.GetType().Name),
    };

    // ============================================================ 断言

    private static void Section(string name) => Console.WriteLine("== " + name);

    private static void Check(bool condition, string name)
    {
        if (condition)
        {
            Console.WriteLine("  ok   " + name);
            return;
        }
        failures++;
        Console.Error.WriteLine("  FAIL " + name);
    }

    private static void CheckEquals<T>(T expected, T actual, string name)
    {
        if (EqualityComparer<T>.Default.Equals(expected, actual))
        {
            Console.WriteLine("  ok   " + name);
            return;
        }
        failures++;
        Console.Error.WriteLine($"  FAIL {name}：期望 {expected}，实际 {actual}");
    }

    private static void CheckBytes(byte[] expected, byte[] actual, string name)
    {
        if (PbpDelta.BytesEqual(expected, actual))
        {
            Console.WriteLine($"  ok   {name} ({actual.Length} 字节)");
            return;
        }
        failures++;
        int at = FirstDiff(expected, actual);
        Console.Error.WriteLine($"  FAIL {name}：长度 期望 {expected.Length} / 实际 {actual.Length}，首个差异下标 {at}");
    }

    private static void CheckThrows(Action action, string name)
    {
        try
        {
            action();
        }
        catch (PbpException)
        {
            Console.WriteLine("  ok   " + name);
            return;
        }
        failures++;
        Console.Error.WriteLine("  FAIL " + name + "：没有抛 PbpException");
    }

    private static int FirstDiff(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            if (a[i] != b[i])
            {
                return i;
            }
        }
        return n;
    }

    // ============================================================ 向量加载

    private static Dictionary<string, byte[]> LoadVectors()
    {
        Dictionary<string, byte[]> map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string raw in File.ReadAllLines(VectorPath()))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }
            int eq = line.IndexOf('=');
            if (eq < 0)
            {
                continue;
            }
            string key = line.Substring(0, eq).Trim();
            string value = line.Substring(eq + 1).Trim();
            map[key] = Convert.FromHexString(value);
        }
        return map;
    }

    /// <summary>从输出目录上溯找到仓库根下的向量文件，避免依赖调用者的工作目录。</summary>
    private static string VectorPath()
    {
        DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            string candidate = Path.Combine(dir.FullName, "pacc-binary-protocol", "test-vectors", "interop.txt");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException("找不到 pacc-binary-protocol/test-vectors/interop.txt");
    }
}