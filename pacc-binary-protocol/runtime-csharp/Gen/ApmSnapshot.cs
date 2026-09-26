// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

using System;
using System.Collections.Generic;

namespace Potatotv.Pbp.Gen;

/// <summary>
/// PBP 消息 ApmSnapshot，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
///
/// <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
/// </summary>
public sealed class ApmSnapshot : IPbpMessage
{
    // ------------------------------------------------------------ 字段

    private float cpuUsage;

    private int memoryUsageKb;

    private float fps;

    private int detectionLatencyMs;

    private int activeRules;

    private Dictionary<string, float> customMetrics = new Dictionary<string, float>();

    /// <summary>解析路径用它建空对象，字段默认值见声明处。</summary>
    internal ApmSnapshot()
    {
    }

    /// <summary>字段构造器；可空性由 MDL 决定。</summary>
    public sealed class Builder
    {
        private float cpuUsage = 0.0f;

        private int memoryUsageKb = 0;

        private float fps = 0.0f;

        private int detectionLatencyMs = 0;

        private int activeRules = 0;

        private Dictionary<string, float> customMetrics = new Dictionary<string, float>();

        internal Builder()
        {
        }

        /// <summary>MDL 字段 1 cpu_usage。</summary>
        public Builder SetCpuUsage(float value)
        {
            cpuUsage = value;
            return this;
        }

        /// <summary>MDL 字段 2 memory_usage_kb。</summary>
        public Builder SetMemoryUsageKb(int value)
        {
            memoryUsageKb = value;
            return this;
        }

        /// <summary>MDL 字段 3 fps。</summary>
        public Builder SetFps(float value)
        {
            fps = value;
            return this;
        }

        /// <summary>MDL 字段 4 detection_latency_ms。</summary>
        public Builder SetDetectionLatencyMs(int value)
        {
            detectionLatencyMs = value;
            return this;
        }

        /// <summary>MDL 字段 5 active_rules。</summary>
        public Builder SetActiveRules(int value)
        {
            activeRules = value;
            return this;
        }

        /// <summary>MDL 字段 6 custom_metrics。</summary>
        public Builder SetCustomMetrics(Dictionary<string, float>? value)
        {
            customMetrics = value == null ? new Dictionary<string, float>() : new Dictionary<string, float>(value);
            return this;
        }

        /// <summary>写入一个 custom_metrics 键值对。</summary>
        public Builder PutCustomMetrics(string key, float value)
        {
            customMetrics[key] = value;
            return this;
        }

        public ApmSnapshot Build()
        {
            ApmSnapshot msg = new ApmSnapshot();
            msg.cpuUsage = cpuUsage;
            msg.memoryUsageKb = memoryUsageKb;
            msg.fps = fps;
            msg.detectionLatencyMs = detectionLatencyMs;
            msg.activeRules = activeRules;
            msg.customMetrics = new Dictionary<string, float>(customMetrics);
            return msg;
        }
    }

    public static Builder NewBuilder() => new Builder();

    /// <summary>以当前值为初值开一个新 Builder（例如改完字段要重新签名）。</summary>
    public Builder ToBuilder()
    {
        return NewBuilder()
            .SetCpuUsage(cpuUsage)
            .SetMemoryUsageKb(memoryUsageKb)
            .SetFps(fps)
            .SetDetectionLatencyMs(detectionLatencyMs)
            .SetActiveRules(activeRules)
            .SetCustomMetrics(customMetrics)
            ;
    }

    // ------------------------------------------------------------ 字段读取

    /// <summary>MDL 字段 1 cpu_usage。</summary>
    public float CpuUsage => cpuUsage;

    /// <summary>MDL 字段 2 memory_usage_kb。</summary>
    public int MemoryUsageKb => memoryUsageKb;

    /// <summary>MDL 字段 3 fps。</summary>
    public float Fps => fps;

    /// <summary>MDL 字段 4 detection_latency_ms。</summary>
    public int DetectionLatencyMs => detectionLatencyMs;

    /// <summary>MDL 字段 5 active_rules。</summary>
    public int ActiveRules => activeRules;

    /// <summary>MDL 字段 6 custom_metrics。</summary>
    public IReadOnlyDictionary<string, float> CustomMetrics => customMetrics;

    // ------------------------------------------------------------ IPbpMessage

    /// <inheritdoc/>
    public int GetMessageId() => 0;

    /// <inheritdoc/>
    public void Encode(PbpEncoder enc)
    {
        enc.WriteFloat32(cpuUsage);
        enc.WriteInt32(memoryUsageKb);
        enc.WriteFloat32(fps);
        enc.WriteInt32(detectionLatencyMs);
        enc.WriteInt32(activeRules);
        enc.WriteStringMap(customMetrics, static (e, v) => e.WriteFloat32(v));
    }

    /// <summary>按定义顺序读回字段；末尾字段在载荷提前读完时取默认值。</summary>
    /// <inheritdoc/>
    public void Decode(PbpDecoder dec)
    {
        cpuUsage = dec.ReadFloat32();
        memoryUsageKb = dec.ReadInt32();
        fps = dec.ReadFloat32();
        detectionLatencyMs = dec.ReadInt32();
        activeRules = dec.ReadInt32();
        customMetrics = dec.ReadStringMap(static d => d.ReadFloat32());
    }

    /// <summary>编码后的字节数，仅用于预分配缓冲区。</summary>
    /// <inheritdoc/>
    public int EncodedSize()
    {
        int size = 0;
        size += PbpEncoder.Float32Size();
        size += PbpEncoder.Int32Size(memoryUsageKb);
        size += PbpEncoder.Float32Size();
        size += PbpEncoder.Int32Size(detectionLatencyMs);
        size += PbpEncoder.Int32Size(activeRules);
        size += PbpEncoder.StringMapSize(customMetrics, static v => PbpEncoder.Float32Size());
        return size;
    }

}
