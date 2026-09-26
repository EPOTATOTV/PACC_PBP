// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

using System;
using System.Collections.Generic;

namespace Potatotv.Pbp.Gen;

/// <summary>
/// PBP 消息 DetectionEvent，无消息 ID，仅作为嵌套类型内联在父消息载荷里。
///
/// <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
/// </summary>
public sealed class DetectionEvent : IPbpMessage
{
    /// <summary>可空字段个数，用于定位载荷里的存在性位图。</summary>
    public const int OptionalFieldCount = 1;

    // ------------------------------------------------------------ 字段

    private int eventType;

    private float confidence;

    private long timestamp;

    private Dictionary<string, byte[]> evidence = new Dictionary<string, byte[]>();

    private string? detail = null;

    /// <summary>解析路径用它建空对象，字段默认值见声明处。</summary>
    internal DetectionEvent()
    {
    }

    /// <summary>字段构造器；可空性由 MDL 决定。</summary>
    public sealed class Builder
    {
        private int eventType = 0;

        private float confidence = 0.0f;

        private long timestamp = 0L;

        private Dictionary<string, byte[]> evidence = new Dictionary<string, byte[]>();

        private string? detail = null;

        internal Builder()
        {
        }

        /// <summary>MDL 字段 1 event_type。</summary>
        public Builder SetEventType(int value)
        {
            eventType = value;
            return this;
        }

        /// <summary>MDL 字段 2 confidence。</summary>
        public Builder SetConfidence(float value)
        {
            confidence = value;
            return this;
        }

        /// <summary>MDL 字段 3 timestamp。</summary>
        public Builder SetTimestamp(long value)
        {
            timestamp = value;
            return this;
        }

        /// <summary>MDL 字段 4 evidence。</summary>
        public Builder SetEvidence(Dictionary<string, byte[]>? value)
        {
            evidence = value == null ? new Dictionary<string, byte[]>() : new Dictionary<string, byte[]>(value);
            return this;
        }

        /// <summary>写入一个 evidence 键值对。</summary>
        public Builder PutEvidence(string key, byte[]? value)
        {
            evidence[key] = value!;
            return this;
        }

        /// <summary>MDL 字段 5 detail。</summary>
        public Builder SetDetail(string? value)
        {
            detail = value;
            return this;
        }

        public DetectionEvent Build()
        {
            DetectionEvent msg = new DetectionEvent();
            msg.eventType = eventType;
            msg.confidence = confidence;
            msg.timestamp = timestamp;
            msg.evidence = new Dictionary<string, byte[]>(evidence);
            msg.detail = detail;
            return msg;
        }
    }

    public static Builder NewBuilder() => new Builder();

    /// <summary>以当前值为初值开一个新 Builder（例如改完字段要重新签名）。</summary>
    public Builder ToBuilder()
    {
        return NewBuilder()
            .SetEventType(eventType)
            .SetConfidence(confidence)
            .SetTimestamp(timestamp)
            .SetEvidence(evidence)
            .SetDetail(detail)
            ;
    }

    // ------------------------------------------------------------ 字段读取

    /// <summary>MDL 字段 1 event_type。</summary>
    public int EventType => eventType;

    /// <summary>MDL 字段 2 confidence。</summary>
    public float Confidence => confidence;

    /// <summary>MDL 字段 3 timestamp。</summary>
    public long Timestamp => timestamp;

    /// <summary>MDL 字段 4 evidence。</summary>
    public IReadOnlyDictionary<string, byte[]> Evidence => evidence;

    /// <summary>MDL 字段 5 detail。</summary>
    public string? Detail => detail;

    // ------------------------------------------------------------ IPbpMessage

    /// <inheritdoc/>
    public int GetMessageId() => 0;

    /// <inheritdoc/>
    public void Encode(PbpEncoder enc)
    {
        enc.WriteInt32(eventType);
        enc.WriteFloat32(confidence);
        enc.WriteInt64(timestamp);
        enc.WriteStringMap(evidence, static (e, v) => e.WriteBytes(v));
        enc.WriteOptionalString(detail);
    }

    /// <summary>按定义顺序读回字段；末尾字段在载荷提前读完时取默认值。</summary>
    /// <inheritdoc/>
    public void Decode(PbpDecoder dec)
    {
        eventType = dec.ReadInt32();
        confidence = dec.ReadFloat32();
        timestamp = dec.ReadInt64();
        evidence = dec.ReadStringMap(static d => d.ReadBytes());
        detail = dec.ReadOptionalString();
    }

    /// <summary>编码后的字节数，仅用于预分配缓冲区。</summary>
    /// <inheritdoc/>
    public int EncodedSize()
    {
        int size = 0;
        size += PbpEncoder.Int32Size(eventType);
        size += PbpEncoder.Float32Size();
        size += PbpEncoder.Int64Size(timestamp);
        size += PbpEncoder.StringMapSize(evidence, static v => PbpEncoder.BytesSize(v));
        size += PbpEncoder.OptionalStringSize(detail);
        return size;
    }

}
