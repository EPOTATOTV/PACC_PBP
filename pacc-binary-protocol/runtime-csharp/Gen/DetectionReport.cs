// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/detection.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

using System;
using System.Collections.Generic;

namespace Potatotv.Pbp.Gen;

/// <summary>
/// PBP 消息 DetectionReport（0x0103，0x0100-0x0FFF 客户端 → 服务端）。
///
/// <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
/// </summary>
public sealed class DetectionReport : IPbpMessage, IPbpDeltaMessage<DetectionReport>
{
    /// <summary>MDL 里声明的消息 ID。</summary>
    public const int MessageId = 0x0103;

    /// <summary>可空字段个数，用于定位载荷里的存在性位图。</summary>
    public const int OptionalFieldCount = 1;

    // ------------------------------------------------------------ 字段

    private string pteid = "";

    private long timestamp;

    private string clientVersion = "";

    private string platform = "";

    private List<DetectionEvent> events = new List<DetectionEvent>();

    private ApmSnapshot? apm = null;

    private byte[] signature = new byte[0];

    /// <summary>解析路径用它建空对象，字段默认值见声明处。</summary>
    internal DetectionReport()
    {
    }

    /// <summary>字段构造器；可空性由 MDL 决定。</summary>
    public sealed class Builder
    {
        private string pteid = "";

        private long timestamp = 0L;

        private string clientVersion = "";

        private string platform = "";

        private List<DetectionEvent> events = new List<DetectionEvent>();

        private ApmSnapshot? apm = null;

        private byte[] signature = new byte[0];

        internal Builder()
        {
        }

        /// <summary>MDL 字段 1 pteid。</summary>
        public Builder SetPteid(string value)
        {
            pteid = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 2 timestamp。</summary>
        public Builder SetTimestamp(long value)
        {
            timestamp = value;
            return this;
        }

        /// <summary>MDL 字段 3 client_version。</summary>
        public Builder SetClientVersion(string value)
        {
            clientVersion = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 4 platform。</summary>
        public Builder SetPlatform(string value)
        {
            platform = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 5 events。</summary>
        public Builder SetEvents(List<DetectionEvent>? value)
        {
            events = value == null ? new List<DetectionEvent>() : new List<DetectionEvent>(value);
            return this;
        }

        /// <summary>追加一个 events 元素。</summary>
        public Builder AddEvents(DetectionEvent value)
        {
            events.Add(value);
            return this;
        }

        /// <summary>MDL 字段 6 apm。</summary>
        public Builder SetApm(ApmSnapshot? value)
        {
            apm = value;
            return this;
        }

        /// <summary>MDL 字段 7 signature。</summary>
        public Builder SetSignature(byte[] value)
        {
            signature = value == null ? new byte[0] : (byte[])value.Clone();
            return this;
        }

        public DetectionReport Build()
        {
            DetectionReport msg = new DetectionReport();
            msg.pteid = pteid;
            msg.timestamp = timestamp;
            msg.clientVersion = clientVersion;
            msg.platform = platform;
            msg.events = new List<DetectionEvent>(events);
            msg.apm = apm;
            msg.signature = (byte[])signature.Clone();
            return msg;
        }
    }

    public static Builder NewBuilder() => new Builder();

    /// <summary>以当前值为初值开一个新 Builder（例如改完字段要重新签名）。</summary>
    public Builder ToBuilder()
    {
        return NewBuilder()
            .SetPteid(pteid)
            .SetTimestamp(timestamp)
            .SetClientVersion(clientVersion)
            .SetPlatform(platform)
            .SetEvents(events)
            .SetApm(apm)
            .SetSignature(signature)
            ;
    }

    // ------------------------------------------------------------ 字段读取

    /// <summary>MDL 字段 1 pteid。</summary>
    public string Pteid => pteid;

    /// <summary>MDL 字段 2 timestamp。</summary>
    public long Timestamp => timestamp;

    /// <summary>MDL 字段 3 client_version。</summary>
    public string ClientVersion => clientVersion;

    /// <summary>MDL 字段 4 platform。</summary>
    public string Platform => platform;

    /// <summary>MDL 字段 5 events。</summary>
    public IReadOnlyList<DetectionEvent> Events => events;

    /// <summary>MDL 字段 6 apm。</summary>
    public ApmSnapshot? Apm => apm;

    /// <summary>MDL 字段 7 signature。</summary>
    public byte[] Signature => (byte[])signature.Clone();

    // ------------------------------------------------------------ 帧

    /// <summary>编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。</summary>
    public byte[] ToByteArray()
    {
        PbpFrame frame = PbpCodec.FrameOf(this, 0L);
        return frame.Encode();
    }

    /// <summary>解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。</summary>
    public static DetectionReport ParseFrom(byte[] raw)
    {
        PbpFrame frame = PbpFrame.Parse(raw);
        if (frame.MessageId != MessageId)
        {
            throw new PbpException(PbpErrorCode.BadFormat,
                "消息 ID 不符：期望 0x" + MessageId.ToString("x")
                + "，实际 0x" + frame.MessageId.ToString("x"));
        }
        DetectionReport msg = new DetectionReport();
        msg.Decode(new PbpDecoder(PbpCodec.PayloadOf(frame)));
        return msg;
    }

    // ------------------------------------------------------------ IPbpMessage

    /// <inheritdoc/>
    public int GetMessageId() => MessageId;

    /// <inheritdoc/>
    public void Encode(PbpEncoder enc)
    {
        enc.WriteString(pteid);
        enc.WriteInt64(timestamp);
        enc.WriteString(clientVersion);
        enc.WriteString(platform);
        enc.WriteMessageList(events);
        enc.WriteOptionalMessage(apm);
        enc.WriteBytes(signature);
    }

    /// <summary>按定义顺序读回字段；末尾字段在载荷提前读完时取默认值。</summary>
    /// <inheritdoc/>
    public void Decode(PbpDecoder dec)
    {
        pteid = dec.ReadString();
        timestamp = dec.ReadInt64();
        clientVersion = dec.ReadString();
        platform = dec.ReadString();
        events = dec.ReadMessageList(() => new DetectionEvent());
        apm = dec.ReadOptionalMessage(() => new ApmSnapshot());
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        signature = dec.Remaining > 0
            ? dec.ReadBytes()
            : new byte[0];
    }

    /// <summary>编码后的字节数，仅用于预分配缓冲区。</summary>
    /// <inheritdoc/>
    public int EncodedSize()
    {
        int size = 0;
        size += PbpEncoder.StringSize(pteid);
        size += PbpEncoder.Int64Size(timestamp);
        size += PbpEncoder.StringSize(clientVersion);
        size += PbpEncoder.StringSize(platform);
        size += PbpEncoder.MessageListSize(events);
        size += PbpEncoder.OptionalMessageSize(apm);
        size += PbpEncoder.BytesSize(signature);
        return size;
    }

    // ------------------------------------------------------------ 差分

    /// <summary>相对基线只写变化的字段：存在位图 + 按字段序的变化值。</summary>
    /// <inheritdoc/>
    public void EncodeDelta(PbpEncoder enc, DetectionReport previous)
    {
        bool[] changed =
        {
            !string.Equals(pteid, previous.pteid, StringComparison.Ordinal),
            timestamp != previous.timestamp,
            !string.Equals(clientVersion, previous.clientVersion, StringComparison.Ordinal),
            !string.Equals(platform, previous.platform, StringComparison.Ordinal),
            PbpDelta.Differs(x => x.WriteMessageList(events), x => x.WriteMessageList(previous.events)),
            PbpDelta.Differs(x => x.WriteOptionalMessage(apm), x => x.WriteOptionalMessage(previous.apm)),
            !PbpDelta.BytesEqual(signature, previous.signature),
        };
        enc.WritePresence(changed);
        if (changed[0])
        {
            enc.WriteString(pteid);
        }
        if (changed[1])
        {
            enc.WriteInt64(timestamp);
        }
        if (changed[2])
        {
            enc.WriteString(clientVersion);
        }
        if (changed[3])
        {
            enc.WriteString(platform);
        }
        if (changed[4])
        {
            enc.WriteMessageList(events);
        }
        if (changed[5])
        {
            enc.WriteOptionalMessage(apm);
        }
        if (changed[6])
        {
            enc.WriteBytes(signature);
        }
    }

    /// <summary>未变化的字段从基线拷贝，变化的字段按位图读入；基线对象不会被改动。</summary>
    /// <inheritdoc/>
    public void ApplyDelta(PbpDecoder dec, DetectionReport previous)
    {
        bool[] present = dec.ReadPresence(7);
        pteid = present[0]
            ? dec.ReadString()
            : previous.pteid;
        timestamp = present[1]
            ? dec.ReadInt64()
            : previous.timestamp;
        clientVersion = present[2]
            ? dec.ReadString()
            : previous.clientVersion;
        platform = present[3]
            ? dec.ReadString()
            : previous.platform;
        events = present[4]
            ? dec.ReadMessageList(() => new DetectionEvent())
            : PbpDelta.CopyList(previous.events, () => new DetectionEvent());
        apm = present[5]
            ? dec.ReadOptionalMessage(() => new ApmSnapshot())
            : PbpDelta.Copy(previous.apm, () => new ApmSnapshot());
        signature = present[6]
            ? dec.ReadBytes()
            : (byte[])previous.signature.Clone();
    }

}
