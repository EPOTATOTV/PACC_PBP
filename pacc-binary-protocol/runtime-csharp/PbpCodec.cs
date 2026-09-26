namespace Potatotv.Pbp;

/// <summary>
/// 载荷 ↔ 帧的组装层。
///
/// <p>把「消息编码 → 压缩策略 → 帧装配」和「帧解析 → 解压」两条固定链路收敛到一处，
/// 生成代码的 ToByteArray/ParseFrom/SigningInput 都走它。压缩决策是载荷的确定性函数：
/// 任何一端拿字段重新编码一遍都能得到同一串待签字节。</p>
///
/// <p>策略：载荷超过 <see cref="CompressThreshold"/> 才尝试压缩，压完比原文小才启用。
/// 阈值以下不压，意味着绝大多数握手 / 指令信封的线上字节与引入压缩之前完全一致。</p>
/// </summary>
public static class PbpCodec
{
    /// <summary>触发压缩尝试的载荷长度。</summary>
    public const int CompressThreshold = 1024;

    /// <summary>编码消息载荷（不含帧头）。</summary>
    public static byte[] PayloadOf(IPbpMessage message)
    {
        if (message == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "消息为 null，无法编码");
        }
        PbpEncoder encoder = new PbpEncoder();
        message.Encode(encoder);
        return encoder.ToByteArray();
    }

    /// <summary>
    /// 按策略尝试压缩。不值得压缩时原样返回入参，调用方用引用相等判断是否启用。
    /// </summary>
    public static byte[] MaybeCompress(byte[] payload)
    {
        if (payload == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "载荷为 null，无法压缩");
        }
        if (payload.Length <= CompressThreshold)
        {
            return payload;
        }
        byte[] packed = PbpZstd.Compress(payload);
        return packed.Length < payload.Length ? packed : payload;
    }

    /// <summary>组装整帧：需要压缩时置 <c>FLAG_COMPRESSED</c>。</summary>
    public static PbpFrame FrameOf(IPbpMessage message, long timestampMs)
    {
        byte[] payload = PayloadOf(message);
        byte[] packed = MaybeCompress(payload);
        PbpFrame frame = PbpFrame.Of(message.GetMessageId(), timestampMs, packed);
        return ReferenceEquals(packed, payload) ? frame : frame.WithFlag(PbpFrame.FlagCompressed);
    }

    /// <summary>取出帧载荷：声明压缩就解压。解压上限取载荷长度上限，兼作解压炸弹的拦截点。</summary>
    public static byte[] PayloadOf(PbpFrame frame)
    {
        if (frame == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "帧为 null，无法取载荷");
        }
        if (!frame.Compressed)
        {
            return frame.Payload;
        }
        return PbpZstd.Decompress(frame.Payload, PbpFrame.MaxPayloadSize);
    }
}