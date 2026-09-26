using System;

namespace Potatotv.Pbp;

/// <summary>
/// 一条消息 ID 上的差分链：发送侧决定"发完整还是发差分"，接收侧按标志位回放。
///
/// <ul>
///   <li>最多连续 <see cref="MaxConsecutive"/> 条差分后必须发一条完整消息（防累积误差）；</li>
///   <li>差分以"上一轮同 ID 的消息"为基线，双方各自维护，两端处理路径完全对称。</li>
/// </ul>
///
/// <p>每条消息一条链实例，按"一条连接一个方向"使用：里面存着基线与计数，非线程安全。</p>
/// </summary>
public sealed class PbpDeltaChain<T> where T : class, IPbpMessage, IPbpDeltaMessage<T>
{
    /// <summary>连续差分上限。</summary>
    public const int MaxConsecutive = 10;

    private readonly int messageId;
    private readonly Func<T> factory;
    private T? previous;
    private int consecutive;

    public PbpDeltaChain(int messageId, Func<T> factory)
    {
        this.messageId = messageId;
        this.factory = factory;
    }

    /// <summary>已连续发出的 / 收到的差分条数。</summary>
    public int Consecutive => consecutive;

    /// <summary>丢弃基线，下一条必定发完整消息。</summary>
    public void Reset()
    {
        previous = null;
        consecutive = 0;
    }

    /// <summary>
    /// 发送侧：按规则选择完整或差分，并把当前消息深拷贝为新基线。
    ///
    /// <returns>待发送的帧；差分时置 <c>FLAG_DELTA</c>，压得动时置 <c>FLAG_COMPRESSED</c>。</returns>
    /// </summary>
    public PbpFrame Encode(T current, long timestampMs)
    {
        if (current == null)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "差分链消息为 null");
        }
        bool useDelta = previous != null && consecutive < MaxConsecutive;
        byte[] payload;
        if (useDelta)
        {
            PbpEncoder encoder = new PbpEncoder();
            current.EncodeDelta(encoder, previous!);
            payload = encoder.ToByteArray();
        }
        else
        {
            payload = PbpCodec.PayloadOf(current);
        }
        byte[] packed = PbpCodec.MaybeCompress(payload);
        PbpFrame frame = PbpFrame.Of(messageId, timestampMs, packed);
        if (useDelta)
        {
            frame = frame.WithFlag(PbpFrame.FlagDelta);
        }
        if (!ReferenceEquals(packed, payload))
        {
            frame = frame.WithFlag(PbpFrame.FlagCompressed);
        }
        previous = PbpDelta.Copy(current, factory);
        consecutive = useDelta ? consecutive + 1 : 0;
        return frame;
    }

    /// <summary>
    /// 接收侧：完整消息直接解码，差分消息在基线上回放。
    ///
    /// <p>没有基线时收到差分、或连续差分超过上限，都按协议错误拒绝——这两种情况说明
    /// 对端状态与本端不一致，继续解会把错位的数据当有效消息用。</p>
    /// </summary>
    public T Decode(byte[] frameBytes)
    {
        PbpFrame frame = PbpFrame.Parse(frameBytes);
        if (frame.MessageId != messageId)
        {
            throw new PbpException(PbpErrorCode.BadFormat,
                "差分链消息 ID 不符：期望 0x" + messageId.ToString("x")
                    + "，实际 0x" + frame.MessageId.ToString("x"));
        }
        T message = factory();
        if (frame.Delta)
        {
            if (previous == null)
            {
                throw new PbpException(PbpErrorCode.BadFormat, "收到差分帧，但没有可用基线");
            }
            if (consecutive >= MaxConsecutive)
            {
                throw new PbpException(PbpErrorCode.BadFormat,
                    "连续差分超过 " + MaxConsecutive + " 条，发送方应先发完整消息");
            }
            message.ApplyDelta(new PbpDecoder(PbpCodec.PayloadOf(frame)), previous);
        }
        else
        {
            message.Decode(new PbpDecoder(PbpCodec.PayloadOf(frame)));
        }
        previous = PbpDelta.Copy(message, factory);
        consecutive = frame.Delta ? consecutive + 1 : 0;
        return message;
    }
}