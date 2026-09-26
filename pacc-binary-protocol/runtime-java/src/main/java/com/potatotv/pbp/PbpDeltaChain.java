package com.potatotv.pbp;

import java.util.function.Supplier;

/**
 * 一条消息 ID 上的差分链：发送侧决定"发完整还是发差分"，接收侧按标志位回放。
 *
 * <p>设计文档 §3.10.2 的两条硬规则都在这里落地：</p>
 * <ul>
 *   <li>最多连续 {@link #MAX_CONSECUTIVE} 条差分后必须发一条完整消息（防累积误差）；</li>
 *   <li>差分以"上一轮同 ID 的消息"为基线，双方各自维护；两端的处理路径完全对称，
 *       所以只要发送方合规，接收方拿到的就是同一份基线。</li>
 * </ul>
 *
 * <p>每条消息一条链实例，按"一条连接一个方向"使用：里面存着基线与计数，非线程安全。</p>
 *
 * <p>需要压缩的大载荷（差分结果超过 1KB）会走与普通帧相同的压缩策略，
 * 两种标志可以同时出现：{@code FLAG_DELTA | FLAG_COMPRESSED}，接收侧先解压再回放差分。</p>
 *
 * <p>本类不处理帧尾签名：带 signed 的消息不生成差分方法（见 {@link PbpDeltaMessage}），
 * 需要签名时由调用方在返回的帧上补。</p>
 *
 * @param <T> 同一条链上承载的消息类型
 */
public final class PbpDeltaChain<T extends PbpMessage & PbpDeltaMessage<T>> {

    /** 连续差分上限（设计文档 §3.10.2）。 */
    public static final int MAX_CONSECUTIVE = 10;

    private final int messageId;
    private final Supplier<T> factory;
    private T previous;
    private int consecutive;

    public PbpDeltaChain(int messageId, Supplier<T> factory) {
        this.messageId = messageId;
        this.factory = factory;
    }

    /** 已连续发出的 / 收到的差分条数。 */
    public int consecutive() {
        return consecutive;
    }

    /** 丢弃基线，下一条必定发完整消息（重连、丢帧后的复位点）。 */
    public void reset() {
        previous = null;
        consecutive = 0;
    }

    /**
     * 发送侧：按规则选择完整或差分，并把当前消息深拷贝为新基线。
     *
     * @return 待发送的帧；差分时置 {@code FLAG_DELTA}，压得动时置 {@code FLAG_COMPRESSED}
     */
    public PbpFrame encode(T current, long timestampMs) {
        if (current == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "差分链消息为 null");
        }
        boolean useDelta = previous != null && consecutive < MAX_CONSECUTIVE;
        byte[] payload;
        if (useDelta) {
            PbpEncoder encoder = new PbpEncoder(Math.max(64, current.encodedSize() / 2 + 8));
            current.encodeDelta(encoder, previous);
            payload = encoder.toByteArray();
        } else {
            payload = PbpCodec.payloadOf(current);
        }
        byte[] packed = PbpCodec.maybeCompress(payload);
        PbpFrame frame = PbpFrame.of(messageId, timestampMs, packed);
        if (useDelta) {
            frame = frame.withFlag(PbpFrame.FLAG_DELTA);
        }
        if (packed != payload) {
            frame = frame.withFlag(PbpFrame.FLAG_COMPRESSED);
        }
        previous = PbpDelta.copy(current, factory);
        consecutive = useDelta ? consecutive + 1 : 0;
        return frame;
    }

    /**
     * 接收侧：完整消息直接解码，差分消息在基线上回放。
     *
     * <p>没有基线时收到差分、或连续差分超过上限，都按协议错误拒绝——
     * 这两种情况说明对端状态与本端不一致，继续解会把错位的数据当有效消息用。</p>
     */
    public T decode(byte[] frameBytes) {
        PbpFrame frame = PbpFrame.parse(frameBytes);
        if (frame.messageId() != messageId) {
            throw new PbpException(PbpException.Code.BAD_FORMAT,
                    "差分链消息 ID 不符：期望 0x" + Integer.toHexString(messageId)
                            + "，实际 0x" + Integer.toHexString(frame.messageId()));
        }
        T message = factory.get();
        if (frame.delta()) {
            if (previous == null) {
                throw new PbpException(PbpException.Code.BAD_FORMAT, "收到差分帧，但没有可用基线");
            }
            if (consecutive >= MAX_CONSECUTIVE) {
                throw new PbpException(PbpException.Code.BAD_FORMAT,
                        "连续差分超过 " + MAX_CONSECUTIVE + " 条，发送方应先发完整消息");
            }
            message.applyDelta(new PbpDecoder(PbpCodec.payloadOf(frame)), previous);
        } else {
            message.decode(new PbpDecoder(PbpCodec.payloadOf(frame)));
        }
        previous = PbpDelta.copy(message, factory);
        consecutive = frame.delta() ? consecutive + 1 : 0;
        return message;
    }
}