package com.potatotv.pbp;

/**
 * 载荷 ↔ 帧的组装层。
 *
 * <p>把「消息编码 → 压缩策略 → 帧装配」和「帧解析 → 解压」这两条固定链路收敛到一处，
 * 生成代码的 {@code toByteArray/parseFrom/signingInput} 都走它。压缩决策是<b>载荷的
 * 确定性函数</b>：任何一端拿字段重新编码一遍都能得到同一串待签字节，所以验签端不需要
 * 保留原始压缩载荷，也不会出现"编码端压了、验签端没压"的两侧不一致。</p>
 *
 * <p>策略照设计文档 §3.10.1：载荷超过 {@link #COMPRESS_THRESHOLD} 才尝试压缩，
 * 压完比原文小才启用。阈值以下不压，意味着绝大多数握手 / 指令信封的线上字节与
 * 引入压缩之前完全一致。</p>
 *
 * <p>压缩子集的边界见 {@link PbpZstd}：解压遇到子集之外的能力会显式失败，
 * 不会把没校验过的数据当有效载荷交出去。</p>
 */
public final class PbpCodec {

    /** 触发压缩尝试的载荷长度（设计文档 §3.10.1）。 */
    public static final int COMPRESS_THRESHOLD = 1024;

    private PbpCodec() {
    }

    /** 编码消息载荷（不含帧头）。 */
    public static byte[] payloadOf(PbpMessage message) {
        if (message == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "消息为 null，无法编码");
        }
        PbpEncoder encoder = new PbpEncoder(Math.max(64, message.encodedSize()));
        message.encode(encoder);
        return encoder.toByteArray();
    }

    /**
     * 按策略尝试压缩。
     *
     * <p>不值得压缩时<b>原样返回入参</b>，调用方用引用相等判断是否启用，
     * 避免"内容恰好一样长但其实是两个对象"这类误判。</p>
     */
    public static byte[] maybeCompress(byte[] payload) {
        if (payload == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "载荷为 null，无法压缩");
        }
        if (payload.length <= COMPRESS_THRESHOLD) {
            return payload;
        }
        byte[] packed = PbpZstd.compress(payload);
        return packed.length < payload.length ? packed : payload;
    }

    /** 组装整帧：需要压缩时置 {@link PbpFrame#FLAG_COMPRESSED}。 */
    public static PbpFrame frameOf(PbpMessage message, long timestampMs) {
        byte[] payload = payloadOf(message);
        byte[] packed = maybeCompress(payload);
        PbpFrame frame = PbpFrame.of(message.messageId(), timestampMs, packed);
        return packed == payload ? frame : frame.withFlag(PbpFrame.FLAG_COMPRESSED);
    }

    /**
     * 取出帧载荷：声明压缩就解压。
     *
     * <p>解压上限取载荷长度上限（16MB），既是"解压不能超过原文规模约定"的护栏，
     * 也是解压炸弹的拦截点。</p>
     */
    public static byte[] payloadOf(PbpFrame frame) {
        if (frame == null) {
            throw new PbpException(PbpException.Code.BAD_FORMAT, "帧为 null，无法取载荷");
        }
        if (!frame.compressed()) {
            return frame.payload();
        }
        return PbpZstd.decompress(frame.payload(), PbpFrame.MAX_PAYLOAD_SIZE);
    }
}