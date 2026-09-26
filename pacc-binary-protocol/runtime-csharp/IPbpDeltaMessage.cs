namespace Potatotv.Pbp;

/// <summary>
/// 支持差分编码的消息。
///
/// <p>由 tools/pbpgen 为「带消息 ID 且不依赖帧尾签名」的消息生成：
/// <see cref="EncodeDelta"/> 只写与基线不同的字段，<see cref="ApplyDelta"/> 先用基线补齐、
/// 再覆盖变化的部分。位图与值的布局是「存在位图（ceil(N/8) 字节）+ 按字段序的变化值」。</p>
///
/// <p>带 signed 选项的消息不生成差分方法：帧尾签名与差分基线是两套状态，混用时
/// "签名覆盖的载荷"与"基线对应的载荷"很容易对不上，风险比省下的字节值钱。</p>
/// </summary>
public interface IPbpDeltaMessage<T>
{
    /// <summary>相对基线编码差异：位图 + 变化字段的值。</summary>
    void EncodeDelta(PbpEncoder enc, T previous);

    /// <summary>用基线补齐未变化的字段，再读入变化的字段；不会改动传入的基线对象。</summary>
    void ApplyDelta(PbpDecoder dec, T previous);
}