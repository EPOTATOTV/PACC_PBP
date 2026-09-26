using System;
using System.Collections.Generic;

namespace Potatotv.Pbp;

/// <summary>
/// 消息 ID → 解码器工厂的注册表。
///
/// <p>刻意只用显式注册，不扫描程序集、不用反射：反射既破坏零依赖目标，
/// 又会在客户端混淆后因类名变化而失效。</p>
/// </summary>
public sealed class PbpRegistry
{
    /// <summary>消息 ID 区间。</summary>
    public const int SystemMin = 0x0000;
    public const int SystemMax = 0x00FF;
    public const int ClientToServerMin = 0x0100;
    public const int ClientToServerMax = 0x0FFF;
    public const int ServerToClientMin = 0x1000;
    public const int ServerToClientMax = 0x1FFF;
    public const int BidirectionalMin = 0x2000;
    public const int BidirectionalMax = 0x2FFF;

    /// <summary>预留区间，禁止使用；同名的来源侧常量在 <c>tools/pbpgen/pbpgen/model.py</c>。</summary>
    public const int ReservedMin = 0x3000;
    public const int ReservedMax = 0xEFFF;
    public const int CustomMin = 0xF000;
    public const int CustomMax = 0xFFFF;

    private readonly Dictionary<int, Func<IPbpMessage>> factories = new Dictionary<int, Func<IPbpMessage>>();

    /// <summary>注册一个消息 ID 与它的空实例工厂。重复或越界 ID 直接抛错。</summary>
    public void Register<T>(int messageId, Func<T> factory) where T : IPbpMessage
    {
        if (messageId < SystemMin || messageId > CustomMax)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "消息 ID 越界: " + messageId.ToString("x"));
        }
        // 已知区间彼此首尾相接，唯一的窟窿就是 0x3000-0xEFFF 这段预留区，别漏掉它。
        if (messageId >= ReservedMin && messageId <= ReservedMax)
        {
            throw new PbpException(PbpErrorCode.BadFormat, "消息 ID 落在预留区间: " + messageId.ToString("x"));
        }
        if (factories.ContainsKey(messageId))
        {
            throw new PbpException(PbpErrorCode.BadFormat, "消息 ID 重复注册: " + messageId.ToString("x"));
        }
        factories[messageId] = () => factory();
    }

    /// <summary>新建一条消息实例；未注册的 ID 返回 null（调用方决定是忽略还是断开）。</summary>
    public IPbpMessage? NewInstance(int messageId) =>
        factories.TryGetValue(messageId, out Func<IPbpMessage>? factory) ? factory() : null;

    public bool Contains(int messageId) => factories.ContainsKey(messageId);

    public int Size => factories.Count;
}