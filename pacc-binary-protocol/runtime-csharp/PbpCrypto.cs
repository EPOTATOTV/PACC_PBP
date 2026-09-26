using System.Security.Cryptography;

namespace Potatotv.Pbp;

/// <summary>
/// PBP 安全层的签名原语：HMAC-SHA256。用 BCL 自带实现，不引任何 NuGet 包。
///
/// <p>载荷加密不在本运行时里（帧层也未实现加密标志位，遇到即拒绝），
/// 所以这里只保留签名相关的最小集合。</p>
/// </summary>
public static class PbpCrypto
{
    public const int NonceSize = 12;

    public const int TagSize = 16;

    public const int KeySize = 32;

    public static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using HMACSHA256 mac = new HMACSHA256(key);
        return mac.ComputeHash(data);
    }

    /// <summary>校验 HMAC，用恒定时间比较避免按字节提前返回泄漏签名前缀。</summary>
    public static bool VerifyHmac(byte[] key, byte[] data, byte[]? expected)
    {
        if (expected == null || expected.Length != 32)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(HmacSha256(key, data), expected);
    }

    /// <summary>恒定时间比较任意等长字节串。</summary>
    public static bool ConstantTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>由会话 ID 与帧序号拼出 nonce：8 字节会话 ID + 4 字节序号（均小端）。</summary>
    public static byte[] NewNonce(ulong sessionId, uint sequence)
    {
        byte[] nonce = new byte[NonceSize];
        for (int i = 0; i < 8; i++)
        {
            nonce[i] = (byte)(sessionId >> (i * 8));
        }
        for (int i = 0; i < 4; i++)
        {
            nonce[8 + i] = (byte)(sequence >> (i * 8));
        }
        return nonce;
    }
}