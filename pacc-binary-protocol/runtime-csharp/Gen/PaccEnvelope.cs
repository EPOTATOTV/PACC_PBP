// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl
// 重新生成：cd tools/pbpgen && python -m pbpgen

using System;
using System.Collections.Generic;

namespace Potatotv.Pbp.Gen;

/// <summary>
/// PBP 消息 PaccEnvelope（0x2001，0x2000-0x2FFF 双向）。
///
/// <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
/// 新字段只能追加在末尾，否则两侧解析会整体错位。</p>
/// </summary>
public sealed class PaccEnvelope : IPbpMessage
{
    /// <summary>MDL 里声明的消息 ID。</summary>
    public const int MessageId = 0x2001;

    // ------------------------------------------------------------ 字段

    private string type = "";

    private long tsMs;

    private string nonce = "";

    private string sessionId = "";

    private string pteid = "";

    private string payloadJson = "";

    private int sigVersion;

    // 帧尾签名，载荷里没有这个字段
    private byte[] signature = new byte[0];

    /// <summary>解析路径用它建空对象，字段默认值见声明处。</summary>
    internal PaccEnvelope()
    {
    }

    /// <summary>字段构造器；可空性由 MDL 决定。</summary>
    public sealed class Builder
    {
        private string type = "";

        private long tsMs = 0L;

        private string nonce = "";

        private string sessionId = "";

        private string pteid = "";

        private string payloadJson = "";

        private int sigVersion = 0;

        private byte[] signature = new byte[0];

        internal Builder()
        {
        }

        /// <summary>MDL 字段 1 type。</summary>
        public Builder SetType(string value)
        {
            type = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 2 ts_ms。</summary>
        public Builder SetTsMs(long value)
        {
            tsMs = value;
            return this;
        }

        /// <summary>MDL 字段 3 nonce。</summary>
        public Builder SetNonce(string value)
        {
            nonce = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 4 session_id。</summary>
        public Builder SetSessionId(string value)
        {
            sessionId = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 5 pteid。</summary>
        public Builder SetPteid(string value)
        {
            pteid = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 6 payload_json。</summary>
        public Builder SetPayloadJson(string value)
        {
            payloadJson = value ?? "";
            return this;
        }

        /// <summary>MDL 字段 7 sig_version。</summary>
        public Builder SetSigVersion(int value)
        {
            sigVersion = value;
            return this;
        }

        /// <summary>帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。</summary>
        public Builder SetSignature(string hex)
        {
            signature = SignatureFromHex(hex);
            return this;
        }

        /// <summary>帧尾签名的原始字节；null 视为不签名。</summary>
        public Builder SetSignatureBytes(byte[]? value)
        {
            signature = value == null ? new byte[0] : (byte[])value.Clone();
            return this;
        }

        public PaccEnvelope Build()
        {
            PaccEnvelope msg = new PaccEnvelope();
            msg.type = type;
            msg.tsMs = tsMs;
            msg.nonce = nonce;
            msg.sessionId = sessionId;
            msg.pteid = pteid;
            msg.payloadJson = payloadJson;
            msg.sigVersion = sigVersion;
            msg.signature = (byte[])signature.Clone();
            return msg;
        }
    }

    public static Builder NewBuilder() => new Builder();

    /// <summary>以当前值为初值开一个新 Builder（例如改完字段要重新签名）。</summary>
    public Builder ToBuilder()
    {
        return NewBuilder()
            .SetType(type)
            .SetTsMs(tsMs)
            .SetNonce(nonce)
            .SetSessionId(sessionId)
            .SetPteid(pteid)
            .SetPayloadJson(payloadJson)
            .SetSigVersion(sigVersion)
            .SetSignatureBytes(signature)
            ;
    }

    // ------------------------------------------------------------ 字段读取

    /// <summary>MDL 字段 1 type。</summary>
    public string Type => type;

    /// <summary>MDL 字段 2 ts_ms。</summary>
    public long TsMs => tsMs;

    /// <summary>MDL 字段 3 nonce。</summary>
    public string Nonce => nonce;

    /// <summary>MDL 字段 4 session_id。</summary>
    public string SessionId => sessionId;

    /// <summary>MDL 字段 5 pteid。</summary>
    public string Pteid => pteid;

    /// <summary>MDL 字段 6 payload_json。</summary>
    public string PayloadJson => payloadJson;

    /// <summary>MDL 字段 7 sig_version。</summary>
    public int SigVersion => sigVersion;

    // ------------------------------------------------------------ 帧

    /// <summary>编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。</summary>
    public byte[] ToByteArray()
    {
        PbpFrame frame = PbpCodec.FrameOf(this, tsMs);
        if (signature.Length == PbpFrame.SignatureSize)
        {
            frame = frame.WithSignature(signature);
        }
        else if (signature.Length != 0)
        {
            throw new PbpException(PbpErrorCode.BadLength,
                "签名长度必须是 0 或 " + PbpFrame.SignatureSize + "，实际 " + signature.Length);
        }
        return frame.Encode();
    }

    /// <summary>HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。</summary>
    public byte[] SigningInput() =>
    PbpCodec.FrameOf(this, tsMs).SigningInput();

    /// <summary>解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。</summary>
    public static PaccEnvelope ParseFrom(byte[] raw)
    {
        PbpFrame frame = PbpFrame.Parse(raw);
        if (frame.MessageId != MessageId)
        {
            throw new PbpException(PbpErrorCode.BadFormat,
                "消息 ID 不符：期望 0x" + MessageId.ToString("x")
                + "，实际 0x" + frame.MessageId.ToString("x"));
        }
        PaccEnvelope msg = new PaccEnvelope();
        msg.Decode(new PbpDecoder(PbpCodec.PayloadOf(frame)));
        msg.signature = frame.Signature;
        return msg;
    }

    // ------------------------------------------------------------ 签名

    /// <summary>帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。</summary>
    public string SignatureHex =>
    signature.Length == 0 ? "" : Convert.ToHexString(signature).ToLowerInvariant();

    /// <summary>帧尾签名的副本；未签名返回零长数组。</summary>
    public byte[] SignatureBytes => (byte[])signature.Clone();

    private static byte[] SignatureFromHex(string hex)
    {
        if (string.IsNullOrEmpty(hex))
        {
            return new byte[0];
        }
        return Convert.FromHexString(hex);
    }

    // ------------------------------------------------------------ IPbpMessage

    /// <inheritdoc/>
    public int GetMessageId() => MessageId;

    /// <inheritdoc/>
    public void Encode(PbpEncoder enc)
    {
        enc.WriteString(type);
        enc.WriteInt64(tsMs);
        enc.WriteString(nonce);
        enc.WriteString(sessionId);
        enc.WriteString(pteid);
        enc.WriteString(payloadJson);
        enc.WriteUInt8(sigVersion);
    }

    /// <summary>按定义顺序读回字段；末尾字段在载荷提前读完时取默认值。</summary>
    /// <inheritdoc/>
    public void Decode(PbpDecoder dec)
    {
        type = dec.ReadString();
        tsMs = dec.ReadInt64();
        nonce = dec.ReadString();
        sessionId = dec.ReadString();
        pteid = dec.ReadString();
        payloadJson = dec.ReadString();
        // 末尾字段自动 optional：旧端的载荷在这里已经读完
        sigVersion = dec.Remaining > 0
            ? dec.ReadUInt8()
            : 0;
    }

    /// <summary>编码后的字节数，仅用于预分配缓冲区。</summary>
    /// <inheritdoc/>
    public int EncodedSize()
    {
        int size = 0;
        size += PbpEncoder.StringSize(type);
        size += PbpEncoder.Int64Size(tsMs);
        size += PbpEncoder.StringSize(nonce);
        size += PbpEncoder.StringSize(sessionId);
        size += PbpEncoder.StringSize(pteid);
        size += PbpEncoder.StringSize(payloadJson);
        size += PbpEncoder.Uint8Size();
        return size;
    }

}
