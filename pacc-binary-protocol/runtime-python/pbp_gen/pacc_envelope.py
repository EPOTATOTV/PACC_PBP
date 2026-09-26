"""PBP 消息 ``PaccEnvelope``（由 tools/pbpgen 生成，请勿手改）。"""
# 本文件由 tools/pbpgen 生成，请勿手改。
# 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl
# 重新生成：cd tools/pbpgen && python -m pbpgen

from __future__ import annotations

from .pbp_core import (PbpCodec, PbpDecoder, PbpEncoder, PbpErrorCode, PbpException, PbpFrame, PbpMessage)


class PaccEnvelope(PbpMessage):
    """
    PBP 消息 ``PaccEnvelope``（``0x2001``，0x2000-0x2FFF 双向）。

    字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
    新字段只能追加在末尾，否则两侧解析会整体错位。

    签名不在载荷里：置位帧头 FLAG_SIGNED，32 字节 HMAC-SHA256 放在帧尾，
    覆盖面是「帧头 + 载荷」整串字节（见 signing_input）。
    """

    MESSAGE_ID = 0x2001

    # ------------------------------------------------------------ 字段

    def __init__(self):
        self.type = ""
        self.ts_ms = 0
        self.nonce = ""
        self.session_id = ""
        self.pteid = ""
        self.payload_json = ""
        self.sig_version = 0
        self.signature = b""

    # ------------------------------------------------------------ 字段设置

    @classmethod
    def new_builder(cls):
        return cls()

    def build(self):
        return self

    def set_type(self, value):
        self.type = "" if value is None else value
        return self

    def set_ts_ms(self, value):
        self.ts_ms = value
        return self

    def set_nonce(self, value):
        self.nonce = "" if value is None else value
        return self

    def set_session_id(self, value):
        self.session_id = "" if value is None else value
        return self

    def set_pteid(self, value):
        self.pteid = "" if value is None else value
        return self

    def set_payload_json(self, value):
        self.payload_json = "" if value is None else value
        return self

    def set_sig_version(self, value):
        self.sig_version = value
        return self

    def set_signature_bytes(self, value):
        self.signature = b"" if value is None else bytes(value)
        return self

    # ------------------------------------------------------------ 帧

    # 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。
    def to_bytes(self):
        frame = PbpCodec.frame_of(self, self.ts_ms)
        if len(self.signature) == PbpFrame.SIGNATURE_SIZE:
            frame = frame.with_signature(self.signature)
        elif len(self.signature) != 0:
            raise PbpException(PbpErrorCode.BAD_LENGTH,
                "签名长度必须是 0 或 %d，实际 %d" % (PbpFrame.SIGNATURE_SIZE, len(self.signature)))
        return frame.encode()

    # HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。
    def signing_input(self):
        return PbpCodec.frame_of(self, self.ts_ms).signing_input()

    # 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。
    @staticmethod
    def parse_from(raw):
        frame = PbpFrame.parse(raw)
        if frame.message_id != PaccEnvelope.MESSAGE_ID:
            raise PbpException(PbpErrorCode.BAD_FORMAT,
                "消息 ID 不符：期望 0x%04X，实际 0x%04X"
                    % (PaccEnvelope.MESSAGE_ID, frame.message_id))
        msg = PaccEnvelope()
        msg.decode(PbpDecoder(PbpCodec.payload_of_frame(frame)))
        msg.signature = frame.signature
        return msg

    # ------------------------------------------------------------ 编解码

    # 编码后的字节数，仅用于预分配缓冲区。
    def encoded_size(self):
        size = 0
        size += PbpEncoder.string_size(self.type)
        size += PbpEncoder.int64_size(self.ts_ms)
        size += PbpEncoder.string_size(self.nonce)
        size += PbpEncoder.string_size(self.session_id)
        size += PbpEncoder.string_size(self.pteid)
        size += PbpEncoder.string_size(self.payload_json)
        size += PbpEncoder.uint8_size()
        return size

    # 把自身字段按编号升序写入编码器。
    def encode(self, enc):
        enc.write_string(self.type)
        enc.write_int64(self.ts_ms)
        enc.write_string(self.nonce)
        enc.write_string(self.session_id)
        enc.write_string(self.pteid)
        enc.write_string(self.payload_json)
        enc.write_uint8(self.sig_version)

    # 按编号顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    # 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（§3.11）。
    def decode(self, dec):
        self.type = dec.read_string()
        self.ts_ms = dec.read_int64()
        self.nonce = dec.read_string()
        self.session_id = dec.read_string()
        self.pteid = dec.read_string()
        self.payload_json = dec.read_string()
        # 末尾字段自动 optional：旧端的载荷在这里已经读完
        self.sig_version = dec.read_uint8() if dec.remaining() > 0 else 0

