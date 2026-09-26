"""PBP 消息 ``DetectionReport``（由 tools/pbpgen 生成，请勿手改）。"""
# 本文件由 tools/pbpgen 生成，请勿手改。
# 源定义：pacc-binary-protocol/mdl/detection.mdl
# 重新生成：cd tools/pbpgen && python -m pbpgen

from __future__ import annotations

from .apm_snapshot import ApmSnapshot
from .detection_event import DetectionEvent

from .pbp_core import (PbpCodec, PbpDecoder, PbpDelta, PbpDeltaMessage, PbpEncoder, PbpErrorCode, PbpException, PbpFrame, PbpMessage)


class DetectionReport(PbpMessage, PbpDeltaMessage):
    """
    PBP 消息 ``DetectionReport``（``0x0103``，0x0100-0x0FFF 客户端 → 服务端）。

    字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
    新字段只能追加在末尾，否则两侧解析会整体错位。

    可经 PbpDeltaChain 发差分帧（设计文档 §3.10.2）：
    encode_delta 只写变化字段，apply_delta 从基线补齐未变字段。
    """

    MESSAGE_ID = 0x0103

    OPTIONAL_FIELD_COUNT = 1

    # ------------------------------------------------------------ 字段

    def __init__(self):
        self.pteid = ""
        self.timestamp = 0
        self.client_version = ""
        self.platform = ""
        self.events = []
        self.apm = None
        self.signature = b""

    # ------------------------------------------------------------ 字段设置

    @classmethod
    def new_builder(cls):
        return cls()

    def build(self):
        return self

    def set_pteid(self, value):
        self.pteid = "" if value is None else value
        return self

    def set_timestamp(self, value):
        self.timestamp = value
        return self

    def set_client_version(self, value):
        self.client_version = "" if value is None else value
        return self

    def set_platform(self, value):
        self.platform = "" if value is None else value
        return self

    def set_events(self, value):
        self.events = [] if value is None else list(value)
        return self

    def add_events(self, value):
        self.events.append(value)
        return self

    def set_apm(self, value):
        self.apm = value
        return self

    def set_signature(self, value):
        self.signature = b"" if value is None else bytes(value)
        return self

    # ------------------------------------------------------------ 帧

    # 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。
    def to_bytes(self):
        frame = PbpCodec.frame_of(self, 0)
        return frame.encode()

    # 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。
    @staticmethod
    def parse_from(raw):
        frame = PbpFrame.parse(raw)
        if frame.message_id != DetectionReport.MESSAGE_ID:
            raise PbpException(PbpErrorCode.BAD_FORMAT,
                "消息 ID 不符：期望 0x%04X，实际 0x%04X"
                    % (DetectionReport.MESSAGE_ID, frame.message_id))
        msg = DetectionReport()
        msg.decode(PbpDecoder(PbpCodec.payload_of_frame(frame)))
        return msg

    # ------------------------------------------------------------ 编解码

    # 编码后的字节数，仅用于预分配缓冲区。
    def encoded_size(self):
        size = 0
        size += PbpEncoder.string_size(self.pteid)
        size += PbpEncoder.int64_size(self.timestamp)
        size += PbpEncoder.string_size(self.client_version)
        size += PbpEncoder.string_size(self.platform)
        size += PbpEncoder.message_list_size(self.events)
        size += PbpEncoder.optional_message_size(self.apm)
        size += PbpEncoder.bytes_size(self.signature)
        return size

    # 把自身字段按编号升序写入编码器。
    def encode(self, enc):
        enc.write_string(self.pteid)
        enc.write_int64(self.timestamp)
        enc.write_string(self.client_version)
        enc.write_string(self.platform)
        enc.write_message_list(self.events)
        enc.write_optional_message(self.apm)
        enc.write_bytes(self.signature)

    # 按编号顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    # 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（§3.11）。
    def decode(self, dec):
        self.pteid = dec.read_string()
        self.timestamp = dec.read_int64()
        self.client_version = dec.read_string()
        self.platform = dec.read_string()
        self.events = dec.read_message_list(DetectionEvent)
        self.apm = dec.read_optional_message(ApmSnapshot)
        # 末尾字段自动 optional：旧端的载荷在这里已经读完
        self.signature = dec.read_bytes() if dec.remaining() > 0 else b""

    # ------------------------------------------------------------ 差分（设计文档 §3.10.2）

    # 相对基线只写变化的字段：存在位图 + 按字段序的变化值。
    def encode_delta(self, enc, previous):
        changed = [
            self.pteid != previous.pteid,
            self.timestamp != previous.timestamp,
            self.client_version != previous.client_version,
            self.platform != previous.platform,
            PbpDelta.differs(lambda e: e.write_message_list(self.events), lambda e: e.write_message_list(previous.events)),
            PbpDelta.differs(lambda e: e.write_optional_message(self.apm), lambda e: e.write_optional_message(previous.apm)),
            self.signature != previous.signature,
        ]
        enc.write_presence(changed)
        if changed[0]:
            enc.write_string(self.pteid)
        if changed[1]:
            enc.write_int64(self.timestamp)
        if changed[2]:
            enc.write_string(self.client_version)
        if changed[3]:
            enc.write_string(self.platform)
        if changed[4]:
            enc.write_message_list(self.events)
        if changed[5]:
            enc.write_optional_message(self.apm)
        if changed[6]:
            enc.write_bytes(self.signature)

    # 未变化的字段从基线拷贝（消息深拷贝、集合按元素复制），变化的字段按位图读入；
    # 传入的基线对象不会被改动。
    def apply_delta(self, dec, previous):
        present = dec.read_presence(7)
        self.pteid = dec.read_string() if present[0] else previous.pteid
        self.timestamp = dec.read_int64() if present[1] else previous.timestamp
        self.client_version = dec.read_string() if present[2] else previous.client_version
        self.platform = dec.read_string() if present[3] else previous.platform
        self.events = dec.read_message_list(DetectionEvent) if present[4] else [PbpDelta.copy(item, DetectionEvent) for item in previous.events]
        self.apm = dec.read_optional_message(ApmSnapshot) if present[5] else PbpDelta.copy(previous.apm, ApmSnapshot)
        self.signature = dec.read_bytes() if present[6] else bytes(previous.signature)

