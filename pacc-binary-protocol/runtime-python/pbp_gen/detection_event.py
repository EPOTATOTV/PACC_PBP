"""PBP 消息 ``DetectionEvent``（由 tools/pbpgen 生成，请勿手改）。"""
# 本文件由 tools/pbpgen 生成，请勿手改。
# 源定义：pacc-binary-protocol/mdl/detection.mdl
# 重新生成：cd tools/pbpgen && python -m pbpgen

from __future__ import annotations

from .pbp_core import (PbpDecoder, PbpEncoder, PbpMessage)


class DetectionEvent(PbpMessage):
    """
    PBP 消息 ``DetectionEvent``，无消息 ID，仅作为嵌套类型内联在父消息载荷里。

    字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
    新字段只能追加在末尾，否则两侧解析会整体错位。
    """

    OPTIONAL_FIELD_COUNT = 1

    # ------------------------------------------------------------ 字段

    def __init__(self):
        self.event_type = 0
        self.confidence = 0.0
        self.timestamp = 0
        self.evidence = {}
        self.detail = None

    # ------------------------------------------------------------ 字段设置

    @classmethod
    def new_builder(cls):
        return cls()

    def build(self):
        return self

    def set_event_type(self, value):
        self.event_type = value
        return self

    def set_confidence(self, value):
        self.confidence = value
        return self

    def set_timestamp(self, value):
        self.timestamp = value
        return self

    def set_evidence(self, value):
        self.evidence = {} if value is None else dict(value)
        return self

    def put_evidence(self, key, value):
        self.evidence[key] = value
        return self

    def set_detail(self, value):
        self.detail = value
        return self

    # ------------------------------------------------------------ 编解码

    # 编码后的字节数，仅用于预分配缓冲区。
    def encoded_size(self):
        size = 0
        size += PbpEncoder.int32_size(self.event_type)
        size += PbpEncoder.float32_size()
        size += PbpEncoder.int64_size(self.timestamp)
        size += PbpEncoder.string_map_size(self.evidence, PbpEncoder.bytes_size)
        size += PbpEncoder.optional_string_size(self.detail)
        return size

    # 把自身字段按编号升序写入编码器。
    def encode(self, enc):
        enc.write_int32(self.event_type)
        enc.write_float32(self.confidence)
        enc.write_int64(self.timestamp)
        enc.write_string_map(self.evidence, PbpEncoder.write_bytes)
        enc.write_optional_string(self.detail)

    # 按编号顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    # 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（§3.11）。
    def decode(self, dec):
        self.event_type = dec.read_int32()
        self.confidence = dec.read_float32()
        self.timestamp = dec.read_int64()
        self.evidence = dec.read_string_map(PbpDecoder.read_bytes)
        self.detail = dec.read_optional_string()

