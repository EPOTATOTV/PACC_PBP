"""PBP 消息 ``ApmSnapshot``（由 tools/pbpgen 生成，请勿手改）。"""
# 本文件由 tools/pbpgen 生成，请勿手改。
# 源定义：pacc-binary-protocol/mdl/detection.mdl
# 重新生成：cd tools/pbpgen && python -m pbpgen

from __future__ import annotations

from .pbp_core import (PbpDecoder, PbpEncoder, PbpMessage)


class ApmSnapshot(PbpMessage):
    """
    PBP 消息 ``ApmSnapshot``，无消息 ID，仅作为嵌套类型内联在父消息载荷里。

    字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；
    新字段只能追加在末尾，否则两侧解析会整体错位。
    """

    # ------------------------------------------------------------ 字段

    def __init__(self):
        self.cpu_usage = 0.0
        self.memory_usage_kb = 0
        self.fps = 0.0
        self.detection_latency_ms = 0
        self.active_rules = 0
        self.custom_metrics = {}

    # ------------------------------------------------------------ 字段设置

    @classmethod
    def new_builder(cls):
        return cls()

    def build(self):
        return self

    def set_cpu_usage(self, value):
        self.cpu_usage = value
        return self

    def set_memory_usage_kb(self, value):
        self.memory_usage_kb = value
        return self

    def set_fps(self, value):
        self.fps = value
        return self

    def set_detection_latency_ms(self, value):
        self.detection_latency_ms = value
        return self

    def set_active_rules(self, value):
        self.active_rules = value
        return self

    def set_custom_metrics(self, value):
        self.custom_metrics = {} if value is None else dict(value)
        return self

    def put_custom_metrics(self, key, value):
        self.custom_metrics[key] = value
        return self

    # ------------------------------------------------------------ 编解码

    # 编码后的字节数，仅用于预分配缓冲区。
    def encoded_size(self):
        size = 0
        size += PbpEncoder.float32_size()
        size += PbpEncoder.int32_size(self.memory_usage_kb)
        size += PbpEncoder.float32_size()
        size += PbpEncoder.int32_size(self.detection_latency_ms)
        size += PbpEncoder.int32_size(self.active_rules)
        size += PbpEncoder.string_map_size(self.custom_metrics, lambda v: PbpEncoder.float32_size())
        return size

    # 把自身字段按编号升序写入编码器。
    def encode(self, enc):
        enc.write_float32(self.cpu_usage)
        enc.write_int32(self.memory_usage_kb)
        enc.write_float32(self.fps)
        enc.write_int32(self.detection_latency_ms)
        enc.write_int32(self.active_rules)
        enc.write_string_map(self.custom_metrics, PbpEncoder.write_float32)

    # 按编号顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），
    # 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（§3.11）。
    def decode(self, dec):
        self.cpu_usage = dec.read_float32()
        self.memory_usage_kb = dec.read_int32()
        self.fps = dec.read_float32()
        self.detection_latency_ms = dec.read_int32()
        self.active_rules = dec.read_int32()
        self.custom_metrics = dec.read_string_map(PbpDecoder.read_float32)

