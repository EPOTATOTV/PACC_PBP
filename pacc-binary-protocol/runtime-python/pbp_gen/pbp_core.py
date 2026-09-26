"""PBP 二进制协议运行时核心（Python，仅标准库）。

本文件由 tools/pbpgen 生成，请勿手改。
重新生成：cd tools/pbpgen && python -m pbpgen

语义与 Java 运行时（pacc-binary-protocol/runtime-java）逐条对齐：
  * VarInt 为 LEB128；多字节定长字段与帧头一律小端
  * int32/int64 走 ZigZag；presence 位图低位在前
  * 读越界抛 PbpException；UTF-8 严格解码；集合元素个数有上界
  * 帧头 30 字节，签名覆盖「帧头(FLAG_SIGNED 置位) + 载荷」
Python 侧不实现 zstd：编码不压缩，收到声明压缩的帧显式失败（压缩互操作由 Java/TS/Rust/C# 覆盖）。
"""

from __future__ import annotations

import hashlib
import hmac
import struct

MAX_VARINT_BYTES = 10
MAX_COLLECTION_SIZE = 1 << 20

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


class PbpErrorCode:
    """失败原因分类，与 Java 的 PbpException.Code 取值一一对应。"""

    BAD_MAGIC = "BAD_MAGIC"
    BAD_VERSION = "BAD_VERSION"
    UNSUPPORTED_FLAG = "UNSUPPORTED_FLAG"
    UNSUPPORTED = "UNSUPPORTED"
    BAD_LENGTH = "BAD_LENGTH"
    TAG_MISMATCH = "TAG_MISMATCH"
    TRUNCATED = "TRUNCATED"
    BAD_VARINT = "BAD_VARINT"
    BAD_FORMAT = "BAD_FORMAT"


class PbpException(Exception):
    """PBP 编解码与帧解析异常；code 供调用方区分「协议不认识」与「疑似篡改」。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class PbpMessage:
    """可编码的 PBP 消息基类。字段顺序即协议，生成类由 tools/pbpgen 产出。"""

    MESSAGE_ID = 0

    def message_id(self):
        return type(self).MESSAGE_ID

    def encode(self, enc):
        raise NotImplementedError

    def decode(self, dec):
        raise NotImplementedError

    def encoded_size(self):
        raise NotImplementedError


class PbpDeltaMessage:
    """支持差分编码的消息（设计文档 §3.10.2）。"""

    def encode_delta(self, enc, previous):
        raise NotImplementedError

    def apply_delta(self, dec, previous):
        raise NotImplementedError


class PbpEncoder:
    """按字段顺序写入、不带标签的二进制编码器；多字节定长字段一律小端。"""

    def __init__(self, initial_capacity=64):
        self._buf = bytearray(max(16, initial_capacity))
        self._len = 0

    def size(self):
        return self._len

    def to_bytes(self):
        return bytes(self._buf[: self._len])

    def reset(self):
        self._len = 0

    # ------------------------------------------------------------ 标量

    def write_bool(self, v):
        self._write_raw(1 if v else 0)
        return self

    def write_int8(self, v):
        self._require_range(v, -0x80, 0x7F, "int8")
        self._write_raw(v)
        return self

    def write_uint8(self, v):
        self._require_range(v, 0, 0xFF, "uint8")
        self._write_raw(v)
        return self

    def write_int16(self, v):
        self._require_range(v, -0x8000, 0x7FFF, "int16")
        self._write_raw(v)
        self._write_raw(v >> 8)
        return self

    def write_uint16(self, v):
        self._require_range(v, 0, 0xFFFF, "uint16")
        self._write_raw(v)
        self._write_raw(v >> 8)
        return self

    def write_int32(self, v):
        self._write_varint(((v << 1) ^ (v >> 31)) & _MASK32)
        return self

    def write_uint32(self, v):
        self._require_range(v, 0, _MASK32, "uint32")
        self._write_varint(v)
        return self

    def write_int64(self, v):
        self._write_varint(((v << 1) ^ (v >> 63)) & _MASK64)
        return self

    def write_uint64(self, v):
        self._require_range(v, 0, _MASK64, "uint64")
        self._write_varint(v)
        return self

    def write_enum(self, v):
        if v < 0:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "enum 值不能为负: %d" % v)
        self._write_varint(v)
        return self

    def write_float32(self, v):
        self._write_bytes(struct.pack("<f", v))
        return self

    def write_float64(self, v):
        self._write_bytes(struct.pack("<d", v))
        return self

    # ------------------------------------------------------------ 变长

    def write_string(self, s):
        if s is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "string 字段为 null，可空字段请用 write_optional_string")
        data = s.encode("utf-8")
        self._write_varint(len(data))
        self._write_bytes(data)
        return self

    def write_bytes(self, b):
        if b is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "bytes 字段为 null，可空字段请用 write_optional_bytes")
        self._write_varint(len(b))
        self._write_bytes(b)
        return self

    # ------------------------------------------------------------ 可空字段

    def write_presence(self, present):
        """写入存在位图：低位对应更靠前的字段，与 read_presence 成对。"""
        present = list(present)
        byte_count = (len(present) + 7) // 8
        for i in range(byte_count):
            bits = 0
            for bit in range(8):
                idx = i * 8 + bit
                if idx < len(present) and present[idx]:
                    bits |= 1 << bit
            self._write_raw(bits)
        return self

    def write_optional_string(self, s):
        self.write_presence([s is not None])
        return self if s is None else self.write_string(s)

    def write_optional_bytes(self, b):
        self.write_presence([b is not None])
        return self if b is None else self.write_bytes(b)

    def write_optional_message(self, m):
        self.write_presence([m is not None])
        return self if m is None else self.write_message(m)

    # ------------------------------------------------------------ 消息与集合

    def write_message(self, m):
        """嵌套消息内联编码，不加长度前缀：字段顺序即边界。"""
        if m is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "嵌套消息为 null，可空字段请用 write_optional_message")
        m.encode(self)
        return self

    def write_message_list(self, messages):
        if messages is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "消息列表为 null")
        self._write_varint(len(messages))
        for m in messages:
            m.encode(self)
        return self

    def write_string_list(self, values):
        return self.write_list(values, PbpEncoder.write_string)

    def write_list(self, values, element_writer):
        if values is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "列表为 null")
        self._write_varint(len(values))
        for element in values:
            element_writer(self, element)
        return self

    def write_map(self, mapping, key_writer, value_writer):
        """键值对按 dict 迭代顺序写入，两侧需用有序容器才能保证字节一致。"""
        if mapping is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "map 为 null")
        self._write_varint(len(mapping))
        for key, value in mapping.items():
            key_writer(self, key)
            value_writer(self, value)
        return self

    def write_string_map(self, mapping, value_writer):
        return self.write_map(mapping, PbpEncoder.write_string, value_writer)

    # ------------------------------------------------------------ 长度预估（纯预分配提示）

    @staticmethod
    def var_int_size(value):
        n = 1
        while value & ~0x7F:
            value >>= 7
            n += 1
        return n

    @staticmethod
    def bool_size():
        return 1

    @staticmethod
    def int8_size():
        return 1

    @staticmethod
    def uint8_size():
        return 1

    @staticmethod
    def int16_size():
        return 2

    @staticmethod
    def uint16_size():
        return 2

    @staticmethod
    def int32_size(v):
        return PbpEncoder.var_int_size(((v << 1) ^ (v >> 31)) & _MASK32)

    @staticmethod
    def uint32_size(v):
        return PbpEncoder.var_int_size(v)

    @staticmethod
    def int64_size(v):
        return PbpEncoder.var_int_size(((v << 1) ^ (v >> 63)) & _MASK64)

    @staticmethod
    def uint64_size(v):
        return PbpEncoder.var_int_size(v)

    @staticmethod
    def enum_size(v):
        return PbpEncoder.var_int_size(v)

    @staticmethod
    def float32_size():
        return 4

    @staticmethod
    def float64_size():
        return 8

    @staticmethod
    def string_size(s):
        if s is None:
            return 0
        return PbpEncoder.var_int_size(len(s.encode("utf-8"))) + len(s.encode("utf-8"))

    @staticmethod
    def bytes_size(b):
        return 0 if b is None else PbpEncoder.var_int_size(len(b)) + len(b)

    @staticmethod
    def presence_size(field_count):
        return (field_count + 7) // 8

    @staticmethod
    def optional_string_size(s):
        return 1 + PbpEncoder.string_size(s)

    @staticmethod
    def optional_bytes_size(b):
        return 1 + PbpEncoder.bytes_size(b)

    @staticmethod
    def message_size(m):
        return 0 if m is None else m.encoded_size()

    @staticmethod
    def optional_message_size(m):
        return 1 + PbpEncoder.message_size(m)

    @staticmethod
    def message_list_size(messages):
        if messages is None:
            return 0
        size = PbpEncoder.var_int_size(len(messages))
        for m in messages:
            size += m.encoded_size()
        return size

    @staticmethod
    def string_list_size(values):
        if values is None:
            return 0
        size = PbpEncoder.var_int_size(len(values))
        for s in values:
            size += PbpEncoder.string_size(s)
        return size

    @staticmethod
    def list_size(values, element_size):
        if values is None:
            return 0
        size = PbpEncoder.var_int_size(len(values))
        for element in values:
            size += element_size(element)
        return size

    @staticmethod
    def map_size(mapping, key_size, value_size):
        if mapping is None:
            return 0
        size = PbpEncoder.var_int_size(len(mapping))
        for key, value in mapping.items():
            size += key_size(key) + value_size(value)
        return size

    @staticmethod
    def string_map_size(mapping, value_size):
        return PbpEncoder.map_size(mapping, PbpEncoder.string_size, value_size)

    # ------------------------------------------------------------ 落地

    def _write_raw(self, value):
        self._ensure(1)
        self._buf[self._len] = value & 0xFF
        self._len += 1

    def _write_bytes(self, data):
        if not data:
            return
        self._ensure(len(data))
        self._buf[self._len : self._len + len(data)] = data
        self._len += len(data)

    def _write_varint(self, value):
        value &= _MASK64
        while value & ~0x7F:
            self._write_raw((value & 0x7F) | 0x80)
            value >>= 7
        self._write_raw(value & 0x7F)

    def _ensure(self, extra):
        need = self._len + extra
        if need <= len(self._buf):
            return
        capacity = len(self._buf)
        while capacity < need:
            capacity = capacity * 2 if capacity < 1024 else capacity + (capacity >> 1)
        self._buf.extend(bytes(capacity - len(self._buf)))

    @staticmethod
    def _require_range(value, low, high, type_name):
        if value < low or value > high:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "%s 越界: %d" % (type_name, value))


class PbpDecoder:
    """与 PbpEncoder 严格镜像的解码器；所有读取做边界检查，越界一律抛错。"""

    def __init__(self, buf, offset=0, length=None):
        raw = bytes(buf)
        if length is None:
            length = len(raw) - offset
        if offset < 0 or length < 0 or offset + length > len(raw):
            raise PbpException(PbpErrorCode.BAD_LENGTH, "解码窗口越界: offset=%d length=%d capacity=%d"
                               % (offset, length, len(raw)))
        self._buf = raw
        self._pos = offset
        self._limit = offset + length

    def remaining(self):
        return self._limit - self._pos

    def has_remaining(self):
        return self._pos < self._limit

    def position(self):
        return self._pos

    def skip_remaining(self):
        self._pos = self._limit

    # ------------------------------------------------------------ 标量

    def read_bool(self):
        b = self._read_raw()
        if b not in (0, 1):
            raise PbpException(PbpErrorCode.BAD_FORMAT, "bool 字段只能是 0/1，读到 %d" % b)
        return b == 1

    def read_int8(self):
        b = self._read_raw()
        return b - 256 if b >= 128 else b

    def read_uint8(self):
        return self._read_raw()

    def read_int16(self):
        lo = self._read_raw()
        hi = self._read_raw()
        v = (hi << 8) | lo
        return v - 0x10000 if v >= 0x8000 else v

    def read_uint16(self):
        lo = self._read_raw()
        hi = self._read_raw()
        return (hi << 8) | lo

    def read_int32(self):
        z = self._read_varint() & _MASK32
        return (z >> 1) ^ -(z & 1)

    def read_uint32(self):
        v = self._read_varint()
        if v > _MASK32:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "uint32 溢出: %d" % v)
        return v

    def read_int64(self):
        z = self._read_varint()
        return (z >> 1) ^ -(z & 1)

    def read_uint64(self):
        return self._read_varint()

    def read_enum(self):
        v = self.read_uint32()
        if v > 0x7FFFFFFF:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "enum 值溢出: %d" % v)
        return v

    def read_float32(self):
        return struct.unpack("<f", self._read_exact(4))[0]

    def read_float64(self):
        return struct.unpack("<d", self._read_exact(8))[0]

    # ------------------------------------------------------------ 变长

    def read_string(self):
        length = self._read_length()
        data = self._read_exact(length)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "字符串字段不是合法 UTF-8") from exc

    def read_bytes(self):
        return self._read_exact(self._read_length())

    # ------------------------------------------------------------ 可空字段

    def read_presence(self, field_count):
        if field_count < 0:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "可空字段数为负: %d" % field_count)
        byte_count = (field_count + 7) // 8
        present = [False] * field_count
        for i in range(byte_count):
            bits = self._read_raw()
            for bit in range(8):
                idx = i * 8 + bit
                if idx < field_count:
                    present[idx] = (bits & (1 << bit)) != 0
        return present

    def read_optional_string(self):
        return self.read_string() if self.read_presence(1)[0] else None

    def read_optional_bytes(self):
        return self.read_bytes() if self.read_presence(1)[0] else None

    def read_optional_message(self, factory):
        return self.read_message(factory) if self.read_presence(1)[0] else None

    # ------------------------------------------------------------ 消息与集合

    def read_message(self, factory):
        message = factory()
        message.decode(self)
        return message

    def read_message_list(self, factory):
        count = self._read_count("list")
        return [self.read_message(factory) for _ in range(count)]

    def read_string_list(self):
        return self.read_list(PbpDecoder.read_string)

    def read_list(self, element_reader):
        count = self._read_count("list")
        return [element_reader(self) for _ in range(count)]

    def read_map(self, key_reader, value_reader):
        count = self._read_count("map")
        out = {}
        for _ in range(count):
            key = key_reader(self)
            out[key] = value_reader(self)
        return out

    def read_string_map(self, value_reader):
        return self.read_map(PbpDecoder.read_string, value_reader)

    # ------------------------------------------------------------ 落地

    def _read_raw(self):
        if self._pos >= self._limit:
            raise PbpException(PbpErrorCode.TRUNCATED,
                               "读取越界: 位置 %d 已达上限 %d" % (self._pos, self._limit))
        value = self._buf[self._pos]
        self._pos += 1
        return value

    def _read_exact(self, length):
        if self.remaining() < length:
            raise PbpException(PbpErrorCode.TRUNCATED,
                               "读取越界: 需要 %d 字节，剩余 %d" % (length, self.remaining()))
        out = self._buf[self._pos : self._pos + length]
        self._pos += length
        return out

    def _read_varint(self):
        value = 0
        for i in range(MAX_VARINT_BYTES):
            b = self._read_raw()
            if i == 9 and (b & 0xFE) != 0:
                raise PbpException(PbpErrorCode.BAD_VARINT, "VarInt 第 10 字节溢出 64 位")
            value |= (b & 0x7F) << (i * 7)
            if (b & 0x80) == 0:
                return value
        raise PbpException(PbpErrorCode.BAD_VARINT, "VarInt 超过 10 字节")

    def _read_length(self):
        length = self._read_varint()
        if length > self.remaining():
            raise PbpException(PbpErrorCode.TRUNCATED,
                               "变长字段声明长度 %d 超出剩余 %d 字节" % (length, self.remaining()))
        return length

    def _read_count(self, what):
        count = self._read_varint()
        if count > MAX_COLLECTION_SIZE:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "%s 元素个数越界: %d" % (what, count))
        return count


class PbpFrame:
    """固定 30 字节帧头 + 载荷 + 可选 32 字节签名（设计文档 §3.3.1）。

    多字节字段一律小端，唯一例外是开头的 2 字节 Magic：它是 ASCII 标记，按 'P','B' 写。
    """

    MAGIC = 0x5042
    VERSION = 1
    MIN_VERSION = 1

    HEADER_SIZE = 30
    SIGNATURE_SIZE = 32

    FLAG_ENCRYPTED = 0x01
    FLAG_COMPRESSED = 0x02
    FLAG_DELTA = 0x04
    FLAG_SIGNED = 0x08
    KNOWN_FLAGS = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_DELTA | FLAG_SIGNED

    MAX_PAYLOAD_SIZE = 16 * 1024 * 1024

    _OFF_MAGIC = 0
    _OFF_VERSION = 2
    _OFF_FLAGS = 3
    _OFF_MESSAGE_ID = 4
    _OFF_SEQUENCE = 6
    _OFF_TIMESTAMP = 10
    _OFF_SESSION_ID = 18
    _OFF_PAYLOAD_LEN = 26

    def __init__(self, version, flags, message_id, sequence, timestamp_ms, session_id,
                 payload=None, signature=None):
        self.version = version
        self.flags = flags
        self.message_id = message_id
        self.sequence = sequence
        self.timestamp_ms = timestamp_ms
        self.session_id = session_id
        self.payload = bytes(payload) if payload else b""
        self.signature = bytes(signature) if signature else b""

    @staticmethod
    def of(message_id, timestamp_ms, payload):
        return PbpFrame(PbpFrame.VERSION, 0, message_id, 0, timestamp_ms, 0, payload)

    def signed(self):
        return (self.flags & PbpFrame.FLAG_SIGNED) != 0

    def compressed(self):
        return (self.flags & PbpFrame.FLAG_COMPRESSED) != 0

    def delta(self):
        return (self.flags & PbpFrame.FLAG_DELTA) != 0

    def payload_length(self):
        return len(self.payload)

    def with_flag(self, flag):
        if flag == 0:
            return self
        if (flag & ~PbpFrame.KNOWN_FLAGS) != 0 or flag == PbpFrame.FLAG_ENCRYPTED:
            raise PbpException(PbpErrorCode.UNSUPPORTED_FLAG, "不能置位未实现的标志: 0x%02x" % flag)
        return PbpFrame(self.version, self.flags | flag, self.message_id, self.sequence,
                        self.timestamp_ms, self.session_id, self.payload, self.signature)

    def with_signature(self, signature):
        if signature is None or len(signature) != PbpFrame.SIGNATURE_SIZE:
            raise PbpException(PbpErrorCode.BAD_LENGTH, "签名必须是 %d 字节，实际 %s"
                               % (PbpFrame.SIGNATURE_SIZE, "null" if signature is None else len(signature)))
        return PbpFrame(self.version, self.flags | PbpFrame.FLAG_SIGNED, self.message_id, self.sequence,
                        self.timestamp_ms, self.session_id, self.payload, signature)

    def signing_input(self):
        """HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。"""
        header = self._header_bytes(self.flags | PbpFrame.FLAG_SIGNED, len(self.payload))
        return header + self.payload

    def encode(self):
        self._validate_flags(self.flags)
        if self.version != PbpFrame.VERSION:
            raise PbpException(PbpErrorCode.BAD_VERSION,
                               "本运行时只支持版本 %d，不能编码版本 %d" % (PbpFrame.VERSION, self.version))
        payload_len = len(self.payload)
        if payload_len > PbpFrame.MAX_PAYLOAD_SIZE:
            raise PbpException(PbpErrorCode.BAD_LENGTH, "载荷长度超上限: %d" % payload_len)
        is_signed = self.signed()
        if is_signed and len(self.signature) != PbpFrame.SIGNATURE_SIZE:
            raise PbpException(PbpErrorCode.BAD_LENGTH, "帧头声明已签名，但签名长度为 %d" % len(self.signature))
        if not is_signed and len(self.signature) != 0:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "带了签名字节但 FLAG_SIGNED 未置位")
        out = self._header_bytes(self.flags, payload_len) + self.payload
        if is_signed:
            out += self.signature
        return out

    @staticmethod
    def parse(raw):
        raw = bytes(raw)
        if len(raw) < PbpFrame.HEADER_SIZE:
            raise PbpException(PbpErrorCode.TRUNCATED, "帧长度不足 %d 字节: %d" % (PbpFrame.HEADER_SIZE, len(raw)))
        magic = (raw[PbpFrame._OFF_MAGIC] << 8) | raw[PbpFrame._OFF_MAGIC + 1]
        if magic != PbpFrame.MAGIC:
            raise PbpException(PbpErrorCode.BAD_MAGIC, 'Magic 不是 "PB": 0x%04x' % magic)
        version = raw[PbpFrame._OFF_VERSION]
        if version < PbpFrame.MIN_VERSION:
            raise PbpException(PbpErrorCode.BAD_VERSION,
                               "协议版本过旧: %d（最低支持 %d）" % (version, PbpFrame.MIN_VERSION))
        if version > PbpFrame.VERSION:
            raise PbpException(PbpErrorCode.BAD_VERSION,
                               "协议版本过新: %d（本运行时最高支持 %d）" % (version, PbpFrame.VERSION))
        flags = raw[PbpFrame._OFF_FLAGS]
        PbpFrame._validate_flags(flags)
        payload_len = _get_u32(raw, PbpFrame._OFF_PAYLOAD_LEN)
        if payload_len > PbpFrame.MAX_PAYLOAD_SIZE:
            raise PbpException(PbpErrorCode.BAD_LENGTH, "载荷长度超上限: %d" % payload_len)
        signed = (flags & PbpFrame.FLAG_SIGNED) != 0
        expected = PbpFrame.HEADER_SIZE + payload_len + (PbpFrame.SIGNATURE_SIZE if signed else 0)
        if len(raw) != expected:
            raise PbpException(PbpErrorCode.BAD_LENGTH,
                               "帧长与 PayloadLen 不符: 实际 %d，按声明应为 %d" % (len(raw), expected))
        payload = raw[PbpFrame.HEADER_SIZE : PbpFrame.HEADER_SIZE + payload_len]
        signature = raw[PbpFrame.HEADER_SIZE + payload_len : expected] if signed else b""
        return PbpFrame(version, flags,
                        _get_u16(raw, PbpFrame._OFF_MESSAGE_ID),
                        _get_u32(raw, PbpFrame._OFF_SEQUENCE),
                        _get_i64(raw, PbpFrame._OFF_TIMESTAMP),
                        _get_u64(raw, PbpFrame._OFF_SESSION_ID),
                        payload, signature)

    @staticmethod
    def _validate_flags(flags):
        if (flags & PbpFrame.FLAG_ENCRYPTED) != 0:
            raise PbpException(PbpErrorCode.UNSUPPORTED_FLAG, "当前版本未实现加密标志位 0x01")
        unknown = flags & ~PbpFrame.KNOWN_FLAGS
        if unknown != 0:
            raise PbpException(PbpErrorCode.UNSUPPORTED_FLAG, "保留标志位被置位: 0x%02x" % unknown)

    def _header_bytes(self, flags, payload_len):
        out = bytearray(PbpFrame.HEADER_SIZE)
        out[PbpFrame._OFF_MAGIC] = PbpFrame.MAGIC >> 8
        out[PbpFrame._OFF_MAGIC + 1] = PbpFrame.MAGIC & 0xFF
        out[PbpFrame._OFF_VERSION] = self.version & 0xFF
        out[PbpFrame._OFF_FLAGS] = flags & 0xFF
        _put_u16(out, PbpFrame._OFF_MESSAGE_ID, self.message_id)
        _put_u32(out, PbpFrame._OFF_SEQUENCE, self.sequence)
        _put_u64(out, PbpFrame._OFF_TIMESTAMP, self.timestamp_ms)
        _put_u64(out, PbpFrame._OFF_SESSION_ID, self.session_id)
        _put_u32(out, PbpFrame._OFF_PAYLOAD_LEN, payload_len)
        return bytes(out)


def _put_u16(buf, offset, value):
    v = value & 0xFFFF
    buf[offset] = v & 0xFF
    buf[offset + 1] = (v >> 8) & 0xFF


def _put_u32(buf, offset, value):
    v = value & _MASK32
    for i in range(4):
        buf[offset + i] = (v >> (i * 8)) & 0xFF


def _put_u64(buf, offset, value):
    v = value & _MASK64
    for i in range(8):
        buf[offset + i] = (v >> (i * 8)) & 0xFF


def _get_u16(buf, offset):
    return buf[offset] | (buf[offset + 1] << 8)


def _get_u32(buf, offset):
    v = 0
    for i in range(4):
        v |= buf[offset + i] << (i * 8)
    return v


def _get_u64(buf, offset):
    v = 0
    for i in range(8):
        v |= buf[offset + i] << (i * 8)
    return v


def _get_i64(buf, offset):
    v = _get_u64(buf, offset)
    return v - (1 << 64) if v >= (1 << 63) else v


class PbpCrypto:
    """只封装标准库的密码学原语；目前只用到 HMAC-SHA256。"""

    @staticmethod
    def hmac_sha256(key, data):
        return hmac.new(bytes(key), bytes(data), hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(key, data, expected):
        """恒定时间比较，避免按字节提前返回泄漏签名前缀。"""
        if expected is None or len(expected) != 32:
            return False
        return hmac.compare_digest(PbpCrypto.hmac_sha256(key, data), bytes(expected))


class PbpCodec:
    """载荷 ↔ 帧的组装层：编码 → 压缩策略 → 帧装配，与 Java 的 PbpCodec 对齐。

    Python 侧不实现 zstd，压缩策略退化为「永不压缩」：载荷原样放进帧，不置 FLAG_COMPRESSED。
    """

    COMPRESS_THRESHOLD = 1024

    @staticmethod
    def payload_of(message):
        if message is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "消息为 null，无法编码")
        encoder = PbpEncoder(max(64, message.encoded_size()))
        message.encode(encoder)
        return encoder.to_bytes()

    @staticmethod
    def maybe_compress(payload):
        if payload is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "载荷为 null，无法压缩")
        return payload

    @staticmethod
    def frame_of(message, timestamp_ms):
        payload = PbpCodec.payload_of(message)
        packed = PbpCodec.maybe_compress(payload)
        return PbpFrame.of(message.message_id(), timestamp_ms, packed)

    @staticmethod
    def payload_of_frame(frame):
        if frame is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "帧为 null，无法取载荷")
        if not frame.compressed():
            return frame.payload
        raise PbpException(PbpErrorCode.UNSUPPORTED, "Python 运行时不实现 zstd 解压")


class PbpDelta:
    """差分编码的公共工具：字段比较与基线深拷贝。"""

    @staticmethod
    def differs(current_writer, previous_writer):
        """两个字段是否不同：把同一套 writer 调用分别写进临时编码器，比字节。"""
        a = PbpEncoder(32)
        b = PbpEncoder(32)
        current_writer(a)
        previous_writer(b)
        return a.to_bytes() != b.to_bytes()

    @staticmethod
    def copy(message, factory):
        if message is None:
            return None
        clone = factory()
        clone.decode(PbpDecoder(PbpCodec.payload_of(message)))
        return clone


class PbpDeltaChain:
    """一条消息 ID 上的差分链；发送侧决定发完整还是发差分，接收侧按标志位回放。"""

    MAX_CONSECUTIVE = 10

    def __init__(self, message_id, factory):
        self._message_id = message_id
        self._factory = factory
        self._previous = None
        self._consecutive = 0

    def consecutive(self):
        return self._consecutive

    def reset(self):
        self._previous = None
        self._consecutive = 0

    def encode(self, current, timestamp_ms):
        if current is None:
            raise PbpException(PbpErrorCode.BAD_FORMAT, "差分链消息为 null")
        use_delta = self._previous is not None and self._consecutive < PbpDeltaChain.MAX_CONSECUTIVE
        if use_delta:
            encoder = PbpEncoder(max(64, current.encoded_size() // 2 + 8))
            current.encode_delta(encoder, self._previous)
            payload = encoder.to_bytes()
        else:
            payload = PbpCodec.payload_of(current)
        packed = PbpCodec.maybe_compress(payload)
        frame = PbpFrame.of(self._message_id, timestamp_ms, packed)
        if use_delta:
            frame = frame.with_flag(PbpFrame.FLAG_DELTA)
        self._previous = PbpDelta.copy(current, self._factory)
        self._consecutive = self._consecutive + 1 if use_delta else 0
        return frame

    def decode(self, frame_bytes):
        frame = PbpFrame.parse(frame_bytes)
        if frame.message_id != self._message_id:
            raise PbpException(PbpErrorCode.BAD_FORMAT,
                               "差分链消息 ID 不符：期望 0x%04X，实际 0x%04X"
                               % (self._message_id, frame.message_id))
        message = self._factory()
        if frame.delta():
            if self._previous is None:
                raise PbpException(PbpErrorCode.BAD_FORMAT, "收到差分帧，但没有可用基线")
            if self._consecutive >= PbpDeltaChain.MAX_CONSECUTIVE:
                raise PbpException(PbpErrorCode.BAD_FORMAT,
                                   "连续差分超过 %d 条，发送方应先发完整消息" % PbpDeltaChain.MAX_CONSECUTIVE)
            message.apply_delta(PbpDecoder(PbpCodec.payload_of_frame(frame)), self._previous)
        else:
            message.decode(PbpDecoder(PbpCodec.payload_of_frame(frame)))
        self._previous = PbpDelta.copy(message, self._factory)
        self._consecutive = self._consecutive + 1 if frame.delta() else 0
        return message
