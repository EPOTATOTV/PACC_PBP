"""Python 代码生成（设计文档 §3.12）。

设计文档只给了 Java/TS/Rust/C# 四个独立运行时，Python 这一路改成「生成器顺带生成运行时」：
`pbp_core.py` 只用标准库实现编码器/解码器/帧/HMAC/存在位图，各消息模块 import 它。
这样「生成的 Python 代码」真正能编译运行，不需要再维护第五个运行时目录。

生成物同样入库、同样要过漂移检查，所以输出必须逐字节确定：不写生成时间、不依赖字典
遍历顺序、字段按编号升序。

与 Java emitter（emit/java.py）的契约保持一致：
  * `// optional` 字段走存在位图（write_presence / read_presence）
  * 末尾字段「载荷读完取默认值」只对带消息 ID 的消息生效（model 已标 trailing）
  * 带消息 ID 且不 signed 的消息发 encode_delta/apply_delta（字段级差分）
  * 帧装配与压缩策略统一走 PbpCodec，生成代码不重复实现

Python 侧不实现 zstd：`PbpCodec.maybe_compress` 原样返回载荷，收到声明压缩的帧显式失败。
所以 `big_frame_compressed` 这类压缩向量在 Python 测试里跳过（由其余四端覆盖）。

`pbp_gen/__init__.py` 与 `pbp_gen/pbp_core.py` 是「非单个 MDL 来源」的共享产物：
core 与 schema 无关，`__init__` 要聚合所有 MDL 的导出。逐 schema 调 `emit_schema` 会为每个
schema 各产出一份 `__init__.py`（内容不同）从而互相覆盖；多 MDL 场景应改用 `emit_package`。
"""

from __future__ import annotations

import re

from ..model import Enum, Message, ResolvedField, ResolvedType, Schema, id_range_label

_GENERATOR_NOTE = "本文件由 tools/pbpgen 生成，请勿手改。"
_REGENERATE = "重新生成：cd tools/pbpgen && python -m pbpgen"

# 生成物的 Python 包名（相对源码根 pacc-binary-protocol/runtime-python 的目录）。
PACKAGE = "pbp_gen"
CORE_MODULE = "pbp_core"

_CORE_EXPORTS = (
    "PbpCodec",
    "PbpCrypto",
    "PbpDecoder",
    "PbpDelta",
    "PbpDeltaChain",
    "PbpDeltaMessage",
    "PbpEncoder",
    "PbpErrorCode",
    "PbpException",
    "PbpFrame",
    "PbpMessage",
)

# MDL 标量 → (写方法, 读方法, 长度方法, 长度方法是否带值)。
_SCALAR_METHODS = {
    "bool": ("write_bool", "read_bool", "bool_size", False),
    "int8": ("write_int8", "read_int8", "int8_size", False),
    "uint8": ("write_uint8", "read_uint8", "uint8_size", False),
    "int16": ("write_int16", "read_int16", "int16_size", False),
    "uint16": ("write_uint16", "read_uint16", "uint16_size", False),
    "int32": ("write_int32", "read_int32", "int32_size", True),
    "uint32": ("write_uint32", "read_uint32", "uint32_size", True),
    "int64": ("write_int64", "read_int64", "int64_size", True),
    "uint64": ("write_uint64", "read_uint64", "uint64_size", True),
    "float32": ("write_float32", "read_float32", "float32_size", False),
    "float64": ("write_float64", "read_float64", "float64_size", False),
    "string": ("write_string", "read_string", "string_size", True),
    "bytes": ("write_bytes", "read_bytes", "bytes_size", True),
}

_PY_SCALAR_DEFAULTS = {
    "bool": "False",
    "int8": "0",
    "uint8": "0",
    "int16": "0",
    "uint16": "0",
    "int32": "0",
    "uint32": "0",
    "int64": "0",
    "uint64": "0",
    "float32": "0.0",
    "float64": "0.0",
    "string": '""',
    "bytes": 'b""',
}


def emit_schema(schema: Schema, mdl_rel: str) -> dict[str, str]:
    """返回 {相对 Python 源码根的路径: 文件内容}。

    含该 schema 的消息/枚举模块，外加 pbp_core.py 与只导出本 schema 的 __init__.py。
    多个 MDL 共享同一输出目录时应改用 emit_package，否则 __init__.py 会被互相覆盖。
    """
    files: dict[str, str] = {
        f"{PACKAGE}/__init__.py": _emit_init([mdl_rel], schema.messages, schema.enums),
        f"{PACKAGE}/{CORE_MODULE}.py": _CORE_SOURCE,
    }
    for enum in schema.enums:
        files[f"{PACKAGE}/{_snake(enum.name)}.py"] = _emit_enum(enum, mdl_rel)
    for message in schema.messages:
        files[f"{PACKAGE}/{_snake(message.name)}.py"] = _emit_message(message, mdl_rel)
    return files


def emit_package(schemas: list[Schema]) -> dict[str, str]:
    """多 MDL 聚合成一个 Python 包：core 与 __init__.py 只出一份。

    路径与 emit_schema 一致，直接写进 `pacc-binary-protocol/runtime-python` 即可。
    """
    messages = [message for schema in schemas for message in schema.messages]
    enums = [enum for schema in schemas for enum in schema.enums]
    files: dict[str, str] = {
        f"{PACKAGE}/__init__.py": _emit_init([schema.path for schema in schemas], messages, enums),
        f"{PACKAGE}/{CORE_MODULE}.py": _CORE_SOURCE,
    }
    for schema in schemas:
        for enum in schema.enums:
            files[f"{PACKAGE}/{_snake(enum.name)}.py"] = _emit_enum(enum, schema.path)
        for message in schema.messages:
            files[f"{PACKAGE}/{_snake(message.name)}.py"] = _emit_message(message, schema.path)
    return files


# ---------------------------------------------------------------- 工具


def _snake(name: str) -> str:
    """PascalCase → snake_case（PaccEnvelope → pacc_envelope，ApmSnapshot → apm_snapshot）。"""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _generator_header(mdl_rel: str) -> list[str]:
    return [
        f"# {_GENERATOR_NOTE}",
        f"# 源定义：{mdl_rel}",
        f"# {_REGENERATE}",
    ]


def _methods(value: ResolvedType) -> tuple[str, str, str, bool]:
    if value.kind == "enum":
        return ("write_enum", "read_enum", "enum_size", True)
    if value.kind == "message":
        return ("write_message", "read_message", "message_size", True)
    return _SCALAR_METHODS[value.name]


def _delta_capable(message: Message) -> bool:
    """带 signed 的消息不发差分（见 emit/java.py 的同名判断，理由一致）。"""
    return message.framed and not message.signed


def _uses_pbp_delta(message: Message) -> bool:
    for field in message.fields:
        value = field.value_type
        if field.is_list or field.is_map or value.kind == "message":
            return True
        if value.name in ("float32", "float64"):
            return True
    return False


# ---------------------------------------------------------------- __init__


def _emit_init(mdl_rels: list[str], messages: tuple[Message, ...], enums: tuple[Enum, ...]) -> str:
    lines = [
        '"""PBP 生成代码包（由 tools/pbpgen 生成，请勿手改）。"""',
    ]
    lines.extend(_generator_header("、".join(mdl_rels)))
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    core = ",\n".join("    %s" % name for name in _CORE_EXPORTS)
    lines.append("from .%s import (\n%s,\n)" % (CORE_MODULE, core))
    type_names = [enum.name for enum in enums] + [message.name for message in messages]
    if type_names:
        lines.append("")
        for name in sorted(type_names):
            lines.append("from .%s import %s" % (_snake(name), name))
    lines.append("")
    lines.append("")
    exported = sorted(set(_CORE_EXPORTS) | set(type_names))
    lines.append("__all__ = [")
    for name in exported:
        lines.append('    "%s",' % name)
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- 枚举


def _emit_enum(enum: Enum, mdl_rel: str) -> str:
    lines = [
        f'"""MDL 枚举 ``{enum.name}``（由 tools/pbpgen 生成，请勿手改）。"""',
    ]
    lines.extend(_generator_header(mdl_rel))
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("")
    lines.append("class %s:" % enum.name)
    lines.append('    """枚举在线上是 VarInt 编码的非负整数，这里就是一组常量。"""')
    lines.append("")
    for name, number in enum.values:
        lines.append("    %s = %d" % (name, number))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- 消息


def _emit_message(message: Message, mdl_rel: str) -> str:
    lines = [
        f'"""PBP 消息 ``{message.name}``（由 tools/pbpgen 生成，请勿手改）。"""',
    ]
    lines.extend(_generator_header(mdl_rel))
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    referenced = sorted({f.value_type.name for f in message.fields if f.value_type.kind == "message"})
    for name in referenced:
        lines.append("from .%s import %s" % (_snake(name), name))
    if referenced:
        lines.append("")
    lines.append("from .%s import (%s)" % (CORE_MODULE, ", ".join(_core_imports(message))))
    lines.append("")
    lines.append("")

    bases = ["PbpMessage"]
    if _delta_capable(message):
        bases.append("PbpDeltaMessage")
    lines.append("class %s(%s):" % (message.name, ", ".join(bases)))
    lines.extend(_class_doc(message))
    lines.append("")

    emitter = _MessageEmitter(message)
    emitter.emit_body()
    lines.extend(emitter.lines)
    lines.append("")
    return "\n".join(lines)


def _core_imports(message: Message) -> list[str]:
    names = ["PbpDecoder", "PbpEncoder", "PbpMessage"]
    if message.framed:
        names += ["PbpCodec", "PbpErrorCode", "PbpException", "PbpFrame"]
    if _delta_capable(message):
        names.append("PbpDeltaMessage")
        if _uses_pbp_delta(message):
            names.append("PbpDelta")
    return sorted(set(names))


def _class_doc(message: Message) -> list[str]:
    lines = ['    """']
    if message.framed:
        lines.append(f"    PBP 消息 ``{message.name}``（``0x{message.message_id:04X}``，"
                     f"{id_range_label(message.message_id)}）。")
    else:
        lines.append(f"    PBP 消息 ``{message.name}``，无消息 ID，仅作为嵌套类型内联在父消息载荷里。")
    lines.append("")
    lines.append("    字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；")
    lines.append("    新字段只能追加在末尾，否则两侧解析会整体错位。")
    if message.signed:
        lines.append("")
        lines.append("    签名不在载荷里：置位帧头 FLAG_SIGNED，32 字节 HMAC-SHA256 放在帧尾，")
        lines.append("    覆盖面是「帧头 + 载荷」整串字节（见 signing_input）。")
    if _delta_capable(message):
        lines.append("")
        lines.append("    可经 PbpDeltaChain 发差分帧（设计文档 §3.10.2）：")
        lines.append("    encode_delta 只写变化字段，apply_delta 从基线补齐未变字段。")
    lines.append('    """')
    return lines


class _MessageEmitter:
    def __init__(self, message: Message):
        self.message = message
        self.lines: list[str] = []

    def add(self, text: str = "", indent: int = 1) -> None:
        self.lines.append(("    " * indent + text) if text else "")

    # ------------------------------------------------------------ 工具

    def default_expr(self, field: ResolvedField) -> str:
        if field.is_list:
            return "[]"
        if field.is_map:
            return "{}"
        value = field.value_type
        if value.kind == "message" or field.optional:
            return "None"
        if value.kind == "enum":
            return "0"
        return _PY_SCALAR_DEFAULTS[value.name]

    # ------------------------------------------------------------ 类体

    def emit_body(self) -> None:
        self._constants()
        self._fields()
        self._builder()
        if self.message.framed:
            self._frame_and_signature()
        self._core_methods()
        self._delta_methods()

    def _constants(self) -> None:
        message = self.message
        if message.framed:
            self.add(f"MESSAGE_ID = 0x{message.message_id:04X}")
            self.add("")
        if message.optional_field_count:
            self.add(f"OPTIONAL_FIELD_COUNT = {message.optional_field_count}")
            self.add("")

    def _fields(self) -> None:
        message = self.message
        self.add("# ------------------------------------------------------------ 字段")
        self.add("")
        self.add("def __init__(self):")
        emitted = False
        for field in message.fields:
            self.add(f"self.{field.name} = {self.default_expr(field)}", 2)
            emitted = True
        if message.signed:
            # 帧尾签名，载荷里没有这个字段
            self.add('self.signature = b""', 2)
            emitted = True
        if not emitted:
            self.add("pass", 2)
        self.add("")

    def _builder(self) -> None:
        message = self.message
        self.add("# ------------------------------------------------------------ 字段设置")
        self.add("")
        self.add("@classmethod")
        self.add("def new_builder(cls):")
        self.add("return cls()", 2)
        self.add("")
        self.add("def build(self):")
        self.add("return self", 2)
        self.add("")
        for field in message.fields:
            self.add(f"def set_{field.name}(self, value):")
            self.add(f"self.{field.name} = {self._setter_expr(field)}", 2)
            self.add("return self", 2)
            self.add("")
            if field.is_list:
                self.add(f"def add_{field.name}(self, value):")
                self.add(f"self.{field.name}.append(value)", 2)
                self.add("return self", 2)
                self.add("")
            if field.is_map:
                self.add(f"def put_{field.name}(self, key, value):")
                self.add(f"self.{field.name}[key] = value", 2)
                self.add("return self", 2)
                self.add("")
        if message.signed:
            self.add("def set_signature_bytes(self, value):")
            self.add('self.signature = b"" if value is None else bytes(value)', 2)
            self.add("return self", 2)
            self.add("")

    @staticmethod
    def _setter_expr(field: ResolvedField) -> str:
        if field.is_list:
            return "[] if value is None else list(value)"
        if field.is_map:
            return "{} if value is None else dict(value)"
        value = field.value_type
        if value.name == "bytes" and value.kind == "scalar":
            return 'b"" if value is None else bytes(value)'
        if value.name == "string" and value.kind == "scalar" and not field.optional:
            return '"" if value is None else value'
        return "value"

    # ------------------------------------------------------------ 帧

    def _frame_and_signature(self) -> None:
        message = self.message
        frame_ts = f"self.{message.frame_timestamp_field.name}" if message.frame_timestamp_field else "0"

        self.add("# ------------------------------------------------------------ 帧")
        self.add("")
        if message.signed:
            self.add("# 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。")
        else:
            self.add("# 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。")
        self.add("def to_bytes(self):")
        self.add(f"frame = PbpCodec.frame_of(self, {frame_ts})", 2)
        if message.signed:
            self.add("if len(self.signature) == PbpFrame.SIGNATURE_SIZE:", 2)
            self.add("frame = frame.with_signature(self.signature)", 3)
            self.add("elif len(self.signature) != 0:", 2)
            self.add("raise PbpException(PbpErrorCode.BAD_LENGTH,", 3)
            self.add('"签名长度必须是 0 或 %d，实际 %d" % (PbpFrame.SIGNATURE_SIZE, len(self.signature)))', 4)
            self.add("return frame.encode()", 2)
        else:
            self.add("return frame.encode()", 2)
        self.add("")

        if message.signed:
            self.add("# HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷。")
            self.add("def signing_input(self):")
            self.add(f"return PbpCodec.frame_of(self, {frame_ts}).signing_input()", 2)
            self.add("")

        self.add("# 解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。")
        self.add("@staticmethod")
        self.add("def parse_from(raw):")
        self.add("frame = PbpFrame.parse(raw)", 2)
        self.add("if frame.message_id != %s.MESSAGE_ID:" % message.name, 2)
        self.add("raise PbpException(PbpErrorCode.BAD_FORMAT,", 3)
        self.add('"消息 ID 不符：期望 0x%04X，实际 0x%04X"', 4)
        self.add("    %% (%s.MESSAGE_ID, frame.message_id))" % message.name, 4)
        self.add("msg = %s()" % message.name, 2)
        self.add("msg.decode(PbpDecoder(PbpCodec.payload_of_frame(frame)))", 2)
        if message.signed:
            self.add("msg.signature = frame.signature", 2)
        self.add("return msg", 2)
        self.add("")

    # ------------------------------------------------------------ 核心

    def _core_methods(self) -> None:
        message = self.message
        self.add("# ------------------------------------------------------------ 编解码")
        self.add("")
        self.add("# 编码后的字节数，仅用于预分配缓冲区。")
        self.add("def encoded_size(self):")
        self.add("size = 0", 2)
        for field in message.fields:
            self.add(f"size += {_size_expr(field)}", 2)
        self.add("return size", 2)
        self.add("")

        self.add("# 把自身字段按编号升序写入编码器。")
        self.add("def encode(self, enc):")
        for field in message.fields:
            self.add(f"enc.{_encode_call(field)}", 2)
        if not message.fields:
            self.add("pass", 2)
        self.add("")

        self.add("# 按编号顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），")
        self.add("# 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（§3.11）。")
        self.add("def decode(self, dec):")
        for field in message.fields:
            if field.trailing:
                self.add("# 末尾字段自动 optional：旧端的载荷在这里已经读完", 2)
                self.add(f"self.{field.name} = "
                         f"{_decode_expr(field)} if dec.remaining() > 0 else {self.default_expr(field)}", 2)
            else:
                self.add(f"self.{field.name} = {_decode_expr(field)}", 2)
        self.add("")

    # ------------------------------------------------------------ 差分

    def _delta_methods(self) -> None:
        message = self.message
        if not _delta_capable(message):
            return
        self.add("# ------------------------------------------------------------ 差分（设计文档 §3.10.2）")
        self.add("")
        self.add("# 相对基线只写变化的字段：存在位图 + 按字段序的变化值。")
        self.add("def encode_delta(self, enc, previous):")
        self.add("changed = [", 2)
        for field in message.fields:
            self.add(f"{_diff_expr(field)},", 3)
        self.add("]", 2)
        self.add("enc.write_presence(changed)", 2)
        for index, field in enumerate(message.fields):
            self.add(f"if changed[{index}]:", 2)
            self.add(f"enc.{_encode_call(field)}", 3)
        if not message.fields:
            self.add("pass", 2)
        self.add("")

        self.add("# 未变化的字段从基线拷贝（消息深拷贝、集合按元素复制），变化的字段按位图读入；")
        self.add("# 传入的基线对象不会被改动。")
        self.add("def apply_delta(self, dec, previous):")
        self.add(f"present = dec.read_presence({len(message.fields)})", 2)
        for index, field in enumerate(message.fields):
            self.add(f"self.{field.name} = "
                     f"{_decode_expr(field)} if present[{index}] else {_copy_expr(field)}", 2)
        if not message.fields:
            self.add("pass", 2)
        self.add("")


# ---------------------------------------------------------------- 表达式


def _writer_ref(value: ResolvedType) -> str:
    return "PbpEncoder.%s" % _methods(value)[0]


def _reader_ref(value: ResolvedType) -> str:
    return "PbpDecoder.%s" % _methods(value)[1]


def _sizer_ref(value: ResolvedType) -> str:
    writer, _, sizer, takes_value = _methods(value)
    if takes_value:
        return "PbpEncoder.%s" % sizer
    return "lambda v: PbpEncoder.%s()" % sizer


def _encode_call(field: ResolvedField, owner: str = "self") -> str:
    value = field.value_type
    ref = f"{owner}.{field.name}"
    if field.is_map:
        if field.map_key.name == "string":
            return f"write_string_map({ref}, {_writer_ref(value)})"
        return f"write_map({ref}, {_writer_ref(field.map_key)}, {_writer_ref(value)})"
    if field.is_list:
        if value.kind == "message":
            return f"write_message_list({ref})"
        if value.name == "string":
            return f"write_string_list({ref})"
        return f"write_list({ref}, {_writer_ref(value)})"
    if field.optional:
        if value.kind == "message":
            return f"write_optional_message({ref})"
        if value.name == "string":
            return f"write_optional_string({ref})"
        return f"write_optional_bytes({ref})"
    if value.kind == "message":
        return f"write_message({ref})"
    return "%s(%s)" % (_methods(value)[0], ref)


def _decode_expr(field: ResolvedField) -> str:
    value = field.value_type
    if field.is_map:
        if field.map_key.name == "string":
            if value.kind == "message":
                return f"dec.read_map(PbpDecoder.read_string, lambda d: d.read_message({value.name}))"
            return "dec.read_string_map(%s)" % _reader_ref(value)
        if value.kind == "message":
            return "dec.read_map(%s, lambda d: d.read_message(%s))" % (_reader_ref(field.map_key), value.name)
        return "dec.read_map(%s, %s)" % (_reader_ref(field.map_key), _reader_ref(value))
    if field.is_list:
        if value.kind == "message":
            return f"dec.read_message_list({value.name})"
        if value.name == "string":
            return "dec.read_string_list()"
        return "dec.read_list(%s)" % _reader_ref(value)
    if field.optional:
        if value.kind == "message":
            return f"dec.read_optional_message({value.name})"
        if value.name == "string":
            return "dec.read_optional_string()"
        return "dec.read_optional_bytes()"
    if value.kind == "message":
        return f"dec.read_message({value.name})"
    return "dec.%s()" % _methods(value)[1]


def _size_expr(field: ResolvedField) -> str:
    value = field.value_type
    ref = "self." + field.name
    if field.is_map:
        if field.map_key.name == "string":
            return "PbpEncoder.string_map_size(%s, %s)" % (ref, _sizer_ref(value))
        return "PbpEncoder.map_size(%s, %s, %s)" % (ref, _sizer_ref(field.map_key), _sizer_ref(value))
    if field.is_list:
        if value.kind == "message":
            return "PbpEncoder.message_list_size(%s)" % ref
        if value.name == "string":
            return "PbpEncoder.string_list_size(%s)" % ref
        return "PbpEncoder.list_size(%s, %s)" % (ref, _sizer_ref(value))
    if field.optional:
        if value.kind == "message":
            return "PbpEncoder.optional_message_size(%s)" % ref
        if value.name == "string":
            return "PbpEncoder.optional_string_size(%s)" % ref
        return "PbpEncoder.optional_bytes_size(%s)" % ref
    if value.kind == "message":
        return "PbpEncoder.message_size(%s)" % ref
    if _methods(value)[3]:
        return "PbpEncoder.%s(%s)" % (_methods(value)[2], ref)
    return "PbpEncoder.%s()" % _methods(value)[2]


def _diff_expr(field: ResolvedField) -> str:
    """字段与基线是否不同。

    标量与字符串直接比值；嵌套消息、列表、映射、浮点按「同一套 writer 调用写出来的字节」
    比较，与编码语义天然对齐（浮点走字节即按位比较，与 Java 的 Float.compare 等价）。
    """
    value = field.value_type
    if field.is_list or field.is_map or value.kind == "message" or value.name in ("float32", "float64"):
        current = _encode_call(field, "self")
        previous = _encode_call(field, "previous")
        return (f"PbpDelta.differs(lambda e: e.{current}, lambda e: e.{previous})")
    return f"self.{field.name} != previous.{field.name}"


def _copy_expr(field: ResolvedField) -> str:
    """从基线拷贝字段：可变类型深拷贝，避免解码结果与基线互串。"""
    value = field.value_type
    ref = "previous." + field.name
    if field.is_map:
        if value.kind == "message":
            return "{key: PbpDelta.copy(item, %s) for key, item in %s.items()}" % (value.name, ref)
        return "dict(%s)" % ref
    if field.is_list:
        if value.kind == "message":
            return "[PbpDelta.copy(item, %s) for item in %s]" % (value.name, ref)
        return "list(%s)" % ref
    if value.kind == "message":
        return "PbpDelta.copy(%s, %s)" % (ref, value.name)
    if value.name == "bytes" and value.kind == "scalar":
        return "bytes(%s)" % ref
    return ref


# ---------------------------------------------------------------- 运行时核心

_CORE_SOURCE = '''"""PBP 二进制协议运行时核心（Python，仅标准库）。

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
'''