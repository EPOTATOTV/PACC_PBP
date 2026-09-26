"""MDL 语义模型：语法树 → 可生成的中间表示，全部校验也在这里做。

校验清单（每一条都对应设计文档里的约束）：
  * syntax 必须是 pbp1
  * 同一文件内类型名唯一；类型引用必须能解析到本文件已声明的类型或 MDL 标量
  * 消息 ID 唯一、落在允许区间，且不得踩 0x3000-0xEFFF 这段预留区
  * 字段编号唯一、从 1 起、不与 reserved 冲突（编号决定线上顺序，冲突即协议错位）
  * 字段名唯一，且转成 Java 驼峰后仍不得撞名（否则生成的 getter 会重复）
  * `// optional` 只允许加在 string / bytes / 消息类型上（位图 + 值才有意义）
  * map 的键不能是消息类型；map 不能同时是 repeated / optional
  * enum 取值非负且唯一

字段顺序一律按编号升序输出，与 MDL 里的书写顺序无关——编号才是协议的排序依据，
这样 `reserved` 留下空号、或者在中间补一个字段时，线上顺序都不会跟着书写顺序漂移。

末尾字段自动 optional（设计文档 §3.6.2）：带消息 ID 的消息，编号最大的字段解码时
允许"载荷提前读完"，取默认值——旧端没发这个字段就是这种情况。只对整帧消息生效：
嵌套消息内联在父载荷里，"读完了"这个信号不存在，对它做推断只会把父消息的字节吞掉。
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from . import ast
from .lexer import MdlSyntaxError

SUPPORTED_SYNTAX = "pbp1"


@dataclass(frozen=True)
class Scalar:
    name: str
    java: str
    writer: str
    reader: str
    sizer: str
    sizer_takes_value: bool
    nullable: bool
    fixed_width: int | None


SCALARS: dict[str, Scalar] = {
    "bool": Scalar("bool", "boolean", "writeBool", "readBool", "boolSize", False, False, 1),
    "int8": Scalar("int8", "int", "writeInt8", "readInt8", "int8Size", False, False, 1),
    "uint8": Scalar("uint8", "int", "writeUInt8", "readUInt8", "uint8Size", False, False, 1),
    "int16": Scalar("int16", "int", "writeInt16", "readInt16", "int16Size", False, False, 2),
    "uint16": Scalar("uint16", "int", "writeUInt16", "readUInt16", "uint16Size", False, False, 2),
    "int32": Scalar("int32", "int", "writeInt32", "readInt32", "int32Size", True, False, None),
    "uint32": Scalar("uint32", "long", "writeUInt32", "readUInt32", "uint32Size", True, False, None),
    "int64": Scalar("int64", "long", "writeInt64", "readInt64", "int64Size", True, False, None),
    "uint64": Scalar("uint64", "long", "writeUInt64", "readUInt64", "uint64Size", True, False, None),
    "float32": Scalar("float32", "float", "writeFloat32", "readFloat32", "float32Size", False, False, 4),
    "float64": Scalar("float64", "double", "writeFloat64", "readFloat64", "float64Size", False, False, 8),
    "string": Scalar("string", "String", "writeString", "readString", "stringSize", True, True, None),
    "bytes": Scalar("bytes", "byte[]", "writeBytes", "readBytes", "bytesSize", True, True, None),
}

# 消息 ID 区间台账（设计文档 §3.5）。改动前先看这里。
ID_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0000, 0x00FF, "系统"),
    (0x0100, 0x0FFF, "客户端 → 服务端"),
    (0x1000, 0x1FFF, "服务端 → 客户端"),
    (0x2000, 0x2FFF, "双向"),
    (0x3000, 0xEFFF, "预留（禁止使用）"),
    (0xF000, 0xFFFF, "自定义"),
)
RESERVED_ID_MIN, RESERVED_ID_MAX = 0x3000, 0xEFFF


@dataclass(frozen=True)
class ResolvedType:
    """一个已经解析完、可以直接映射到 Java 与编解码调用的类型。"""

    kind: str  # scalar / message / enum
    name: str
    java: str
    writer: str
    reader: str
    sizer: str
    sizer_takes_value: bool
    nullable: bool


@dataclass(frozen=True)
class ResolvedField:
    name: str
    java_name: str
    field_name: str
    number: int
    value_type: ResolvedType
    repeated: bool
    optional: bool
    map_key: "ResolvedType | None"
    line: int
    trailing: bool = False

    @property
    def is_map(self) -> bool:
        return self.map_key is not None

    @property
    def is_list(self) -> bool:
        return self.repeated and not self.is_map


@dataclass(frozen=True)
class Message:
    name: str
    message_id: int | None
    signed: bool
    frame_timestamp_field: "ResolvedField | None"
    fields: tuple[ResolvedField, ...]
    reserved: tuple[int, ...]
    line: int

    @property
    def framed(self) -> bool:
        """声明了消息 ID 的消息才有「整帧」概念：能独立解析、可能有帧尾签名。"""
        return self.message_id is not None

    @property
    def optional_field_count(self) -> int:
        return sum(1 for f in self.fields if f.optional)


@dataclass(frozen=True)
class Enum:
    name: str
    values: tuple[tuple[str, int], ...]
    line: int


@dataclass(frozen=True)
class Schema:
    path: str
    java_package: str
    messages: tuple[Message, ...]
    enums: tuple[Enum, ...]


def id_range_label(message_id: int) -> str:
    for low, high, label in ID_RANGES:
        if low <= message_id <= high:
            return f"0x{low:04X}-0x{high:04X} {label}"
    return "越界"


def build_schema(node: ast.FileNode) -> Schema:
    """校验并收敛一个 .mdl 文件。"""
    errors: list[str] = []

    def fail(line: int, message: str) -> None:
        where = f"{node.path}:{line}" if node.path else f"第 {line} 行"
        errors.append(f"{where}: {message}")

    if node.syntax != SUPPORTED_SYNTAX:
        fail(1, f"syntax 必须是 {SUPPORTED_SYNTAX!r}，实际 {node.syntax!r}")

    java_package = _java_package(node, fail)

    type_names: dict[str, int] = {}
    for message in node.messages:
        if message.name in type_names:
            fail(message.line, f"类型名 {message.name} 重复声明")
        type_names[message.name] = message.line
    for enum in node.enums:
        if enum.name in type_names:
            fail(enum.line, f"类型名 {enum.name} 重复声明")
        type_names[enum.name] = enum.line

    enums = tuple(_build_enum(enum, fail) for enum in node.enums)
    messages = tuple(_build_message(message, node, fail) for message in node.messages)

    seen_ids: dict[int, str] = {}
    for message in messages:
        if message.message_id is None:
            continue
        if message.message_id in seen_ids:
            fail(message.line, f"消息 ID 0x{message.message_id:04X} 已被 {seen_ids[message.message_id]} 占用")
        seen_ids[message.message_id] = message.name

    if errors:
        raise MdlSyntaxError("；".join(errors), 0, node.path)

    return Schema(path=node.path, java_package=java_package, messages=messages, enums=enums)


def _java_package(node: ast.FileNode, fail) -> str:
    option = node.option("java_package")
    package = option.value if option is not None and isinstance(option.value, str) else node.package
    if not package:
        fail(node.messages[0].line if node.messages else 1, "缺少 package 或 option java_package")
        return ""
    if not _is_valid_java_package(package):
        fail(1, f"Java 包名不合法: {package!r}")
    return package


def _is_valid_java_package(package: str) -> bool:
    for part in package.split("."):
        if not part or not (part[0].isalpha() or part[0] == "_"):
            return False
        if not all(ch.isalnum() or ch == "_" for ch in part):
            return False
    return True


def _build_enum(node: ast.EnumNode, fail) -> Enum:
    if not node.values:
        fail(node.line, f"enum {node.name} 没有任何取值")
    names: dict[str, int] = {}
    numbers: dict[int, str] = {}
    for value in node.values:
        label = f"enum {node.name} 的 {value.name}"
        if value.name in names:
            fail(value.line, f"{label} 重复声明")
        if value.number in numbers:
            fail(value.line, f"{label} 取值 {value.number} 与 {numbers[value.number]} 撞车")
        if value.number < 0:
            fail(value.line, f"{label} 取值不能为负")
        names[value.name] = value.number
        numbers[value.number] = value.name
    return Enum(node.name, tuple((v.name, v.number) for v in node.values), node.line)


def _build_message(node: ast.MessageNode, file_node: ast.FileNode, fail) -> Message:
    message_id = node.message_id
    if message_id is not None:
        if message_id < 0 or message_id > 0xFFFF:
            fail(node.line, f"message {node.name} 的消息 ID 0x{message_id:X} 超出 16 位")
        elif RESERVED_ID_MIN <= message_id <= RESERVED_ID_MAX:
            fail(node.line, f"message {node.name} 不能使用预留消息 ID 0x{message_id:04X}")

    kinds = {m.name: "message" for m in file_node.messages}
    kinds.update({e.name: "enum" for e in file_node.enums})
    reserved = set(node.reserved)
    fields: list[ResolvedField] = []
    by_number: dict[int, str] = {}
    by_java_name: dict[str, str] = {}

    for field in node.fields:
        if field.number < 1:
            fail(field.line, f"message {node.name} 的字段 {field.name} 编号必须从 1 起")
        if field.number in reserved:
            fail(field.line, f"message {node.name} 的字段 {field.name} 用了保留编号 {field.number}")
        if field.number in by_number:
            fail(field.line, f"message {node.name} 的字段编号 {field.number} 与 {by_number[field.number]} 撞车")
        by_number[field.number] = field.name

        java_name = _pascal(field.name)
        field_name = java_name[:1].lower() + java_name[1:]
        if java_name in by_java_name:
            fail(field.line, f"message {node.name} 的字段 {field.name} 与 {by_java_name[java_name]} 转成 Java 名后撞车")
        by_java_name[java_name] = field.name

        value_type = _resolve(field.type, kinds, fail)
        map_key = None
        if field.type.map_key is not None:
            map_key = _resolve(field.type.map_key, kinds, fail)
            if map_key.kind == "message":
                fail(field.line, f"map 字段 {field.name} 的键不能是消息类型")
            if field.repeated:
                fail(field.line, f"map 字段 {field.name} 不能同时是 repeated")
            if field.optional:
                fail(field.line, f"map 字段 {field.name} 不能是 optional")
        elif field.optional:
            if not value_type.nullable:
                fail(field.line, f"字段 {field.name} 标了 optional，但类型 {value_type.name} 不支持可空")
            if field.repeated:
                fail(field.line, f"字段 {field.name} 不能同时是 repeated 与 optional")

        fields.append(
            ResolvedField(
                name=field.name,
                java_name=java_name,
                field_name=field_name,
                number=field.number,
                value_type=value_type,
                repeated=field.repeated,
                optional=field.optional,
                map_key=map_key,
                line=field.line,
            )
        )

    fields.sort(key=lambda f: f.number)
    if fields and message_id is not None:
        # 末尾字段自动 optional（设计文档 §3.6.2）：只有"整帧消息"能拿"载荷读完"当缺席信号
        fields[-1] = replace(fields[-1], trailing=True)

    signed = bool(_option_flag(node, "signed", False, fail))
    frame_timestamp_field = None
    if signed:
        if message_id is None:
            fail(node.line, f"message {node.name} 声明了 signed，但没有消息 ID，无法承载帧头")
        named = _option_flag(node, "frame_timestamp", None, fail)
        if not isinstance(named, str):
            fail(node.line, f"message {node.name} 声明了 signed，必须同时用 option frame_timestamp = <字段名> 指定帧头时间戳来源")
        else:
            frame_timestamp_field = next((f for f in fields if f.name == named), None)
            if frame_timestamp_field is None:
                fail(node.line, f"option frame_timestamp 指向的字段 {named} 不存在")
            elif not frame_timestamp_field.is_list and not frame_timestamp_field.is_map:
                if frame_timestamp_field.value_type.java != "long":
                    fail(node.line, f"帧头时间戳字段 {named} 必须是 int64/uint64（毫秒），实际 {frame_timestamp_field.value_type.name}")

    return Message(
        name=node.name,
        message_id=message_id,
        signed=signed,
        frame_timestamp_field=frame_timestamp_field,
        fields=tuple(fields),
        reserved=tuple(sorted(reserved)),
        line=node.line,
    )


def _option_flag(node: ast.MessageNode, name: str, default, fail):
    values = [opt for opt in node.options if opt.name == name]
    if not values:
        return default
    if len(values) > 1:
        fail(values[1].line, f"message {node.name} 的 option {name} 重复声明")
    return values[0].value


def _resolve(ref: ast.TypeRef, kinds: dict[str, str], fail) -> ResolvedType:
    scalar = SCALARS.get(ref.name)
    if scalar is not None:
        return ResolvedType(
            kind="scalar",
            name=scalar.name,
            java=scalar.java,
            writer=scalar.writer,
            reader=scalar.reader,
            sizer=scalar.sizer,
            sizer_takes_value=scalar.sizer_takes_value,
            nullable=scalar.nullable,
        )
    kind = kinds.get(ref.name)
    if kind == "message":
        return ResolvedType(
            kind="message",
            name=ref.name,
            java=ref.name,
            writer="writeMessage",
            reader="readMessage",
            sizer="messageSize",
            sizer_takes_value=True,
            nullable=True,
        )
    if kind == "enum":
        # 枚举在线上是 VarInt 的非负整数，Java 侧用 int 承载，不生成装箱类型。
        return ResolvedType(
            kind="enum",
            name=ref.name,
            java="int",
            writer="writeEnum",
            reader="readEnum",
            sizer="enumSize",
            sizer_takes_value=True,
            nullable=False,
        )
    fail(ref.line, f"未知类型 {ref.name}（MDL 标量，或本文件内已声明的 message/enum）")
    return ResolvedType("scalar", "int32", "int", "writeInt32", "readInt32", "int32Size", True, False)


def _pascal(snake: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in snake.split("_") if part)


def pascal(name: str) -> str:
    """对外暴露给 emit 层复用（enum 名等场景）。"""
    return _pascal(name)