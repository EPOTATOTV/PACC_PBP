"""C# 代码生成。

生成物入库，输出必须逐字节确定：不写生成时间、不依赖字典遍历顺序、字段按编号升序。
返回值结构与 Java emitter 一致（相对源码根的路径 → 文件内容），编排层可以直接复用。

契约与 Java 侧对齐（见 emit/java.py 的说明）：
  * 字段按编号升序编码，`// optional` 走存在位图，末尾字段只对带消息 ID 的消息取默认值；
  * 帧装配走运行时的 PbpCodec（自动压缩），生成代码不重复实现压缩策略；
  * 差分方法只发给「带消息 ID 且不 signed」的消息。

C# 与该仓库 Java 生成物的差异只在语言习惯上：类成员用 PascalCase、字段读取用属性、
集合 getter 返回只读视图。这些不影响线上字节，编解码调用与 Java 一一对应。
"""

from __future__ import annotations

from ..model import Enum, Message, ResolvedField, ResolvedType, Schema, id_range_label

_GENERATOR_NOTE = "本文件由 tools/pbpgen 生成，请勿手改。"

# MDL 标量名 → C# 类型。uint32/uint64 直接用无符号类型，其余窄整数统一 int。
_SCALAR_TYPES = {
    "bool": "bool",
    "int8": "int",
    "uint8": "int",
    "int16": "int",
    "uint16": "int",
    "int32": "int",
    "uint32": "uint",
    "int64": "long",
    "uint64": "ulong",
    "float32": "float",
    "float64": "double",
    "string": "string",
    "bytes": "byte[]",
}

_DEFAULTS = {
    "bool": "false",
    "int": "0",
    "uint": "0u",
    "long": "0L",
    "ulong": "0UL",
    "float": "0.0f",
    "double": "0.0d",
    "string": '""',
    "byte[]": "new byte[0]",
}

# 值类型默认值：不显式初始化、留字段声明的隐式零值。
_VALUE_TYPES = frozenset({"bool", "int", "uint", "long", "ulong", "float", "double"})


def _delta_capable(message: Message) -> bool:
    """是否生成差分方法：带 signed 的消息不发（签名与基线是两套状态，混用的失败面太大）。"""
    return message.framed and not message.signed


def _pascal(name: str) -> str:
    return name[:1].upper() + name[1:]


def _is_ref_type(value: ResolvedType) -> bool:
    """C# 引用类型：string / bytes / 嵌套消息；其余标量与枚举都是值类型。"""
    return value.kind == "message" or value.name in ("string", "bytes")


def _scalar_type(value: ResolvedType) -> str:
    return _SCALAR_TYPES[value.name]


def emit_schema(schema: Schema, mdl_rel: str) -> dict[str, str]:
    """返回 {相对 C# 源码根的路径: 文件内容}。"""
    files: dict[str, str] = {}
    for enum in schema.enums:
        files[f"Gen/{enum.name}.cs"] = _emit_enum(enum, mdl_rel)
    for message in schema.messages:
        files[f"Gen/{message.name}.cs"] = _emit_message(message, mdl_rel)
    return files


# ---------------------------------------------------------------- 枚举


def _emit_enum(enum: Enum, mdl_rel: str) -> str:
    lines = [
        f"// {_GENERATOR_NOTE}",
        f"// 源定义：{mdl_rel}",
        "// 重新生成：cd tools/pbpgen && python -m pbpgen",
        "",
        "namespace Potatotv.Pbp.Gen;",
        "",
        f"/// <summary>MDL 枚举 {enum.name}。枚举在线上是 VarInt 编码的非负整数，所以生成常量而不是 enum。</summary>",
        f"public static class {enum.name}",
        "{",
    ]
    for name, number in enum.values:
        lines.append(f"    public const int {name} = {number};")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- 消息


class _Emitter:
    def __init__(self, message: Message):
        self.message = message
        self.lines: list[str] = []

    def add(self, text: str = "", indent: int = 1) -> None:
        self.lines.append(("    " * indent + text) if text else "")

    # ------------------------------------------------------------ 类型

    def field_type(self, field: ResolvedField) -> str:
        if field.is_list:
            return f"List<{self.value_type_name(field.value_type)}>"
        if field.is_map:
            return (f"Dictionary<{self.value_type_name(field.map_key)}, "
                    f"{self.value_type_name(field.value_type)}>")
        return self.decl_type(field)

    def value_type_name(self, value: ResolvedType) -> str:
        if value.kind == "message":
            return value.name
        if value.kind == "enum":
            return "int"
        return _scalar_type(value)

    def decl_type(self, field: ResolvedField) -> str:
        """非集合字段的声明类型：可空字段带 `?`。"""
        type_name = self.value_type_name(field.value_type)
        if field.value_type.kind == "message" or field.optional:
            return type_name + "?"
        return type_name

    def default_expr(self, field: ResolvedField) -> str:
        if field.is_list:
            return f"new List<{self.value_type_name(field.value_type)}>()"
        if field.is_map:
            return (f"new Dictionary<{self.value_type_name(field.map_key)}, "
                    f"{self.value_type_name(field.value_type)}>()")
        if field.value_type.kind == "message" or field.optional:
            return "null"
        return _DEFAULTS[self.value_type_name(field.value_type)]

    def setter_expr(self, field: ResolvedField) -> str:
        if field.is_list:
            element = self.value_type_name(field.value_type)
            return f"value == null ? new List<{element}>() : new List<{element}>(value)"
        if field.is_map:
            key = self.value_type_name(field.map_key)
            value = self.value_type_name(field.value_type)
            return f"value == null ? new Dictionary<{key}, {value}>() : new Dictionary<{key}, {value}>(value)"
        type_name = self.value_type_name(field.value_type)
        if type_name == "byte[]":
            return "value == null ? new byte[0] : (byte[])value.Clone()"
        if type_name == "string" and not field.optional and field.value_type.kind != "message":
            return 'value ?? ""'
        return "value"

    def setter_param_type(self, field: ResolvedField) -> str:
        if field.is_list or field.is_map:
            return self.field_type(field) + "?"
        base = self.value_type_name(field.value_type)
        return base + "?" if self._nullable_setter(field) else base

    def _nullable_setter(self, field: ResolvedField) -> bool:
        if field.is_list or field.is_map:
            return True
        return field.value_type.kind == "message" or field.optional

    # ------------------------------------------------------------ 类体

    def emit(self) -> list[str]:
        message = self.message
        interfaces = "IPbpMessage"
        if _delta_capable(message):
            interfaces += f", IPbpDeltaMessage<{message.name}>"
        self.add("/// <summary>", 0)
        if message.framed:
            self.add(f"/// PBP 消息 {message.name}（0x{message.message_id:04X}，"
                     f"{id_range_label(message.message_id)}）。", 0)
        else:
            self.add(f"/// PBP 消息 {message.name}，无消息 ID，仅作为嵌套类型内联在父消息载荷里。", 0)
        self.add("///", 0)
        self.add("/// <p>字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；", 0)
        self.add("/// 新字段只能追加在末尾，否则两侧解析会整体错位。</p>", 0)
        self.add("/// </summary>", 0)
        self.add(f"public sealed class {message.name} : {interfaces}", 0)
        self.add("{", 0)

        if message.framed:
            self.add("/// <summary>MDL 里声明的消息 ID。</summary>")
            self.add(f"public const int MessageId = 0x{message.message_id:04X};")
            self.add("")
        if message.optional_field_count:
            self.add("/// <summary>可空字段个数，用于定位载荷里的存在性位图。</summary>")
            self.add(f"public const int OptionalFieldCount = {message.optional_field_count};")
            self.add("")

        self._fields()
        self._builder()
        self._getters()
        if message.framed:
            self._frame()
        self._core_methods()
        self._delta_methods()

        self.add("}", 0)
        self.add("", 0)
        return self.lines

    def _fields(self) -> None:
        message = self.message
        self.add("// ------------------------------------------------------------ 字段")
        self.add("")
        for field in message.fields:
            init = "" if (not field.is_list and not field.is_map
                          and self.value_type_name(field.value_type) in _VALUE_TYPES) \
                else f" = {self.default_expr(field)}"
            self.add(f"private {self.field_type(field)} {field.field_name}{init};")
            self.add("")
        if message.signed:
            self.add("// 帧尾签名，载荷里没有这个字段")
            self.add("private byte[] signature = new byte[0];")
            self.add("")
        self.add("/// <summary>解析路径用它建空对象，字段默认值见声明处。</summary>")
        # internal 而不是 public：被嵌套引用时父消息里的 `new Child()` 需要拿到它
        self.add(f"internal {message.name}()")
        self.add("{")
        self.add("}")
        self.add("")

    def _builder(self) -> None:
        message = self.message
        self.add("/// <summary>字段构造器；可空性由 MDL 决定。</summary>")
        self.add("public sealed class Builder")
        self.add("{")
        for field in message.fields:
            self.add(f"private {self.field_type(field)} {field.field_name} = {self.default_expr(field)};", 2)
            self.add("", 0)
        if message.signed:
            self.add("private byte[] signature = new byte[0];", 2)
            self.add("", 0)
        # internal 而不是 private：外层类的 NewBuilder/ToBuilder 需要能构造它
        self.add("internal Builder()", 2)
        self.add("{", 2)
        self.add("}", 2)
        self.add("", 0)

        for field in message.fields:
            self.add(f"/// <summary>MDL 字段 {field.number} {field.name}。</summary>", 2)
            self.add(f"public Builder Set{field.java_name}({self.setter_param_type(field)} value)", 2)
            self.add("{", 2)
            self.add(f"{field.field_name} = {self.setter_expr(field)};", 3)
            self.add("return this;", 3)
            self.add("}", 2)
            self.add("", 0)
            if field.is_list:
                element = self.value_type_name(field.value_type)
                self.add(f"/// <summary>追加一个 {field.name} 元素。</summary>", 2)
                self.add(f"public Builder Add{field.java_name}({element} value)", 2)
                self.add("{", 2)
                self.add(f"{field.field_name}.Add(value);", 3)
                self.add("return this;", 3)
                self.add("}", 2)
                self.add("", 0)
            if field.is_map:
                key = self.value_type_name(field.map_key)
                value = self.value_type_name(field.value_type)
                self.add(f"/// <summary>写入一个 {field.name} 键值对。</summary>", 2)
                if _is_ref_type(field.value_type):
                    self.add(f"public Builder Put{field.java_name}({key} key, {value}? value)", 2)
                    assign = f"{field.field_name}[key] = value!;"
                else:
                    self.add(f"public Builder Put{field.java_name}({key} key, {value} value)", 2)
                    assign = f"{field.field_name}[key] = value;"
                self.add("{", 2)
                self.add(assign, 3)
                self.add("return this;", 3)
                self.add("}", 2)
                self.add("", 0)

        if message.signed:
            self.add("/// <summary>帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。</summary>", 2)
            self.add("public Builder SetSignature(string hex)", 2)
            self.add("{", 2)
            self.add("signature = SignatureFromHex(hex);", 3)
            self.add("return this;", 3)
            self.add("}", 2)
            self.add("", 0)
            self.add("/// <summary>帧尾签名的原始字节；null 视为不签名。</summary>", 2)
            self.add("public Builder SetSignatureBytes(byte[]? value)", 2)
            self.add("{", 2)
            self.add("signature = value == null ? new byte[0] : (byte[])value.Clone();", 3)
            self.add("return this;", 3)
            self.add("}", 2)
            self.add("", 0)

        self.add(f"public {message.name} Build()", 2)
        self.add("{", 2)
        self.add(f"{message.name} msg = new {message.name}();", 3)
        for field in message.fields:
            if field.is_list:
                element = self.value_type_name(field.value_type)
                self.add(f"msg.{field.field_name} = new List<{element}>({field.field_name});", 3)
            elif field.is_map:
                key = self.value_type_name(field.map_key)
                value = self.value_type_name(field.value_type)
                self.add(f"msg.{field.field_name} = new Dictionary<{key}, {value}>({field.field_name});", 3)
            elif self.value_type_name(field.value_type) == "byte[]":
                self.add(f"msg.{field.field_name} = (byte[]){field.field_name}.Clone();", 3)
            else:
                self.add(f"msg.{field.field_name} = {field.field_name};", 3)
        if message.signed:
            self.add("msg.signature = (byte[])signature.Clone();", 3)
        self.add("return msg;", 3)
        self.add("}", 2)
        self.add("}")
        self.add("")

        self.add(f"public static Builder NewBuilder() => new Builder();")
        self.add("")

        self.add("/// <summary>以当前值为初值开一个新 Builder（例如改完字段要重新签名）。</summary>")
        self.add("public Builder ToBuilder()")
        self.add("{")
        calls = [f"Set{field.java_name}({field.field_name})" for field in message.fields]
        if message.signed:
            calls.append("SetSignatureBytes(signature)")
        if not calls:
            self.add("return NewBuilder();", 2)
        else:
            self.add("return NewBuilder()", 2)
            for call in calls:
                self.add(f".{call}", 3)
            self.add(";", 3)
        self.add("}")
        self.add("")

    def _getters(self) -> None:
        self.add("// ------------------------------------------------------------ 字段读取")
        self.add("")
        for field in self.message.fields:
            self.add(f"/// <summary>MDL 字段 {field.number} {field.name}。</summary>")
            type_name = self.field_type(field)
            if field.is_list:
                element = self.value_type_name(field.value_type)
                self.add(f"public IReadOnlyList<{element}> {field.java_name} => {field.field_name};")
            elif field.is_map:
                key = self.value_type_name(field.map_key)
                value = self.value_type_name(field.value_type)
                self.add(f"public IReadOnlyDictionary<{key}, {value}> {field.java_name} => {field.field_name};")
            elif type_name == "byte[]":
                if field.optional:
                    self.add(f"public byte[]? {field.java_name} => "
                             f"{field.field_name} == null ? null : (byte[]){field.field_name}.Clone();")
                else:
                    self.add(f"public byte[] {field.java_name} => (byte[]){field.field_name}.Clone();")
            else:
                self.add(f"public {self.decl_type(field)} {field.java_name} => {field.field_name};")
            self.add("")

    def _frame(self) -> None:
        message = self.message
        frame_ts = message.frame_timestamp_field.field_name if message.frame_timestamp_field else "0L"

        self.add("// ------------------------------------------------------------ 帧")
        self.add("")
        if message.signed:
            self.add("/// <summary>编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。</summary>")
        else:
            self.add("/// <summary>编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。</summary>")
        self.add("public byte[] ToByteArray()")
        self.add("{")
        self.add(f"PbpFrame frame = PbpCodec.FrameOf(this, {frame_ts});", 2)
        if message.signed:
            self.add("if (signature.Length == PbpFrame.SignatureSize)", 2)
            self.add("{", 2)
            self.add("frame = frame.WithSignature(signature);", 3)
            self.add("}", 2)
            self.add("else if (signature.Length != 0)", 2)
            self.add("{", 2)
            self.add("throw new PbpException(PbpErrorCode.BadLength,", 3)
            self.add('"签名长度必须是 0 或 " + PbpFrame.SignatureSize + "，实际 " + signature.Length);', 4)
            self.add("}", 2)
        self.add("return frame.Encode();", 2)
        self.add("}")
        self.add("")

        if message.signed:
            self.add("/// <summary>HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。</summary>")
            self.add("public byte[] SigningInput() =>")
            self.add(f"PbpCodec.FrameOf(this, {frame_ts}).SigningInput();")
            self.add("")

        self.add("/// <summary>解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。</summary>")
        self.add(f"public static {message.name} ParseFrom(byte[] raw)")
        self.add("{")
        self.add("PbpFrame frame = PbpFrame.Parse(raw);", 2)
        self.add("if (frame.MessageId != MessageId)", 2)
        self.add("{", 2)
        self.add("throw new PbpException(PbpErrorCode.BadFormat,", 3)
        self.add('"消息 ID 不符：期望 0x" + MessageId.ToString("x")', 4)
        self.add('+ "，实际 0x" + frame.MessageId.ToString("x"));', 4)
        self.add("}", 2)
        self.add(f"{message.name} msg = new {message.name}();", 2)
        self.add("msg.Decode(new PbpDecoder(PbpCodec.PayloadOf(frame)));", 2)
        if message.signed:
            self.add("msg.signature = frame.Signature;", 2)
        self.add("return msg;", 2)
        self.add("}")
        self.add("")

        if not message.signed:
            return

        self.add("// ------------------------------------------------------------ 签名")
        self.add("")
        self.add("/// <summary>帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。</summary>")
        self.add("public string SignatureHex =>")
        self.add('signature.Length == 0 ? "" : Convert.ToHexString(signature).ToLowerInvariant();')
        self.add("")
        self.add("/// <summary>帧尾签名的副本；未签名返回零长数组。</summary>")
        self.add("public byte[] SignatureBytes => (byte[])signature.Clone();")
        self.add("")
        self.add("private static byte[] SignatureFromHex(string hex)")
        self.add("{")
        self.add("if (string.IsNullOrEmpty(hex))", 2)
        self.add("{", 2)
        self.add("return new byte[0];", 3)
        self.add("}", 2)
        self.add("return Convert.FromHexString(hex);", 2)
        self.add("}")
        self.add("")

    def _core_methods(self) -> None:
        message = self.message
        self.add("// ------------------------------------------------------------ IPbpMessage")
        self.add("")
        self.add("/// <inheritdoc/>")
        self.add("public int GetMessageId() => " + ("MessageId;" if message.framed else "0;"))
        self.add("")

        self.add("/// <inheritdoc/>")
        self.add("public void Encode(PbpEncoder enc)")
        self.add("{")
        for field in message.fields:
            self.add(f"enc.{_encode_call(field)};", 2)
        self.add("}")
        self.add("")

        self.add("/// <summary>按定义顺序读回字段；末尾字段在载荷提前读完时取默认值。</summary>")
        self.add("/// <inheritdoc/>")
        self.add("public void Decode(PbpDecoder dec)")
        self.add("{")
        for field in message.fields:
            if field.trailing:
                self.add("// 末尾字段自动 optional：旧端的载荷在这里已经读完", 2)
                self.add(f"{field.field_name} = dec.Remaining > 0", 2)
                self.add(f"? {_decode_expr(field)}", 3)
                self.add(f": {self.default_expr(field)};", 3)
            else:
                self.add(f"{field.field_name} = {_decode_expr(field)};", 2)
        self.add("}")
        self.add("")

        self.add("/// <summary>编码后的字节数，仅用于预分配缓冲区。</summary>")
        self.add("/// <inheritdoc/>")
        self.add("public int EncodedSize()")
        self.add("{")
        self.add("int size = 0;", 2)
        for field in message.fields:
            self.add(f"size += {_size_expr(field)};", 2)
        self.add("return size;", 2)
        self.add("}")
        self.add("")

    def _delta_methods(self) -> None:
        message = self.message
        if not _delta_capable(message):
            return
        self.add("// ------------------------------------------------------------ 差分")
        self.add("")
        self.add("/// <summary>相对基线只写变化的字段：存在位图 + 按字段序的变化值。</summary>")
        self.add("/// <inheritdoc/>")
        self.add(f"public void EncodeDelta(PbpEncoder enc, {message.name} previous)")
        self.add("{")
        self.add("bool[] changed =", 2)
        self.add("{", 2)
        for field in message.fields:
            self.add(_diff_expr(field) + ",", 3)
        self.add("};", 2)
        self.add("enc.WritePresence(changed);", 2)
        for index, field in enumerate(message.fields):
            self.add(f"if (changed[{index}])", 2)
            self.add("{", 2)
            self.add(f"enc.{_encode_call(field)};", 3)
            self.add("}", 2)
        self.add("}")
        self.add("")
        self.add("/// <summary>未变化的字段从基线拷贝，变化的字段按位图读入；基线对象不会被改动。</summary>")
        self.add("/// <inheritdoc/>")
        self.add(f"public void ApplyDelta(PbpDecoder dec, {message.name} previous)")
        self.add("{")
        self.add(f"bool[] present = dec.ReadPresence({len(message.fields)});", 2)
        for index, field in enumerate(message.fields):
            self.add(f"{field.field_name} = present[{index}]", 2)
            self.add(f"? {_decode_expr(field)}", 3)
            self.add(f": {_copy_expr(field)};", 3)
        self.add("}")
        self.add("")


def _emit_message(message: Message, mdl_rel: str) -> str:
    head = [
        f"// {_GENERATOR_NOTE}",
        f"// 源定义：{mdl_rel}",
        "// 重新生成：cd tools/pbpgen && python -m pbpgen",
        "",
        "using System;",
        "using System.Collections.Generic;",
        "",
        "namespace Potatotv.Pbp.Gen;",
        "",
    ]
    return "\n".join(head + _Emitter(message).emit())


# ---------------------------------------------------------------- 表达式


def _writer_call(value: ResolvedType) -> str:
    """标量/枚举/消息在 C# 编码器上的方法名（PascalCase）。"""
    return _pascal(value.writer)


def _reader_call(value: ResolvedType) -> str:
    return _pascal(value.reader)


def _sizer_call(value: ResolvedType) -> str:
    return _pascal(value.sizer)


def _value_lambda(value: ResolvedType) -> str:
    return f"static (e, v) => e.{_writer_call(value)}(v)"


def _key_lambda(value: ResolvedType) -> str:
    return f"static (e, k) => e.{_writer_call(value)}(k)"


def _element_sizer(value: ResolvedType) -> str:
    if value.sizer_takes_value:
        return f"static v => PbpEncoder.{_sizer_call(value)}(v)"
    return f"static v => PbpEncoder.{_sizer_call(value)}()"


def _encode_call(field: ResolvedField, prefix: str = "") -> str:
    value = field.value_type
    name = f"{prefix}{field.field_name}"
    if field.is_map:
        if field.map_key.name == "string":
            return f"WriteStringMap({name}, {_value_lambda(value)})"
        return f"WriteMap({name}, {_key_lambda(field.map_key)}, {_value_lambda(value)})"
    if field.is_list:
        if value.kind == "message":
            return f"WriteMessageList({name})"
        if value.name == "string":
            return f"WriteStringList({name})"
        return f"WriteList({name}, {_value_lambda(value)})"
    if field.optional:
        if value.kind == "message":
            return f"WriteOptionalMessage({name})"
        if value.name == "string":
            return f"WriteOptionalString({name})"
        return f"WriteOptionalBytes({name})"
    if value.kind == "message":
        return f"WriteMessage({name})"
    return f"{_writer_call(value)}({name})"


def _decode_expr(field: ResolvedField) -> str:
    value = field.value_type
    if field.is_map:
        if field.map_key.name == "string":
            if value.kind == "message":
                return f"dec.ReadStringMap(static d => d.ReadMessage(() => new {value.name}()))"
            return f"dec.ReadStringMap(static d => d.{_reader_call(value)}())"
        key_reader = f"static d => d.{_reader_call(field.map_key)}()"
        if value.kind == "message":
            return f"dec.ReadMap({key_reader}, static d => d.ReadMessage(() => new {value.name}()))"
        return f"dec.ReadMap({key_reader}, static d => d.{_reader_call(value)}())"
    if field.is_list:
        if value.kind == "message":
            return f"dec.ReadMessageList(() => new {value.name}())"
        if value.name == "string":
            return "dec.ReadStringList()"
        return f"dec.ReadList(static d => d.{_reader_call(value)}())"
    if field.optional:
        if value.kind == "message":
            return f"dec.ReadOptionalMessage(() => new {value.name}())"
        if value.name == "string":
            return "dec.ReadOptionalString()"
        return "dec.ReadOptionalBytes()"
    if value.kind == "message":
        return f"dec.ReadMessage(() => new {value.name}())"
    return f"dec.{_reader_call(value)}()"


def _size_expr(field: ResolvedField) -> str:
    value = field.value_type
    name = field.field_name
    if field.is_map:
        if field.map_key.name == "string":
            return f"PbpEncoder.StringMapSize({name}, {_element_sizer(value)})"
        return (f"PbpEncoder.MapSize({name}, {_element_sizer(field.map_key)}, "
                f"{_element_sizer(value)})")
    if field.is_list:
        if value.kind == "message":
            return f"PbpEncoder.MessageListSize({name})"
        if value.name == "string":
            return f"PbpEncoder.StringListSize({name})"
        return f"PbpEncoder.ListSize({name}, {_element_sizer(value)})"
    if field.optional:
        if value.kind == "message":
            return f"PbpEncoder.OptionalMessageSize({name})"
        if value.name == "string":
            return f"PbpEncoder.OptionalStringSize({name})"
        return f"PbpEncoder.OptionalBytesSize({name})"
    if value.kind == "message":
        return f"PbpEncoder.MessageSize({name})"
    if value.sizer_takes_value:
        return f"PbpEncoder.{_sizer_call(value)}({name})"
    return f"PbpEncoder.{_sizer_call(value)}()"


def _diff_expr(field: ResolvedField) -> str:
    value = field.value_type
    name = field.field_name
    previous = f"previous.{field.field_name}"
    if field.is_list or field.is_map or value.kind == "message":
        return (f"PbpDelta.Differs(x => x.{_encode_call(field)}, "
                f"x => x.{_encode_call(field, 'previous.')})")
    if value.name == "string":
        return f"!string.Equals({name}, {previous}, StringComparison.Ordinal)"
    if value.name == "bytes":
        return f"!PbpDelta.BytesEqual({name}, {previous})"
    if value.java == "float":
        return f"BitConverter.SingleToInt32Bits({name}) != BitConverter.SingleToInt32Bits({previous})"
    if value.java == "double":
        return f"BitConverter.DoubleToInt64Bits({name}) != BitConverter.DoubleToInt64Bits({previous})"
    return f"{name} != {previous}"


def _copy_expr(field: ResolvedField) -> str:
    value = field.value_type
    previous = f"previous.{field.field_name}"
    if field.is_map:
        if value.kind == "message":
            return f"PbpDelta.CopyMap({previous}, () => new {value.name}())"
        key = _SCALAR_TYPES.get(field.map_key.name, field.map_key.name)
        value_type = _SCALAR_TYPES.get(value.name, value.name)
        return f"new Dictionary<{key}, {value_type}>({previous})"
    if field.is_list:
        if value.kind == "message":
            return f"PbpDelta.CopyList({previous}, () => new {value.name}())"
        element = _SCALAR_TYPES.get(value.name, value.name)
        return f"new List<{element}>({previous})"
    if value.kind == "message":
        return f"PbpDelta.Copy({previous}, () => new {value.name}())"
    if value.name == "bytes":
        return f"(byte[]){previous}.Clone()"
    return previous