"""Rust 代码生成。

生成物入库（设计文档 §3.7 要求生成结果进版本库，便于 review 与 diff），所以输出必须
逐字节确定：不写生成时间、不依赖字典遍历顺序、字段按编号升序排列、类型按名字排序。

输出根是 runtime-rust 的源码根（`pacc-binary-protocol/runtime-rust/src`），键形如
`gen/PaccEnvelope.rs`、`gen/mod.rs`；调用方（编排层）负责把返回值写到该根目录下。

契约与 Java 侧对齐：末尾字段自动 optional（只对带消息 ID 的消息）、带 ID 且不 signed
的消息发 `encode_delta/apply_delta`、帧装配走运行时的 [`crate::codec`] 自动压缩、
枚举生成常量。Rust 侧的字段类型：标量映射到等宽整型，消息字段一律 `Option<T>`
（默认值对齐 Java 的 null），集合用 `Vec`、映射用 `Vec<(K, V)>`（保留线上顺序）。
"""

from __future__ import annotations

from ..model import Enum, Message, ResolvedField, ResolvedType, Schema, id_range_label

_GENERATOR_NOTE = "本文件由 tools/pbpgen 生成，请勿手改。"
_REGENERATE = "重新生成：cd tools/pbpgen && python -m pbpgen"

# MDL 标量 → (Rust 类型, 写入方法, 读取方法, size 方法, size 是否取值)
_SCALARS: dict[str, tuple[str, str, str, str, bool]] = {
    "bool": ("bool", "write_bool", "read_bool", "bool_size", False),
    "int8": ("i8", "write_int8", "read_int8", "int8_size", False),
    "uint8": ("u8", "write_uint8", "read_uint8", "uint8_size", False),
    "int16": ("i16", "write_int16", "read_int16", "int16_size", False),
    "uint16": ("u16", "write_uint16", "read_uint16", "uint16_size", False),
    "int32": ("i32", "write_int32", "read_int32", "int32_size", True),
    "uint32": ("u32", "write_uint32", "read_uint32", "uint32_size", True),
    "int64": ("i64", "write_int64", "read_int64", "int64_size", True),
    "uint64": ("u64", "write_uint64", "read_uint64", "uint64_size", True),
    "float32": ("f32", "write_float32", "read_float32", "float32_size", False),
    "float64": ("f64", "write_float64", "read_float64", "float64_size", False),
    "string": ("String", "write_string", "read_string", "string_size", True),
    "bytes": ("Vec<u8>", "write_bytes", "read_bytes", "bytes_size", True),
}

# Rust 关键字不能做标识符；同名 MDL 字段加下划线后缀避开（如 `type` → `type_`）。
_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "union",
})


def _delta_capable(message: Message) -> bool:
    """是否生成差分方法：带 signed 选项的消息不发（签名与基线是两套状态）。"""
    return message.framed and not message.signed


def _snake(name: str) -> str:
    out: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and (
            not name[i - 1].isupper() or (i + 1 < len(name) and name[i + 1].islower())
        ):
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _ident(name: str) -> str:
    return name + "_" if name in _KEYWORDS else name


def emit_schema(schema: Schema, mdl_rel: str) -> dict[str, str]:
    """返回 {相对 Rust 源码根的路径: 文件内容}（单 schema 视图）。

    含该 schema 的全部类型模块，外加只导出本 schema 类型的 `gen/mod.rs`。
    多个 MDL 共享同一输出目录时应改用 [`emit_package`]，否则 `gen/mod.rs` 会被互相覆盖。
    """
    files: dict[str, str] = {}
    types = sorted(
        [(m.name, m) for m in schema.messages] + [(e.name, e) for e in schema.enums],
        key=lambda item: item[0],
    )
    names: list[str] = []
    for name, node in types:
        if isinstance(node, Enum):
            files[f"gen/{name}.rs"] = _emit_enum(node, mdl_rel)
        else:
            files[f"gen/{name}.rs"] = _emit_message(schema, node, mdl_rel)
        names.append(name)
    files["gen/mod.rs"] = _emit_mod(names, mdl_rel)
    return files


def emit_package(schemas: list[Schema]) -> dict[str, str]:
    """多 MDL 聚合成一个 Rust 模块：每个类型仍各一个 `gen/<Type>.rs`，`gen/mod.rs` 只出一份。

    路径与 [`emit_schema`] 一致，直接写进 `pacc-binary-protocol/runtime-rust/src` 即可。
    `gen/mod.rs` 的 header 源定义是多文件花括号列表（按 schema.path 排序，稳定不随入参顺序漂移）。
    """
    files: dict[str, str] = {}
    names: list[str] = []
    for schema in schemas:
        for enum in schema.enums:
            files[f"gen/{enum.name}.rs"] = _emit_enum(enum, schema.path)
            names.append(enum.name)
        for message in schema.messages:
            files[f"gen/{message.name}.rs"] = _emit_message(schema, message, schema.path)
            names.append(message.name)
    files["gen/mod.rs"] = _emit_mod(sorted(set(names)), _mdl_list([schema.path for schema in schemas]))
    return files


def _header(mdl_rel: str) -> list[str]:
    return [
        f"// {_GENERATOR_NOTE}",
        f"// 源定义：{mdl_rel}",
        f"// {_REGENERATE}",
        "",
    ]


def _mdl_list(paths: list[str]) -> str:
    """把多个 MDL 相对路径折成「公共目录 + 花括号文件名列表」，单文件时原样返回。

    按 schema.path 排序，保证同一组 MDL 无论入参顺序如何都得到同一串 header。
    """
    ordered = sorted(set(paths))
    if len(ordered) == 1:
        return ordered[0]
    dirs = [p.rsplit("/", 1)[0] if "/" in p else "" for p in ordered]
    bases = [p.rsplit("/", 1)[1] if "/" in p else p for p in ordered]
    if len(set(dirs)) == 1 and dirs[0]:
        return f"{dirs[0]}/{{{', '.join(bases)}}}"
    return "、".join(ordered)


def _emit_mod(names: list[str], mdl_rel: str) -> str:
    lines = _header(mdl_rel)
    for name in names:
        lines.append(f'#[path = "{name}.rs"]')
        lines.append(f"pub mod {_snake(name)};")
        lines.append(f"pub use {_snake(name)}::{name};")
        lines.append("")
    return "\n".join(lines)


def _emit_enum(enum: Enum, mdl_rel: str) -> str:
    lines = _header(mdl_rel)
    lines.append("/// MDL 枚举。枚举在线上是 VarInt 编码的非负整数，所以生成的是常量而不是 Rust enum：")
    lines.append("/// 编解码两侧统一按 `u32` 传递，省掉一层 value ↔ 常量的来回转换。")
    for name, number in enum.values:
        lines.append("")
        lines.append(f"pub const {_ident(name).upper()}: u32 = {number};")
    lines.append("")
    return "\n".join(lines)


def _emit_message(schema: Schema, message: Message, mdl_rel: str) -> str:
    lines = _header(mdl_rel)
    lines.extend(_imports(message))
    lines.append("")
    lines.append("/// " + _summary(message))
    lines.append("///")
    lines.append("/// 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；")
    lines.append("/// 新字段只能追加在末尾，否则两侧解析会整体错位。")
    if message.signed:
        lines.append("///")
        lines.append("/// 签名不在载荷里：置位帧头 `FLAG_SIGNED`，32 字节 HMAC-SHA256 放在帧尾，")
        lines.append("/// 覆盖面是「帧头 + 载荷」整串字节（见 `signing_input`）。")
    if _delta_capable(message):
        lines.append("///")
        lines.append("/// 实现了 [`crate::delta::PbpDeltaMessage`]：可经 [`crate::delta::PbpDeltaChain`] 发差分帧。")
    lines.append("#[derive(Debug, Clone, Default, PartialEq)]")
    lines.append(f"pub struct {message.name} {{")
    for field in message.fields:
        lines.append(f"    /// MDL 字段 {field.number} `{field.name}`。")
        lines.append(f"    pub {_ident(field.name)}: {_rust_type(field)},")
    if message.signed:
        lines.append("")
        lines.append("    /// 帧尾签名，载荷里没有这个字段。")
        lines.append("    pub signature: Vec<u8>,")
    lines.append("}")
    lines.append("")

    lines.extend(_inherent_impl(schema, message))
    lines.append("")
    lines.extend(_message_impl(message))
    if _delta_capable(message):
        lines.append("")
        lines.extend(_delta_impl(message))
    helpers = _list_size_helpers(message)
    if helpers:
        lines.append("")
        lines.extend(helpers)
    return "\n".join(lines)


def _summary(message: Message) -> str:
    if message.framed:
        return (f"PBP 消息 `{message.name}`（`0x{message.message_id:04X}`，"
                f"{id_range_label(message.message_id)}）。")
    return f"PBP 消息 `{message.name}`，无消息 ID，仅作为嵌套类型内联在父消息载荷里。"


def _imports(message: Message) -> list[str]:
    imports = {
        "use crate::decoder::PbpDecoder;",
        "use crate::encoder::PbpEncoder;",
        "use crate::error::Result;",
        "use crate::message::PbpMessage;",
    }
    if message.framed:
        imports.add("use crate::error::PbpError;")
        imports.add("use crate::codec::PbpCodec;")
        imports.add("use crate::frame::PbpFrame;")
    if _delta_capable(message):
        imports.add("use crate::delta::PbpDeltaMessage;")
        if any(f.is_list or f.is_map or f.value_type.kind == "message" for f in message.fields):
            imports.add("use crate::delta::PbpDelta;")
    for field in message.fields:
        if field.value_type.kind == "message" and field.value_type.name != message.name:
            imports.add(f"use crate::gen::{field.value_type.name};")
    return sorted(imports)


# ---------------------------------------------------------------- 类型与默认值


def _rust_type(field: ResolvedField) -> str:
    if field.is_map:
        assert field.map_key is not None
        return f"Vec<({_value_rust(field.map_key)}, {_value_rust(field.value_type)})>"
    if field.is_list:
        return f"Vec<{_value_rust(field.value_type)}>"
    if field.optional or field.value_type.kind == "message":
        return f"Option<{_value_rust(field.value_type)}>"
    return _value_rust(field.value_type)


def _value_rust(value_type: ResolvedType) -> str:
    if value_type.kind == "message":
        return value_type.name
    if value_type.kind == "enum":
        return "u32"
    return _SCALARS[value_type.name][0]


def _default_expr(field: ResolvedField) -> str:
    if field.is_list or field.is_map:
        return "Vec::new()"
    if field.optional or field.value_type.kind == "message":
        return "None"
    return _scalar_default(field.value_type)


def _scalar_default(value_type: ResolvedType) -> str:
    if value_type.kind == "enum":
        return "0"
    rust = _SCALARS[value_type.name][0]
    if rust == "bool":
        return "false"
    if rust == "String":
        return "String::new()"
    if rust == "Vec<u8>":
        return "Vec::new()"
    if rust.startswith("f"):
        return "0.0"
    return "0"


def _is_copy(value_type: ResolvedType) -> bool:
    if value_type.kind == "enum":
        return True
    rust = _SCALARS[value_type.name][0]
    return rust not in ("String", "Vec<u8>")


# ---------------------------------------------------------------- 固有方法


def _inherent_impl(schema: Schema, message: Message) -> list[str]:
    name = message.name
    lines = [f"impl {name} {{"]
    if message.framed:
        lines.append("    /// MDL 里声明的消息 ID。")
        lines.append(f"    pub const MESSAGE_ID: u16 = 0x{message.message_id:04X};")
        lines.append("")
    if message.optional_field_count:
        lines.append("    /// 可空字段个数，用于定位载荷里的存在性位图。")
        lines.append(f"    pub const OPTIONAL_FIELD_COUNT: usize = {message.optional_field_count};")
        lines.append("")
    lines.append("    /// 以空值构造（等价于 `Default`）。")
    lines.append("    pub fn new() -> Self {")
    lines.append("        Self::default()")
    lines.append("    }")
    lines.append("")
    lines.append("    /// 以当前值为初值开一个新构造器（例如改完字段要重新签名）。")
    lines.append("    pub fn to_builder(&self) -> Self {")
    lines.append("        self.clone()")
    lines.append("    }")
    lines.append("")

    for field in message.fields:
        lines.extend(_setter(field))

    if message.signed:
        lines.append("    /// 帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。")
        lines.append("    pub fn set_signature(mut self, hex: &str) -> Result<Self> {")
        lines.append("        self.signature = crate::crypto::hex_decode(hex).ok_or(PbpError::BadFormat)?;")
        lines.append("        Ok(self)")
        lines.append("    }")
        lines.append("")
        lines.append("    /// 帧尾签名的原始字节。")
        lines.append("    pub fn set_signature_bytes(mut self, value: Vec<u8>) -> Self {")
        lines.append("        self.signature = value;")
        lines.append("        self")
        lines.append("    }")
        lines.append("")

    if message.framed:
        lines.extend(_frame_methods(schema, message))
    if message.signed:
        lines.extend(_signature_methods())
    lines.append("}")
    return lines


def _setter(field: ResolvedField) -> list[str]:
    field_name = _ident(field.name)
    setter = f"set_{field_name}"
    value_type = _rust_type(field)
    lines = [f"    /// MDL 字段 {field.number} `{field.name}`。"]
    if field.is_map:
        assert field.map_key is not None
        key_type = _value_rust(field.map_key)
        key_decl = "impl Into<String>" if field.map_key.name == "string" else key_type
        lines.append(f"    pub fn {setter}(mut self, value: {value_type}) -> Self {{")
        lines.append(f"        self.{field_name} = value;")
        lines.append("        self")
        lines.append("    }")
        lines.append("")
        lines.append(f"    /// 写入一个 `{field.name}` 键值对。")
        lines.append(f"    pub fn put_{field_name}(mut self, key: {key_decl}, value: {_value_rust(field.value_type)}) -> Self {{")
        key_expr = "key.into()" if field.map_key.name == "string" else "key"
        lines.append(f"        self.{field_name}.push(({key_expr}, value));")
        lines.append("        self")
        lines.append("    }")
    elif field.is_list:
        lines.append(f"    pub fn {setter}(mut self, value: {value_type}) -> Self {{")
        lines.append(f"        self.{field_name} = value;")
        lines.append("        self")
        lines.append("    }")
        lines.append("")
        lines.append(f"    /// 追加一个 `{field.name}` 元素。")
        lines.append(f"    pub fn add_{field_name}(mut self, value: {_value_rust(field.value_type)}) -> Self {{")
        lines.append(f"        self.{field_name}.push(value);")
        lines.append("        self")
        lines.append("    }")
    elif field.value_type.kind == "message":
        lines.append(f"    pub fn {setter}(mut self, value: {value_type}) -> Self {{")
        lines.append(f"        self.{field_name} = value;")
        lines.append("        self")
        lines.append("    }")
    elif field.optional and field.value_type.name == "string":
        lines.append(f"    pub fn {setter}(mut self, value: {value_type}) -> Self {{")
        lines.append(f"        self.{field_name} = value;")
        lines.append("        self")
        lines.append("    }")
    elif not field.optional and field.value_type.name == "string":
        lines.append(f"    pub fn {setter}(mut self, value: impl Into<String>) -> Self {{")
        lines.append(f"        self.{field_name} = value.into();")
        lines.append("        self")
        lines.append("    }")
    else:
        lines.append(f"    pub fn {setter}(mut self, value: {value_type}) -> Self {{")
        lines.append(f"        self.{field_name} = value;")
        lines.append("        self")
        lines.append("    }")
    lines.append("")
    return lines


def _frame_methods(schema: Schema, message: Message) -> list[str]:
    frame_ts = f"self.{_ident(message.frame_timestamp_field.name)}" if message.frame_timestamp_field else "0"
    lines: list[str] = []
    if message.signed:
        lines.append("    /// 编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。")
    else:
        lines.append("    /// 编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。")
    lines.append("    pub fn to_byte_array(&self) -> Result<Vec<u8>> {")
    lines.append(f"        let frame = PbpCodec::frame_of(self, {frame_ts})?;")
    if message.signed:
        lines.append("        let frame = if self.signature.len() == PbpFrame::SIGNATURE_SIZE {")
        lines.append("            frame.with_signature(&self.signature)?")
        lines.append("        } else if self.signature.is_empty() {")
        lines.append("            frame")
        lines.append("        } else {")
        lines.append("            return Err(PbpError::BadLength);")
        lines.append("        };")
    lines.append("        frame.encode()")
    lines.append("    }")
    lines.append("")

    if message.signed:
        lines.append("    /// HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。")
        lines.append("    pub fn signing_input(&self) -> Result<Vec<u8>> {")
        lines.append(f"        Ok(PbpCodec::frame_of(self, {frame_ts})?.signing_input())")
        lines.append("    }")
        lines.append("")

    lines.append("    /// 解析完整帧；帧结构非法或消息 ID 不符一律返回错误。")
    lines.append("    /// 置位 FLAG_COMPRESSED 的帧先解压再解码载荷。")
    lines.append("    pub fn parse_from(raw: &[u8]) -> Result<Self> {")
    lines.append("        let frame = PbpFrame::parse(raw)?;")
    lines.append("        if frame.message_id != Self::MESSAGE_ID {")
    lines.append("            return Err(PbpError::BadFormat);")
    lines.append("        }")
    lines.append("        let payload = PbpCodec::payload_of_frame(&frame)?;")
    lines.append("        let mut msg = Self::default();")
    lines.append("        msg.decode(&mut PbpDecoder::new(&payload))?;")
    if message.signed:
        lines.append("        msg.signature = frame.signature.clone();")
    lines.append("        Ok(msg)")
    lines.append("    }")
    lines.append("")
    return lines


def _signature_methods() -> list[str]:
    return [
        "    /// 帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。",
        "    pub fn signature_hex(&self) -> String {",
        "        crate::crypto::hex_encode(&self.signature)",
        "    }",
        "",
    ]


# ---------------------------------------------------------------- PbpMessage


def _message_impl(message: Message) -> list[str]:
    lines = [f"impl PbpMessage for {message.name} {{"]
    lines.append("    fn message_id(&self) -> u16 {")
    lines.append("        Self::MESSAGE_ID" if message.framed else "        0")
    lines.append("    }")
    lines.append("")
    lines.append("    fn encode(&self, enc: &mut PbpEncoder) {")
    for field in message.fields:
        lines.append(f"        {_encode_stmt(field, 'self')}")
    lines.append("    }")
    lines.append("")
    lines.append("    /// 按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），")
    lines.append("    /// 载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点。")
    lines.append("    fn decode(&mut self, dec: &mut PbpDecoder<'_>) -> Result<()> {")
    for field in message.fields:
        ident = _ident(field.name)
        if field.trailing:
            lines.append("        // 末尾字段自动 optional：旧端的载荷在这里已经读完")
            lines.append(f"        self.{ident} = if dec.remaining() > 0 {{ {_decode_expr(field)} }} else {{ {_default_expr(field)} }};")
        else:
            lines.append(f"        self.{ident} = {_decode_expr(field)};")
    lines.append("        Ok(())")
    lines.append("    }")
    lines.append("")
    lines.append("    fn encoded_size(&self) -> usize {")
    lines.append("        let mut size = 0usize;")
    for field in message.fields:
        lines.append(f"        size += {_size_expr(field)};")
    lines.append("        size")
    lines.append("    }")
    lines.append("}")
    return lines


# ---------------------------------------------------------------- 差分


def _delta_impl(message: Message) -> list[str]:
    name = message.name
    lines = [f"impl PbpDeltaMessage<{name}> for {name} {{"]
    lines.append("    /// 相对基线只写变化的字段：存在位图 + 按字段序的变化值。")
    lines.append(f"    fn encode_delta(&self, enc: &mut PbpEncoder, previous: &{name}) {{")
    lines.append(f"        let changed: [bool; {len(message.fields)}] = [")
    for field in message.fields:
        lines.append(f"            {_diff_expr(field)},")
    lines.append("        ];")
    lines.append("        enc.write_presence(&changed);")
    for index, field in enumerate(message.fields):
        lines.append(f"        if changed[{index}] {{")
        lines.append(f"            {_encode_stmt(field, 'self')}")
        lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    /// 未变化的字段从基线拷贝，变化的字段按位图读入；传入的基线对象不会被改动。")
    lines.append(f"    fn apply_delta(&mut self, dec: &mut PbpDecoder<'_>, previous: &{name}) -> Result<()> {{")
    lines.append(f"        let present = dec.read_presence({len(message.fields)})?;")
    for index, field in enumerate(message.fields):
        ident = _ident(field.name)
        lines.append(f"        self.{ident} = if present[{index}] {{ {_decode_expr(field)} }} else {{ {_copy_expr(field)} }};")
    lines.append("        Ok(())")
    lines.append("    }")
    lines.append("}")
    return lines


# ---------------------------------------------------------------- 表达式


def _scalar_writer(value_type: ResolvedType, arg: str) -> str:
    if value_type.kind == "enum":
        return f"write_enum({arg})"
    if value_type.kind == "message":
        return f"write_message({arg})"
    return f"{_SCALARS[value_type.name][1]}({arg})"


def _encode_stmt(field: ResolvedField, recv: str) -> str:
    ident = _ident(field.name)
    target = f"&{recv}.{ident}" if recv else f"&{ident}"
    value = field.value_type
    if field.is_map:
        assert field.map_key is not None
        key = _closure_writer(field.map_key, "k")
        val = _closure_writer(value, "v")
        return f"enc.write_map({target}, |e, k| e.{key}, |e, v| e.{val});"
    if field.is_list:
        if value.kind == "message":
            return f"enc.write_message_list({target});"
        if value.name == "string":
            return f"enc.write_string_list({target});"
        element = _closure_writer(value, "v")
        return f"enc.write_list({target}, |e, v| e.{element});"
    if field.optional:
        if value.kind == "message":
            return f"enc.write_optional_message({target});"
        if value.name == "string":
            return f"enc.write_optional_string({target});"
        return f"enc.write_optional_bytes({target});"
    if value.kind == "message":
        return f'enc.write_message({recv}.{ident}.as_ref().expect("{field.name} 字段不允许为空"));'
    access = f"{recv}.{ident}"
    arg = f"&{access}" if value.name in ("string", "bytes") else access
    return f"enc.{_scalar_writer(value, arg)};"


def _closure_writer(value_type: ResolvedType, param: str) -> str:
    if value_type.kind == "message":
        return f"write_message({param})"
    if value_type.kind == "enum":
        return f"write_enum(*{param})"
    writer = _SCALARS[value_type.name][1]
    if _is_copy(value_type):
        return f"{writer}(*{param})"
    return f"{writer}({param})"


def _decode_expr(field: ResolvedField) -> str:
    value = field.value_type
    if field.is_map:
        assert field.map_key is not None
        key = _closure_reader(field.map_key)
        val = _closure_reader(value)
        return f"dec.read_map(|d| d.{key}, |d| d.{val})?"
    if field.is_list:
        if value.kind == "message":
            return f"dec.read_message_list::<{value.name}>()?"
        if value.name == "string":
            return "dec.read_string_list()?"
        return f"dec.read_list(|d| d.{_closure_reader(value)})?"
    if field.optional:
        if value.kind == "message":
            return f"dec.read_optional_message::<{value.name}>()?"
        if value.name == "string":
            return "dec.read_optional_string()?"
        return "dec.read_optional_bytes()?"
    if value.kind == "message":
        return f"Some(dec.read_message::<{value.name}>()?)"
    return f"dec.{_scalar_reader(value)}()?"


def _scalar_reader(value_type: ResolvedType) -> str:
    if value_type.kind == "enum":
        return "read_enum"
    return _SCALARS[value_type.name][2]


def _closure_reader(value_type: ResolvedType) -> str:
    if value_type.kind == "message":
        return f"read_message::<{value_type.name}>()"
    return f"{_scalar_reader(value_type)}()"


def _diff_expr(field: ResolvedField) -> str:
    ident = _ident(field.name)
    value = field.value_type
    if field.is_list or field.is_map or value.kind == "message":
        current = _encode_stmt(field, "self")
        previous = _encode_stmt(field, "previous")
        return f"PbpDelta::differs(|x| {{ {current.replace('enc.', 'x.')} }}, |x| {{ {previous.replace('enc.', 'x.')} }})"
    if value.name in ("float32", "float64"):
        return f"self.{ident}.to_bits() != previous.{ident}.to_bits()"
    return f"self.{ident} != previous.{ident}"


def _copy_expr(field: ResolvedField) -> str:
    ident = _ident(field.name)
    value = field.value_type
    if field.is_map:
        if value.kind == "message":
            return f"PbpDelta::copy_map_entries(&previous.{ident})?"
        return f"previous.{ident}.clone()"
    if field.is_list:
        if value.kind == "message":
            return f"PbpDelta::copy_list(&previous.{ident})?"
        return f"previous.{ident}.clone()"
    if value.kind == "message":
        return f"PbpDelta::copy_option(previous.{ident}.as_ref())?"
    if field.optional:
        return f"previous.{ident}.clone()"
    if _is_copy(value):
        return f"previous.{ident}"
    return f"previous.{ident}.clone()"


def _size_expr(field: ResolvedField) -> str:
    ident = _ident(field.name)
    value = field.value_type
    if field.is_map:
        assert field.map_key is not None
        key = _size_lambda(field.map_key, "k")
        val = _size_lambda(value, "v")
        if field.map_key.name == "string":
            return f"PbpEncoder::string_map_size(&self.{ident}, {val})"
        return f"PbpEncoder::map_size(&self.{ident}, {key}, {val})"
    if field.is_list:
        if value.kind == "message":
            return f"PbpEncoder::message_list_size(&self.{ident})"
        if value.name == "string":
            return f"PbpEncoder::string_list_size(&self.{ident})"
        return f"size_of_{ident}(&self.{ident})"
    if field.optional:
        if value.kind == "message":
            return f"PbpEncoder::optional_message_size(&self.{ident})"
        if value.name == "string":
            return f"PbpEncoder::optional_string_size(&self.{ident})"
        return f"PbpEncoder::optional_bytes_size(&self.{ident})"
    if value.kind == "message":
        return f"self.{ident}.as_ref().map_or(0, |m| m.encoded_size())"
    return _scalar_size(value, f"self.{ident}")


def _scalar_size(value_type: ResolvedType, expr: str) -> str:
    if value_type.kind == "enum":
        return f"PbpEncoder::enum_size({expr})"
    _, _, _, sizer, takes_value = _SCALARS[value_type.name]
    if not takes_value:
        return f"PbpEncoder::{sizer}()"
    if value_type.name in ("string", "bytes"):
        return f"PbpEncoder::{sizer}(&{expr})"
    return f"PbpEncoder::{sizer}({expr})"


def _size_lambda(value_type: ResolvedType, param: str) -> str:
    if value_type.kind == "message":
        return f"|{param}| {param}.encoded_size()"
    if value_type.kind == "enum":
        return f"|{param}| PbpEncoder::enum_size(*{param})"
    _, _, _, sizer, takes_value = _SCALARS[value_type.name]
    if not takes_value:
        return f"|_{param}| PbpEncoder::{sizer}()"
    return f"|{param}| PbpEncoder::{sizer}({param})"


def _element_size(value_type: ResolvedType) -> str:
    """列表元素（`for element in list` 的 `element: &T`）的编码长度。"""
    if value_type.kind == "enum":
        return "PbpEncoder::enum_size(*element)"
    _, _, _, sizer, takes_value = _SCALARS[value_type.name]
    if not takes_value:
        return f"PbpEncoder::{sizer}()"
    if value_type.name in ("string", "bytes"):
        return f"PbpEncoder::{sizer}(element)"
    return f"PbpEncoder::{sizer}(*element)"


def _list_size_helpers(message: Message) -> list[str]:
    fields = [
        f for f in message.fields
        if f.is_list and not (f.value_type.kind == "message" or f.value_type.name == "string")
    ]
    lines: list[str] = []
    for field in fields:
        ident = _ident(field.name)
        element = _value_rust(field.value_type)
        lines.append(f"/// `{field.name}` 列表的编码长度：`PbpEncoder` 只内置了 string/message 列表的大小计算。")
        lines.append(f"fn size_of_{ident}(list: &[{element}]) -> usize {{")
        lines.append("    let mut size = PbpEncoder::varint_size(list.len() as u64);")
        lines.append("    for element in list {")
        lines.append(f"        size += {_element_size(field.value_type)};")
        lines.append("    }")
        lines.append("    size")
        lines.append("}")
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines