"""TypeScript 代码生成。

生成物是入库的（设计文档 §3.7 要求生成结果进版本库），所以输出必须逐字节确定：不写
生成时间、不依赖字典遍历顺序、字段按编号升序排列。

与 Java emitter 的对应关系（同一份 MDL，同一套语义）：
  * 字段按编号升序写、`// optional` 走存在位图；
  * 末尾字段自动 optional：只对带消息 ID 的整帧消息生效，解码时「载荷读完取默认值」；
  * 带消息 ID 且不 signed 的消息发 encodeDelta/applyDelta；
  * 帧装配与压缩统一走运行时的 PbpCodec，生成代码不重复实现压缩策略；
  * 枚举生成常量对象而非 TS enum（线上是 VarInt 的非负整数，用 number 承载）。

int64/uint64 映射到 bigint：JS number 只有 53 位精度，撑不住 ZigZag 后的 64 位取值。
"""

from __future__ import annotations

from ..model import Enum, Message, ResolvedField, ResolvedType, Schema, id_range_label

_GENERATOR_NOTE = "本文件由 tools/pbpgen 生成，请勿手改。"

_SCALAR_TS = {
    "bool": "boolean",
    "int8": "number",
    "uint8": "number",
    "int16": "number",
    "uint16": "number",
    "int32": "number",
    "uint32": "number",
    "int64": "bigint",
    "uint64": "bigint",
    "float32": "number",
    "float64": "number",
    "string": "string",
    "bytes": "Uint8Array",
}

_DEFAULTS = {
    "boolean": "false",
    "number": "0",
    "bigint": "0n",
    "string": '""',
    "Uint8Array": "new Uint8Array(0)",
}

# 生成的 import 语句按符号名排序，保证确定性。类型专用符号用 `import type`。
_IMPORT_MODULE = {
    "PbpCodec": "../PbpCodec.js",
    "PbpDelta": "../PbpDelta.js",
    "PbpDeltaMessage": "../PbpDeltaMessage.js",
    "PbpDecoder": "../PbpDecoder.js",
    "PbpEncoder": "../PbpEncoder.js",
    "PbpException": "../PbpException.js",
    "PbpFrame": "../PbpFrame.js",
    "PbpMessage": "../PbpMessage.js",
    "bytesFromHex": "../PbpCrypto.js",
    "bytesToHex": "../PbpCrypto.js",
}
_TYPE_ONLY = frozenset({"PbpMessage", "PbpDeltaMessage"})


def _delta_capable(message: Message) -> bool:
    """是否生成差分方法：带 signed 选项的消息不发（签名与基线混用的失败面太大）。"""
    return message.framed and not message.signed


def emit_schema(schema: Schema, mdl_rel: str) -> dict[str, str]:
    """返回 {相对源码根的路径: 文件内容}。"""
    files: dict[str, str] = {}
    for enum in schema.enums:
        files[f"gen/{enum.name}.ts"] = _emit_enum(enum, mdl_rel)
    for message in schema.messages:
        files[f"gen/{message.name}.ts"] = _emit_message(message, mdl_rel)
    return files


def _header(mdl_rel: str) -> list[str]:
    return [
        f"// {_GENERATOR_NOTE}",
        f"// 源定义：{mdl_rel}",
        "// 重新生成：cd tools/pbpgen && python -m pbpgen",
        "",
    ]


def _emit_enum(enum: Enum, mdl_rel: str) -> str:
    lines = _header(mdl_rel)
    lines.append("/**")
    lines.append(f" * MDL 枚举 {enum.name}。")
    lines.append(" *")
    lines.append(" * 枚举在线上是 VarInt 编码的非负整数，所以生成的是常量对象而不是 TS enum：")
    lines.append(" * 编解码两侧统一按 number 传递，省掉一层值 ↔ 成员的来回转换。")
    lines.append(" */")
    lines.append(f"export const {enum.name} = {{")
    for name, number in enum.values:
        lines.append(f"  {name}: {number},")
    lines.append("} as const;")
    lines.append("")
    return "\n".join(lines)


def _emit_message(message: Message, mdl_rel: str) -> str:
    lines = _header(mdl_rel)
    lines.extend(_import_lines(_import_symbols(message), _message_deps(message)))
    lines.append("")

    interfaces = ["PbpMessage"]
    if _delta_capable(message):
        interfaces.append(f"PbpDeltaMessage<{message.name}>")
    lines.append("/**")
    if message.framed:
        lines.append(
            f" * PBP 消息 {message.name}（0x{message.message_id:04X}，{id_range_label(message.message_id)}）。"
        )
    else:
        lines.append(f" * PBP 消息 {message.name}，无消息 ID，仅作为嵌套类型内联在父消息载荷里。")
    lines.append(" *")
    lines.append(" * 字段按编号升序写在载荷里、不带标签，所以调整字段顺序等同于改协议；")
    lines.append(" * 新字段只能追加在末尾，否则两侧解析会整体错位。")
    if message.signed:
        lines.append(" *")
        lines.append(" * 签名不在载荷里：置位帧头 FLAG_SIGNED，32 字节 HMAC-SHA256 放在帧尾，")
        lines.append(" * 覆盖面是「帧头 + 载荷」整串字节（见 signingInput()）。")
    if _delta_capable(message):
        lines.append(" *")
        lines.append(" * 实现了 PbpDeltaMessage：可经 PbpDeltaChain 发差分帧（设计文档 §3.10.2）。")
    lines.append(" */")
    lines.append(f"export class {message.name} implements {', '.join(interfaces)} {{")

    emitter = _MessageEmitter(message)
    emitter.emit_class_body()
    lines.extend(emitter.lines)
    lines.append("}")
    lines.append("")
    lines.extend(emitter.builder_lines)
    return "\n".join(lines)


def _import_symbols(message: Message) -> list[str]:
    symbols = {"PbpDecoder", "PbpEncoder", "PbpMessage"}
    if message.framed:
        symbols.update({"PbpCodec", "PbpException", "PbpFrame"})
    if _delta_capable(message):
        symbols.add("PbpDeltaMessage")
        if any(f.is_list or f.is_map or f.value_type.kind == "message" or f.value_type.name == "bytes"
               for f in message.fields):
            symbols.add("PbpDelta")
    if message.signed:
        symbols.update({"bytesFromHex", "bytesToHex"})
    return sorted(symbols)


def _message_deps(message: Message) -> list[str]:
    """字段引用到的同目录生成消息（TS 每个类型一个模块，需要显式 import）。"""
    deps = {f.value_type.name for f in message.fields if f.value_type.kind == "message"}
    deps.discard(message.name)
    return sorted(deps)


def _import_lines(symbols: list[str], deps: list[str]) -> list[str]:
    # 同一模块的符号合并成一条 import，符号名与整行都排序，保证确定性
    modules: dict[str, list[str]] = {}
    for symbol in symbols:
        modules.setdefault(_IMPORT_MODULE[symbol], []).append(symbol)
    lines = []
    for module, names in modules.items():
        ordered = sorted(names)
        keyword = "import type" if all(name in _TYPE_ONLY for name in ordered) else "import"
        lines.append(f'{keyword} {{ {", ".join(ordered)} }} from "{module}";')
    for dep in deps:
        lines.append(f'import {{ {dep} }} from "./{dep}.js";')
    return sorted(lines)


class _MessageEmitter:
    """逐段拼出类体（lines）与独立的构造器类（builder_lines），缩进固定两空格。"""

    def __init__(self, message: Message):
        self.message = message
        self.lines: list[str] = []
        self.builder_lines: list[str] = []

    # ------------------------------------------------------------ 工具

    def add(self, text: str = "", indent: int = 1) -> None:
        self.lines.append(("  " * indent + text) if text else "")

    def doc(self, text: str, indent: int = 1) -> None:
        self.add(f"/** {text} */", indent)

    # ------------------------------------------------------------ 类型与默认值

    def base_type(self, field: ResolvedField) -> str:
        if field.is_list:
            return f"{_value_ts(field.value_type)}[]"
        if field.is_map:
            return f"Map<{_value_ts(field.map_key)}, {_value_ts(field.value_type)}>"
        return _value_ts(field.value_type)

    def storage_type(self, field: ResolvedField) -> str:
        base = self.base_type(field)
        if field.optional:
            return f"{base} | null"
        if field.value_type.kind == "message" and not field.is_list and not field.is_map:
            return f"{base} | null"
        return base

    def setter_type(self, field: ResolvedField) -> str:
        base = self.base_type(field)
        value = field.value_type
        if field.is_list or field.is_map or value.kind == "message" or value.name in ("string", "bytes"):
            return f"{base} | null"
        return base

    def default_expr(self, field: ResolvedField) -> str:
        if field.is_list:
            return "[]"
        if field.is_map:
            return "new Map()"
        if field.value_type.kind == "message" or field.optional:
            return "null"
        return _DEFAULTS[_value_ts(field.value_type)]

    def setter_expr(self, field: ResolvedField) -> str:
        value = field.value_type
        if field.is_list:
            return "value === null ? [] : value.slice()"
        if field.is_map:
            return "value === null ? new Map() : new Map(value)"
        if value.name == "bytes":
            return "value === null ? new Uint8Array(0) : value.slice()"
        if value.name == "string" and not field.optional:
            return 'value === null ? "" : value'
        return "value"

    # ------------------------------------------------------------ 类体

    def emit_class_body(self) -> None:
        self._constants()
        self._fields()
        self._builder_entry_points()
        if self.message.framed:
            self._frame()
            if self.message.signed:
                self._signature_accessors()
        self._core_methods()
        self._delta_methods()
        self._builder_class()

    def _constants(self) -> None:
        message = self.message
        if message.framed:
            self.add("/** MDL 里声明的消息 ID。 */")
            self.add(f"static readonly MESSAGE_ID = 0x{message.message_id:04X};")
            self.add("")
        if message.optional_field_count:
            self.add("/** 可空字段个数，用于定位载荷里的存在性位图。 */")
            self.add(f"static readonly OPTIONAL_FIELD_COUNT = {message.optional_field_count};")
            self.add("")

    def _fields(self) -> None:
        message = self.message
        self.add("// ------------------------------------------------------------ 字段")
        self.add("")
        for field in message.fields:
            self.add(f"{field.field_name}: {self.storage_type(field)} = {self.default_expr(field)};")
        if message.signed:
            self.add("")
            self.add("// 帧尾签名，载荷里没有这个字段")
            self.add("signature: Uint8Array = new Uint8Array(0);")
        self.add("")

    def _builder_entry_points(self) -> None:
        message = self.message
        builder = f"{message.name}Builder"
        self.doc("建一个空构造器；可空性由 MDL 决定：String 与 byte[] 默认空值、消息类型字段默认 null。")
        self.add(f"static newBuilder(): {builder} {{")
        self.add(f"  return new {builder}();")
        self.add("}")
        self.add("")
        self.doc("以当前值为初值开一个新构造器（例如改完字段要重新签名）。")
        self.add(f"toBuilder(): {builder} {{")
        self.add(f"  const builder = new {builder}();")
        for field in message.fields:
            self.add(f"  builder.{field.field_name} = {self._copy_to_builder(field)};")
        if message.signed:
            self.add("  builder.signature = this.signature.slice();")
        self.add("  return builder;")
        self.add("}")
        self.add("")

    def _copy_to_builder(self, field: ResolvedField) -> str:
        name = f"this.{field.field_name}"
        if field.is_list:
            return f"{name}.slice()"
        if field.is_map:
            return f"new Map({name})"
        if field.value_type.name == "bytes":
            return f"{name} === null ? null : {name}.slice()" if field.optional else f"{name}.slice()"
        return name

    def _frame(self) -> None:
        message = self.message
        frame_ts = f"this.{message.frame_timestamp_field.field_name}" if message.frame_timestamp_field else "0n"
        self.add("// ------------------------------------------------------------ 帧")
        self.add("")
        if message.signed:
            self.doc("编码为完整帧；已签名时置位 FLAG_SIGNED 并把 32 字节签名放到帧尾。")
        else:
            self.doc("编码为完整帧。本消息不签名，帧头时间戳与序列号由上层填写。")
        self.add("toByteArray(): Uint8Array {")
        if message.signed:
            self.add(f"  let frame = PbpCodec.frameOf(this, {frame_ts});")
            self.add("  if (this.signature.length === PbpFrame.SIGNATURE_SIZE) {")
            self.add("    frame = frame.withSignature(this.signature);")
            self.add("  } else if (this.signature.length !== 0) {")
            self.add("    throw new PbpException(")
            self.add('      "BAD_LENGTH",')
            self.add("      `签名长度必须是 0 或 ${PbpFrame.SIGNATURE_SIZE}，实际 ${this.signature.length}`,")
            self.add("    );")
            self.add("  }")
            self.add("  return frame.encode();")
        else:
            self.add(f"  const frame = PbpCodec.frameOf(this, {frame_ts});")
            self.add("  return frame.encode();")
        self.add("}")
        self.add("")

        if message.signed:
            self.doc("HMAC 覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷（需要压缩时是压缩后的载荷）。")
            self.add("signingInput(): Uint8Array {")
            self.add(f"  return PbpCodec.frameOf(this, {frame_ts}).signingInput();")
            self.add("}")
            self.add("")

        self.doc("解析完整帧；帧结构非法或消息 ID 不符一律抛 PbpException。"
                 "置位 FLAG_COMPRESSED 的帧先解压再解码载荷。")
        self.add(f"static parseFrom(raw: Uint8Array): {message.name} {{")
        self.add("  const frame = PbpFrame.parse(raw);")
        self.add(f"  if (frame.messageId !== {message.name}.MESSAGE_ID) {{")
        self.add("    throw new PbpException(")
        self.add('      "BAD_FORMAT",')
        self.add(f"      `消息 ID 不符：期望 0x${{{message.name}.MESSAGE_ID.toString(16)}}，"
                 "实际 0x${frame.messageId.toString(16)}`,")
        self.add("    );")
        self.add("  }")
        self.add(f"  const msg = new {message.name}();")
        self.add("  msg.decode(new PbpDecoder(PbpCodec.payloadOfFrame(frame)));")
        if message.signed:
            self.add("  msg.signature = frame.signature;")
        self.add("  return msg;")
        self.add("}")
        self.add("")

    def _signature_accessors(self) -> None:
        self.add("// ------------------------------------------------------------ 签名")
        self.add("")
        self.doc("帧尾 32 字节 HMAC-SHA256 的小写十六进制；未签名返回空串。")
        self.add("getSignatureHex(): string {")
        self.add('  return this.signature.length === 0 ? "" : bytesToHex(this.signature);')
        self.add("}")
        self.add("")
        self.doc("帧尾签名的副本；未签名返回零长数组。")
        self.add("signatureBytes(): Uint8Array {")
        self.add("  return this.signature.slice();")
        self.add("}")
        self.add("")

    def _core_methods(self) -> None:
        message = self.message
        self.add("// ------------------------------------------------------------ PbpMessage")
        self.add("")
        self.add("messageId(): number {")
        self.add(f"  return {message.name}.MESSAGE_ID;" if message.framed else "  return 0;")
        self.add("}")
        self.add("")

        self.add("encode(enc: PbpEncoder): void {")
        for field in message.fields:
            self.add(f"  enc.{self._encode_call(field)};")
        self.add("}")
        self.add("")

        self.doc("按定义顺序读回字段。末尾字段在载荷提前读完时取默认值（旧端没发该字段），"
                 "载荷尾部多出的字节不再消费（新端追加了字段）——两条都是兼容落点（设计文档 §3.11）。")
        self.add("decode(dec: PbpDecoder): void {")
        for field in message.fields:
            if field.trailing:
                self.add("  // 末尾字段自动 optional：旧端的载荷在这里已经读完")
                self.add(f"  this.{field.field_name} = dec.remaining() > 0"
                         f" ? {self._decode_expr(field)} : {self.default_expr(field)};")
            else:
                self.add(f"  this.{field.field_name} = {self._decode_expr(field)};")
        self.add("}")
        self.add("")

        self.doc("编码后的字节数，仅用于预分配缓冲区。")
        self.add("encodedSize(): number {")
        self.add("  let size = 0;")
        for field in message.fields:
            self.add(f"  size += {self._size_expr(field)};")
        self.add("  return size;")
        self.add("}")
        self.add("")

    def _delta_methods(self) -> None:
        message = self.message
        if not _delta_capable(message):
            return
        self.add("// ------------------------------------------------------------ 差分（设计文档 §3.10.2）")
        self.add("")
        self.doc("相对基线只写变化的字段：存在位图 + 按字段序的变化值。")
        self.add(f"encodeDelta(enc: PbpEncoder, previous: {message.name}): void {{")
        self.add("  const changed = [")
        for field in message.fields:
            self.add(f"    {self._diff_expr(field)},")
        self.add("  ];")
        self.add("  enc.writePresence(changed);")
        for index, field in enumerate(message.fields):
            self.add(f"  if (changed[{index}]) {{")
            self.add(f"    enc.{self._encode_call(field)};")
            self.add("  }")
        self.add("}")
        self.add("")
        self.doc("未变化的字段从基线拷贝（消息与字节数组深拷贝、集合按元素复制），变化的字段按位图读入；"
                 "传入的基线对象不会被改动。")
        self.add(f"applyDelta(dec: PbpDecoder, previous: {message.name}): void {{")
        self.add(f"  const present = dec.readPresence({len(message.fields)});")
        for index, field in enumerate(message.fields):
            self.add(f"  this.{field.field_name} = present[{index}]"
                     f" ? {self._decode_expr(field)} : {self._copy_expr(field)};")
        self.add("}")
        self.add("")

    def _builder_class(self) -> None:
        message = self.message
        builder = f"{message.name}Builder"
        self.builder_lines.append("/**")
        self.builder_lines.append(f" * {message.name} 的字段构造器：setter 处理 null 归一化，"
                                  "build() 对可变字段做拷贝。")
        self.builder_lines.append(" */")
        self.builder_lines.append(f"export class {builder} {{")
        for field in message.fields:
            self.builder_lines.append(
                f"  {field.field_name}: {self.storage_type(field)} = {self.default_expr(field)};")
        if message.signed:
            self.builder_lines.append("  signature: Uint8Array = new Uint8Array(0);")
        self.builder_lines.append("")
        for field in message.fields:
            self.builder_lines.append(f"  /** MDL 字段 {field.number} {field.name}。 */")
            self.builder_lines.append(f"  set{field.java_name}(value: {self.setter_type(field)}): this {{")
            self.builder_lines.append(f"    this.{field.field_name} = {self.setter_expr(field)};")
            self.builder_lines.append("    return this;")
            self.builder_lines.append("  }")
            self.builder_lines.append("")
            if field.is_list:
                self.builder_lines.append(f"  /** 追加一个 {field.name} 元素。 */")
                self.builder_lines.append(
                    f"  add{field.java_name}(value: {_value_ts(field.value_type)}): this {{")
                self.builder_lines.append(f"    this.{field.field_name}.push(value);")
                self.builder_lines.append("    return this;")
                self.builder_lines.append("  }")
                self.builder_lines.append("")
            if field.is_map:
                self.builder_lines.append(f"  /** 写入一个 {field.name} 键值对。 */")
                self.builder_lines.append(
                    f"  put{field.java_name}(key: {_value_ts(field.map_key)}, "
                    f"value: {_value_ts(field.value_type)}): this {{")
                self.builder_lines.append(f"    this.{field.field_name}.set(key, value);")
                self.builder_lines.append("    return this;")
                self.builder_lines.append("  }")
                self.builder_lines.append("")
        if message.signed:
            self.builder_lines.append("  /** 帧尾 32 字节 HMAC-SHA256 的小写十六进制；空串表示不签名。 */")
            self.builder_lines.append("  setSignature(hex: string | null): this {")
            self.builder_lines.append(
                '    this.signature = hex === null || hex === "" ? new Uint8Array(0) : bytesFromHex(hex);')
            self.builder_lines.append("    return this;")
            self.builder_lines.append("  }")
            self.builder_lines.append("")
            self.builder_lines.append("  /** 帧尾签名的原始字节；null 视为不签名。 */")
            self.builder_lines.append("  setSignatureBytes(value: Uint8Array | null): this {")
            self.builder_lines.append(
                "    this.signature = value === null ? new Uint8Array(0) : value.slice();")
            self.builder_lines.append("    return this;")
            self.builder_lines.append("  }")
            self.builder_lines.append("")
        self.builder_lines.append(f"  build(): {message.name} {{")
        self.builder_lines.append(f"    const msg = new {message.name}();")
        for field in message.fields:
            self.builder_lines.append(f"    msg.{field.field_name} = {self._copy_on_build(field)};")
        if message.signed:
            self.builder_lines.append("    msg.signature = this.signature.slice();")
        self.builder_lines.append("    return msg;")
        self.builder_lines.append("  }")
        self.builder_lines.append("}")
        self.builder_lines.append("")

    def _copy_on_build(self, field: ResolvedField) -> str:
        name = f"this.{field.field_name}"
        if field.is_list:
            return f"{name}.slice()"
        if field.is_map:
            return f"new Map({name})"
        if field.value_type.name == "bytes":
            return f"{name} === null ? null : {name}.slice()" if field.optional else f"{name}.slice()"
        return name

    # ------------------------------------------------------------ 表达式

    def _encode_call(self, field: ResolvedField, prefix: str = "this.") -> str:
        value = field.value_type
        name = f"{prefix}{field.field_name}"
        if field.is_map:
            value_writer = f"(e, v) => e.{value.writer}(v)"
            if field.map_key.name == "string":
                return f"writeStringMap({name}, {value_writer})"
            return f"writeMap({name}, (e, k) => e.{field.map_key.writer}(k), {value_writer})"
        if field.is_list:
            if value.kind == "message":
                return f"writeMessageList({name})"
            if value.name == "string":
                return f"writeStringList({name})"
            return f"writeList({name}, (e, v) => e.{value.writer}(v))"
        if field.optional:
            if value.kind == "message":
                return f"writeOptionalMessage({name})"
            if value.name == "string":
                return f"writeOptionalString({name})"
            return f"writeOptionalBytes({name})"
        if value.kind == "message":
            return f"writeMessage({name})"
        return f"{value.writer}({name})"

    def _decode_expr(self, field: ResolvedField) -> str:
        value = field.value_type
        if field.is_map:
            if field.map_key.name == "string":
                if value.kind == "message":
                    return f"dec.readStringMap((d) => d.readMessage(() => new {value.name}()))"
                return f"dec.readStringMap((d) => d.{value.reader}())"
            value_reader = (f"(d) => d.readMessage(() => new {value.name}())"
                            if value.kind == "message" else f"(d) => d.{value.reader}()")
            return (f"dec.readMap<{_value_ts(field.map_key)}, {_value_ts(value)}>("
                    f"() => new Map(), (d) => d.{field.map_key.reader}(), {value_reader})")
        if field.is_list:
            if value.kind == "message":
                return f"dec.readMessageList(() => new {value.name}())"
            if value.name == "string":
                return "dec.readStringList()"
            return f"dec.readList<{_value_ts(value)}>(() => [], (d) => d.{value.reader}())"
        if field.optional:
            if value.kind == "message":
                return f"dec.readOptionalMessage(() => new {value.name}())"
            if value.name == "string":
                return "dec.readOptionalString()"
            return "dec.readOptionalBytes()"
        if value.kind == "message":
            return f"dec.readMessage(() => new {value.name}())"
        return f"dec.{value.reader}()"

    def _size_expr(self, field: ResolvedField) -> str:
        value = field.value_type
        name = f"this.{field.field_name}"
        if field.is_map:
            if field.map_key.name == "string":
                return f"PbpEncoder.stringMapSize({name}, {_sizer_ref(value)})"
            return f"PbpEncoder.mapSize({name}, {_sizer_ref(field.map_key)}, {_sizer_ref(value)})"
        if field.is_list:
            if value.kind == "message":
                return f"PbpEncoder.messageListSize({name})"
            if value.name == "string":
                return f"PbpEncoder.stringListSize({name})"
            return f"PbpEncoder.listSize({name}, {_sizer_ref(value)})"
        if field.optional:
            if value.kind == "message":
                return f"PbpEncoder.optionalMessageSize({name})"
            if value.name == "string":
                return f"PbpEncoder.optionalStringSize({name})"
            return f"PbpEncoder.optionalBytesSize({name})"
        if value.kind == "message":
            return f"PbpEncoder.messageSize({name})"
        if value.sizer_takes_value:
            return f"PbpEncoder.{value.sizer}({name})"
        return f"PbpEncoder.{value.sizer}()"

    def _diff_expr(self, field: ResolvedField) -> str:
        value = field.value_type
        other = f"previous.{field.field_name}"
        if field.is_list or field.is_map or value.kind == "message":
            current = f"(x) => x.{self._encode_call(field, 'this.')}"
            base = f"(x) => x.{self._encode_call(field, 'previous.')}"
            return f"PbpDelta.differs({current}, {base})"
        if value.name == "string":
            return f"this.{field.field_name} !== {other}"
        if value.name == "bytes":
            return f"!PbpDelta.bytesEqual(this.{field.field_name}, {other})"
        if value.java in ("float", "double"):
            return f"!Object.is(this.{field.field_name}, {other})"
        return f"this.{field.field_name} !== {other}"

    def _copy_expr(self, field: ResolvedField) -> str:
        value = field.value_type
        other = f"previous.{field.field_name}"
        if field.is_map:
            if value.kind == "message":
                return f"PbpDelta.copyMap({other}, () => new {value.name}())"
            return f"new Map({other})"
        if field.is_list:
            if value.kind == "message":
                return f"PbpDelta.copyList({other}, () => new {value.name}())"
            return f"{other}.slice()"
        if value.kind == "message":
            return f"PbpDelta.copy({other}, () => new {value.name}())"
        if value.name == "bytes":
            return f"{other}.slice()"
        return other


# ---------------------------------------------------------------- 纯函数


def _value_ts(value: ResolvedType) -> str:
    if value.kind == "scalar":
        return _SCALAR_TS[value.name]
    if value.kind == "message":
        return value.name
    # 枚举在 TS 侧用 number 承载
    return "number"


def _sizer_ref(value: ResolvedType) -> str:
    """sizer 引用：取值型直接用静态方法引用，无参的定长 sizer 用无参箭头适配。"""
    if value.sizer_takes_value:
        return f"PbpEncoder.{value.sizer}"
    return f"() => PbpEncoder.{value.sizer}()"