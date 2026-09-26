"""MDL 语法分析：token 流 → 语法树（ast.py 的节点）。

递归下降，不引入 parser 生成器：MDL 只有十来条产生式，手写更好读也更好定位错误。

一个需要留意的写法：消息 ID 声明 `0x2001: id` 结尾不带分号，与其他语句不同，
所以语句分派要先看「数字后面是不是冒号」。
"""

from __future__ import annotations

from . import ast
from .lexer import MdlSyntaxError, Token, tokenize


def parse_source(source: str, path: str = "") -> ast.FileNode:
    return Parser(tokenize(source, path), path).parse_file()


def parse_file(path: str) -> ast.FileNode:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_source(handle.read(), path)


class Parser:
    def __init__(self, tokens: list[Token], path: str = ""):
        self.tokens = tokens
        self.path = path
        self.i = 0

    # ------------------------------------------------------------ token 游标

    def _peek(self, ahead: int = 0) -> Token:
        """向前看第 ahead 个非注释 token；到末尾返回 eof。"""
        j = self.i
        seen = 0
        while j < len(self.tokens):
            if self.tokens[j].kind != "comment":
                if seen == ahead:
                    return self.tokens[j]
                seen += 1
            j += 1
        return self.tokens[-1]

    def _next(self) -> Token:
        while self.tokens[self.i].kind == "comment":
            self.i += 1
        token = self.tokens[self.i]
        self.i += 1
        return token

    def _error(self, message: str, line: int) -> MdlSyntaxError:
        return MdlSyntaxError(message, line, self.path)

    def _at_punct(self, text: str) -> bool:
        token = self._peek()
        return token.kind == "punct" and token.text == text

    def _at_ident(self, text: str) -> bool:
        token = self._peek()
        return token.kind == "ident" and token.text == text

    def _expect_punct(self, text: str) -> Token:
        token = self._next()
        if token.kind != "punct" or token.text != text:
            raise self._error(f"期望 {text!r}，实际 {token.text or token.kind!r}", token.line)
        return token

    def _expect_ident(self, what: str = "标识符") -> Token:
        token = self._next()
        if token.kind != "ident":
            raise self._error(f"期望{what}，实际 {token.text or token.kind!r}", token.line)
        return token

    # ------------------------------------------------------------ 文件级

    def parse_file(self) -> ast.FileNode:
        syntax: str | None = None
        package: str | None = None
        options: list[ast.Option] = []
        messages: list[ast.MessageNode] = []
        enums: list[ast.EnumNode] = []

        while True:
            token = self._peek()
            if token.kind == "eof":
                break
            if token.kind != "ident":
                raise self._error(f"文件级只允许 syntax/package/option/message/enum，实际 {token.text!r}", token.line)
            if token.text == "syntax":
                self._next()
                self._expect_punct("=")
                value = self._next()
                if value.kind != "string":
                    raise self._error("syntax 的值必须是字符串", value.line)
                if syntax is not None:
                    raise self._error("syntax 重复声明", token.line)
                self._expect_punct(";")
                syntax = value.text
            elif token.text == "package":
                self._next()
                if package is not None:
                    raise self._error("package 重复声明", token.line)
                package = self._parse_dotted_name()
                self._expect_punct(";")
            elif token.text == "option":
                options.append(self._parse_option())
            elif token.text == "message":
                messages.append(self._parse_message())
            elif token.text == "enum":
                enums.append(self._parse_enum())
            else:
                raise self._error(f"文件级不认识的关键字 {token.text!r}", token.line)

        return ast.FileNode(
            path=self.path,
            syntax=syntax,
            package=package,
            options=tuple(options),
            messages=tuple(messages),
            enums=tuple(enums),
        )

    def _parse_dotted_name(self) -> str:
        parts = [self._expect_ident("包名").text]
        while self._at_punct("."):
            self._next()
            parts.append(self._expect_ident("包名片段").text)
        return ".".join(parts)

    def _parse_option(self) -> ast.Option:
        keyword = self._expect_ident()
        name = self._expect_ident("选项名")
        self._expect_punct("=")
        value = self._parse_value()
        self._expect_punct(";")
        return ast.Option(name.text, value, keyword.line)

    def _parse_value(self) -> object:
        token = self._next()
        if token.kind == "string":
            return token.text
        if token.kind == "number":
            return _parse_int(token, self.path)
        if token.kind == "ident":
            if token.text == "true":
                return True
            if token.text == "false":
                return False
            # 裸标识符按字符串取值，用于 `option frame_timestamp = ts_ms;` 这类字段名引用
            return token.text
        raise self._error(f"不支持的选项值 {token.text or token.kind!r}", token.line)

    # ------------------------------------------------------------ message

    def _parse_message(self) -> ast.MessageNode:
        keyword = self._expect_ident()
        name = self._expect_ident("消息名")
        self._expect_punct("{")

        message_id: int | None = None
        fields: list[ast.FieldNode] = []
        reserved: list[int] = []
        options: list[ast.Option] = []

        while not self._at_punct("}"):
            token = self._peek()
            if token.kind == "eof":
                raise self._error(f"message {name.text} 没有闭合的 }}", keyword.line)

            nxt = self._peek(1)
            if token.kind == "number" and nxt.kind == "punct" and nxt.text == ":":
                number = self._next()
                self._expect_punct(":")
                id_keyword = self._expect_ident("id")
                if id_keyword.text != "id":
                    raise self._error("消息 ID 声明必须写成 `<数字>: id`", id_keyword.line)
                if message_id is not None:
                    raise self._error(f"message {name.text} 重复声明消息 ID", number.line)
                message_id = _parse_int(number, self.path)
                continue

            if token.kind == "ident" and token.text == "option":
                options.append(self._parse_option())
                continue
            if token.kind == "ident" and token.text == "reserved":
                reserved.extend(self._parse_reserved())
                continue
            fields.append(self._parse_field())

        self._expect_punct("}")
        return ast.MessageNode(
            name=name.text,
            message_id=message_id,
            fields=tuple(fields),
            reserved=tuple(reserved),
            options=tuple(options),
            line=keyword.line,
        )

    def _parse_reserved(self) -> list[int]:
        keyword = self._expect_ident()
        numbers = [_parse_int_required(self, "保留字段编号")]
        while self._at_punct(","):
            self._next()
            numbers.append(_parse_int_required(self, "保留字段编号"))
        self._expect_punct(";")
        return numbers

    def _parse_field(self) -> ast.FieldNode:
        repeated = False
        if self._at_ident("repeated"):
            repeated = True
            self._next()

        type_ref = self._parse_type_ref()
        name = self._expect_ident("字段名")
        self._expect_punct("=")
        number = _parse_int_required(self, "字段编号")
        semicolon = self._expect_punct(";")
        optional = self._take_optional_marker(semicolon.line)

        return ast.FieldNode(
            name=name.text,
            number=number,
            type=type_ref,
            repeated=repeated,
            optional=optional,
            line=name.line,
        )

    def _parse_type_ref(self) -> ast.TypeRef:
        token = self._expect_ident("类型名")
        if token.text != "map":
            return ast.TypeRef(token.text, token.line)

        self._expect_punct("<")
        key = self._parse_type_ref()
        self._expect_punct(",")
        value = self._parse_type_ref()
        self._expect_punct(">")
        if value.map_key is not None:
            raise self._error("map 的值类型不能再是 map", value.line)
        return ast.TypeRef(value.name, token.line, map_key=key)

    def _take_optional_marker(self, line: int) -> bool:
        """取用紧跟字段同一行的 `// optional` 注释。

        可空性靠注释声明（设计文档 §3.6.1），所以注释 token 不能在这里被无差别跳过。
        只认行首第一个词是 optional 的注释，`// optional 说明…` 也算。
        """
        if self.i < len(self.tokens):
            token = self.tokens[self.i]
            if token.kind == "comment" and token.line == line:
                body = token.text.lstrip("/").strip()
                if body == "optional" or body.startswith("optional "):
                    self.i += 1
                    return True
        return False

    # ------------------------------------------------------------ enum

    def _parse_enum(self) -> ast.EnumNode:
        keyword = self._expect_ident()
        name = self._expect_ident("枚举名")
        self._expect_punct("{")
        values: list[ast.EnumValue] = []
        while not self._at_punct("}"):
            token = self._peek()
            if token.kind == "eof":
                raise self._error(f"enum {name.text} 没有闭合的 }}", keyword.line)
            value_name = self._expect_ident("枚举项名")
            self._expect_punct("=")
            number = _parse_int_required(self, "枚举项取值")
            self._expect_punct(";")
            values.append(ast.EnumValue(value_name.text, number, value_name.line))
        self._expect_punct("}")
        return ast.EnumNode(name.text, tuple(values), keyword.line)


def _parse_int(token: Token, path: str) -> int:
    try:
        return int(token.text, 0)
    except ValueError:
        raise MdlSyntaxError(f"不是合法整数 {token.text!r}", token.line, path) from None


def _parse_int_required(parser: Parser, what: str) -> int:
    token = parser._next()
    if token.kind != "number":
        raise parser._error(f"期望{what}，实际 {token.text or token.kind!r}", token.line)
    return _parse_int(token, parser.path)