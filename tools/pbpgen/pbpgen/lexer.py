"""MDL 词法分析：把 .mdl 文本切成带行号的 token 流。

只认 MDL 真正需要的东西：标识符 / 数字（十进制或 0x 十六进制）/ 双引号字符串 /
少量标点 / 注释。遇到不认识的字符直接报错并带上行号——生成器是构建期工具，
与其放过一个看不懂的写法、生成出语义错位的代码，不如在这里停下。

注释不做丢弃处理：`// optional` 是字段可空性的声明方式（设计文档 §3.6.1），
所以注释要作为 token 留在流里，由语法分析按「是否紧跟在同一行的字段之后」取用。
"""

from __future__ import annotations

from dataclasses import dataclass

_PUNCT = frozenset("{}()<>,;=:.[]")
_IDENT_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_BODY = _IDENT_START | frozenset("0123456789")
_DIGITS = frozenset("0123456789")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class MdlSyntaxError(Exception):
    """MDL 词法/语法错误，带出错行号与文件路径。"""

    def __init__(self, message: str, line: int, path: str = ""):
        where = f"{path}:{line}" if path else f"第 {line} 行"
        super().__init__(f"{where}: {message}")
        self.line = line
        self.path = path


@dataclass(frozen=True)
class Token:
    """kind 取 ident / number / string / punct / comment / eof。"""

    kind: str
    text: str
    line: int


def tokenize(source: str, path: str = "") -> list[Token]:
    tokens: list[Token] = []
    i = 0
    line = 1
    size = len(source)

    while i < size:
        ch = source[i]

        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue

        if ch == "/" and i + 1 < size and source[i + 1] == "/":
            start = i
            while i < size and source[i] != "\n":
                i += 1
            tokens.append(Token("comment", source[start:i], line))
            continue

        if ch == "/" and i + 1 < size and source[i + 1] == "*":
            start_line = line
            i += 2
            while i + 1 < size and not (source[i] == "*" and source[i + 1] == "/"):
                if source[i] == "\n":
                    line += 1
                i += 1
            if i + 1 >= size:
                raise MdlSyntaxError("块注释没有闭合", start_line, path)
            i += 2
            continue

        if ch == '"':
            start_line = line
            i += 1
            buf: list[str] = []
            while True:
                if i >= size:
                    raise MdlSyntaxError("字符串没有闭合", start_line, path)
                c = source[i]
                if c == "\n":
                    raise MdlSyntaxError("字符串里不能出现换行", start_line, path)
                if c == "\\":
                    if i + 1 >= size:
                        raise MdlSyntaxError("字符串结尾的转义不完整", start_line, path)
                    escaped = source[i + 1]
                    if escaped not in ('"', "\\"):
                        raise MdlSyntaxError(f"不支持的转义 \\{escaped}", start_line, path)
                    buf.append(escaped)
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            tokens.append(Token("string", "".join(buf), start_line))
            continue

        if ch in _IDENT_START:
            start = i
            while i < size and source[i] in _IDENT_BODY:
                i += 1
            tokens.append(Token("ident", source[start:i], line))
            continue

        if ch in _DIGITS:
            start = i
            if ch == "0" and i + 1 < size and source[i + 1] in "xX":
                i += 2
                digits_start = i
                while i < size and source[i] in _HEX_DIGITS:
                    i += 1
                if i == digits_start:
                    raise MdlSyntaxError("0x 后面没有十六进制数字", line, path)
            else:
                while i < size and source[i] in _DIGITS:
                    i += 1
            tokens.append(Token("number", source[start:i], line))
            continue

        if ch in _PUNCT:
            tokens.append(Token("punct", ch, line))
            i += 1
            continue

        raise MdlSyntaxError(f"不认识的字符 {ch!r}", line, path)

    tokens.append(Token("eof", "", line))
    return tokens