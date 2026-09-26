"""MDL 抽象语法树。

这一层只回答「文件里写了什么」，不做任何语义判断：类型是否已声明、字段编号是否
冲突、消息 ID 是否落在允许区间，全部留给 model.py。分开的好处是语法树可以被原样
回写（调试语法问题时打印它即可），而校验规则改动不会牵动词法/语法。

所有节点都是不可变的 frozen dataclass，集合一律用 tuple，避免生成阶段的遍历顺序
受调用方影响——生成物要入库，输出必须逐字节确定。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Option:
    """`option name = value;`，值可以是字符串、整数或布尔。"""

    name: str
    value: object
    line: int


@dataclass(frozen=True)
class TypeRef:
    """字段类型引用：MDL 标量名，或本文件内声明的消息/枚举名。

    map 字段用外层 TypeRef 表示值类型、`map_key` 表示键类型，例如
    `map<string, bytes> evidence` 会得到 `TypeRef("bytes", map_key=TypeRef("string"))`。
    这样 map 只是一种「带了键类型的类型引用」，不需要额外的字段种类。
    """

    name: str
    line: int
    map_key: "TypeRef | None" = None


@dataclass(frozen=True)
class FieldNode:
    name: str
    number: int
    type: TypeRef
    repeated: bool
    optional: bool
    line: int


@dataclass(frozen=True)
class MessageNode:
    name: str
    message_id: "int | None"
    fields: tuple[FieldNode, ...]
    reserved: tuple[int, ...]
    options: tuple[Option, ...]
    line: int


@dataclass(frozen=True)
class EnumValue:
    name: str
    number: int
    line: int


@dataclass(frozen=True)
class EnumNode:
    name: str
    values: tuple[EnumValue, ...]
    line: int


@dataclass(frozen=True)
class FileNode:
    """.mdl 文件的全部内容。"""

    path: str
    syntax: "str | None"
    package: "str | None"
    options: tuple[Option, ...]
    messages: tuple[MessageNode, ...]
    enums: tuple[EnumNode, ...]

    def option(self, name: str) -> "Option | None":
        for opt in self.options:
            if opt.name == name:
                return opt
        return None