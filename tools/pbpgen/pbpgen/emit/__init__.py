"""多种语言生成器出口。

五种语言的 emitter 都实现 `emit_schema(schema, mdl_rel) -> {相对路径: 内容}`；
Rust 与 Python 还有跨 MDL 的共享产物（gen/mod.rs、pbp_core.py 与 __init__.py），
必须走 `emit_package(schemas, language)` 整体生成，逐 schema 循环会互相覆盖。
"""

from __future__ import annotations

from ..model import Schema
from .csharp import emit_schema as _emit_csharp
from .java import emit_schema as _emit_java
from .python import emit_package as _emit_python_package
from .python import emit_schema as _emit_python
from .rust import emit_package as _emit_rust_package
from .rust import emit_schema as _emit_rust
from .typescript import emit_schema as _emit_typescript

__all__ = ["emit_schema", "emit_package", "LANGUAGES"]

_SCHEMA_EMITTERS = {
    "java": _emit_java,
    "typescript": _emit_typescript,
    "rust": _emit_rust,
    "csharp": _emit_csharp,
    "python": _emit_python,
}

_PACKAGE_EMITTERS = {
    "rust": _emit_rust_package,
    "python": _emit_python_package,
}

# 生成器支持的语言（与设计文档 §3.7 的五语言一致）。
LANGUAGES: tuple[str, ...] = tuple(_SCHEMA_EMITTERS)


def emit_schema(schema: Schema, mdl_rel: str, language: str = "java") -> dict[str, str]:
    """单 schema 生成；默认语言保持为 Java，兼容既有调用点。"""
    try:
        emitter = _SCHEMA_EMITTERS[language]
    except KeyError:
        raise ValueError(f"未知语言 {language!r}，可选：{', '.join(_SCHEMA_EMITTERS)}") from None
    return emitter(schema, mdl_rel)


def emit_package(schemas: list[Schema], language: str) -> dict[str, str]:
    """跨 MDL 聚合生成（只有部分语言需要）。"""
    try:
        emitter = _PACKAGE_EMITTERS[language]
    except KeyError:
        raise ValueError(f"{language!r} 没有跨 MDL 聚合产物") from None
    return emitter(schemas)