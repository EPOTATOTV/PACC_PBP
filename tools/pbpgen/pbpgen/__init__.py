"""pbpgen：PBP 消息定义语言（MDL）解析器与代码生成器。

零第三方依赖，只用标准库——生成器要在各平台 CI 上跑，装依赖这一步能省则省。
"""

from __future__ import annotations

from .codegen import (
    DEFAULT_JAVA_ROOT,
    DEFAULT_MDL_DIR,
    GeneratedFile,
    check,
    default_java_root,
    default_mdl_dir,
    find_mdl_files,
    generate,
    load_schemas,
    repo_root,
    write,
)
from .lexer import MdlSyntaxError

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_JAVA_ROOT",
    "DEFAULT_MDL_DIR",
    "GeneratedFile",
    "MdlSyntaxError",
    "check",
    "default_java_root",
    "default_mdl_dir",
    "find_mdl_files",
    "generate",
    "load_schemas",
    "repo_root",
    "write",
    "__version__",
]