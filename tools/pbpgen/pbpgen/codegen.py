"""MDL → 生成物的编排：收集文件、解析校验、写盘或比对。

生成物入库，所以这里有两条铁律：
  * 同一份 MDL 必须生成出逐字节相同的文件（emit 层不写时间戳、不依赖字典顺序）
  * `check()` 只读，绝不顺手修补磁盘上的文件——CI 要靠它判断"人改了生成物"还是
    "MDL 改了但忘了重新生成"，自动修会把后者掩盖成通过

一次运行生成设计文档 §3.7 的五种语言；各语言输出根见 EMIT_TARGETS。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import model, parser
from .emit import emit_package, emit_schema
from .lexer import MdlSyntaxError

DEFAULT_MDL_DIR = "pacc-binary-protocol/mdl"
DEFAULT_JAVA_ROOT = "pacc-binary-protocol/runtime-java/src/main/java"


@dataclass(frozen=True)
class EmitTarget:
    """一种语言（或运行时）的输出目标。

    root 是相对仓库根的源码根；package_level 表示该语言有跨 MDL 的共享产物
    （Rust 的 gen/mod.rs、Python 的 pbp_core.py 与 __init__.py），必须整体生成一次，
    逐 schema 循环会互相覆盖。
    """

    language: str
    root: str
    package_level: bool = False


EMIT_TARGETS: tuple[EmitTarget, ...] = (
    EmitTarget("java", DEFAULT_JAVA_ROOT),
    EmitTarget("typescript", "pacc-binary-protocol/runtime-ts/src"),
    EmitTarget("rust", "pacc-binary-protocol/runtime-rust/src", package_level=True),
    EmitTarget("csharp", "pacc-binary-protocol/runtime-csharp"),
    EmitTarget("python", "pacc-binary-protocol/runtime-python", package_level=True),
)


def repo_root() -> Path:
    """仓库根：tools/pbpgen/pbpgen/codegen.py 上溯 3 层。

    刻意不用 cwd——CI 与本地开发者可能从任意目录调用，靠 cwd 会让 `--check`
    在不同机器上比对不同的文件。
    """
    return Path(__file__).resolve().parents[3]


def default_mdl_dir() -> Path:
    return repo_root() / DEFAULT_MDL_DIR


def default_java_root() -> Path:
    return repo_root() / DEFAULT_JAVA_ROOT


@dataclass(frozen=True)
class GeneratedFile:
    path: Path
    content: str
    mdl_rel: str


def find_mdl_files(mdl_path: str | Path | None) -> list[Path]:
    path = Path(mdl_path) if mdl_path is not None else default_mdl_dir()
    if path.is_dir():
        files = sorted(path.glob("*.mdl"))
        if not files:
            raise MdlSyntaxError(f"{path} 下没有任何 .mdl 文件", 0, str(path))
        return files
    if not path.exists():
        raise MdlSyntaxError(f"MDL 文件不存在: {path}", 0, str(path))
    return [path]


def load_schemas(mdl_paths: Iterable[Path]) -> list[model.Schema]:
    schemas: list[model.Schema] = []
    for path in mdl_paths:
        rel = relative_label(path)
        with open(path, "r", encoding="utf-8") as handle:
            node = parser.parse_source(handle.read(), rel)
        schemas.append(model.build_schema(node))
    _check_global_uniqueness(schemas)
    return schemas


def generate(mdl_path: str | Path | None = None,
             java_root: str | Path | None = None) -> list[GeneratedFile]:
    """生成全部语言的输出清单；java_root 只覆盖 Java 目标（旧调用点兼容）。"""
    schemas = load_schemas(find_mdl_files(mdl_path))
    out: list[GeneratedFile] = []
    for target in EMIT_TARGETS:
        if target.language == "java" and java_root is not None:
            root = Path(java_root)
        else:
            root = repo_root() / target.root
        if target.package_level:
            mdl_rel = "、".join(schema.path for schema in schemas)
            for rel_path, content in emit_package(schemas, target.language).items():
                out.append(GeneratedFile(root / rel_path, content, mdl_rel))
        else:
            for schema in schemas:
                for rel_path, content in emit_schema(schema, schema.path, target.language).items():
                    out.append(GeneratedFile(root / rel_path, content, schema.path))
    return out


def write(files: Iterable[GeneratedFile]) -> list[Path]:
    written: list[Path] = []
    for generated in files:
        generated.path.parent.mkdir(parents=True, exist_ok=True)
        generated.path.write_text(generated.content, encoding="utf-8", newline="\n")
        written.append(generated.path)
    return written


def check(mdl_path: str | Path | None = None,
          java_root: str | Path | None = None) -> list[str]:
    """返回漂移问题清单；空表示磁盘上的生成物与 MDL 一致。"""
    problems: list[str] = []
    root = Path(java_root) if java_root is not None else default_java_root()
    files = generate(mdl_path, root)

    for generated in files:
        if not generated.path.exists():
            problems.append(f"生成物缺失：{relative_label(generated.path)}（来自 {generated.mdl_rel}）")
            continue
        actual = generated.path.read_text(encoding="utf-8")
        if actual != generated.content:
            problems.append(
                f"生成物与 MDL 不一致：{relative_label(generated.path)}"
                f"（来自 {generated.mdl_rel}，{_first_diff(actual, generated.content)}）"
            )

    expected = {f.path.resolve() for f in files}
    for stale in _stale_candidates(files, root):
        if stale.resolve() not in expected:
            problems.append(f"生成物已无对应 MDL 定义：{relative_label(stale)}")

    return problems


def _stale_candidates(files: list[GeneratedFile], root: Path) -> list[Path]:
    """只看生成器自己的输出目录，不扫整棵源码树。

    每个语言的生成物都落在专门的子目录（gen/、Gen/、pbp_gen/），手写的运行时源码
    不在这些目录里，所以按"生成物所在目录 + 出现过的后缀"清理即可，
    不会把手写文件误判成残留。
    """
    dirs: dict[Path, set[str]] = {}
    for generated in files:
        dirs.setdefault(generated.path.parent, set()).add(generated.path.suffix)
    stale: list[Path] = []
    for directory, suffixes in sorted(dirs.items()):
        if not directory.is_dir():
            continue
        for suffix in sorted(suffixes):
            stale.extend(sorted(directory.glob(f"*{suffix}")))
    return stale


def _first_diff(actual: str, expected: str) -> str:
    actual_lines = actual.splitlines()
    expected_lines = expected.splitlines()
    for index, (a, e) in enumerate(zip(actual_lines, expected_lines), start=1):
        if a != e:
            return f"首个差异在第 {index} 行"
    return f"行数不同（磁盘 {len(actual_lines)} 行，期望 {len(expected_lines)} 行）"


def _check_global_uniqueness(schemas: list[model.Schema]) -> None:
    seen_ids: dict[int, str] = {}
    seen_outputs: dict[str, str] = {}
    for schema in schemas:
        for message in schema.messages:
            if message.message_id is not None:
                owner = seen_ids.get(message.message_id)
                if owner is not None:
                    raise MdlSyntaxError(
                        f"消息 ID 0x{message.message_id:04X} 在 {owner} 与 {schema.path} 中重复出现",
                        0, schema.path)
                seen_ids[message.message_id] = f"{schema.path} 的 {message.name}"
        for type_name in [m.name for m in schema.messages] + [e.name for e in schema.enums]:
            key = f"{schema.java_package}.{type_name}"
            owner = seen_outputs.get(key)
            if owner is not None:
                raise MdlSyntaxError(
                    f"类型 {key} 在 {owner} 与 {schema.path} 中会生成同一个文件", 0, schema.path)
            seen_outputs[key] = schema.path


def relative_label(path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root()).as_posix()
    except ValueError:
        return path.as_posix()