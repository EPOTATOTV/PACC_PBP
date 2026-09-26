"""pbpgen 命令行入口。

    cd tools/pbpgen
    python -m pbpgen            # 生成并覆盖写盘
    python -m pbpgen --check    # 只比对，发现漂移退出码 1

退出码：0 正常 / 1 生成物与 MDL 不一致 / 2 MDL 本身有问题（语法或校验不过）。
把"MDL 写错了"和"忘了重新生成"分开，CI 日志里一眼能看出该改哪边。
"""

from __future__ import annotations

import argparse
import sys

from . import codegen
from .lexer import MdlSyntaxError


def main(argv: list[str] | None = None) -> int:
    arg_parser = argparse.ArgumentParser(
        prog="pbpgen",
        description="从 MDL 生成 PBP 消息的五语言代码（Java/TS/Rust/C#/Python；生成物入库，改动后需提交）",
    )
    arg_parser.add_argument("--in", dest="mdl", default=None,
                            help=f"MDL 文件或目录，默认 {codegen.DEFAULT_MDL_DIR}")
    arg_parser.add_argument("--out", dest="java_root", default=None,
                            help=f"Java 源码根（只覆盖 Java 目标的输出根），默认 {codegen.DEFAULT_JAVA_ROOT}")
    arg_parser.add_argument("--check", action="store_true",
                            help="只比对磁盘上的生成物，不写盘（CI 用）")
    args = arg_parser.parse_args(argv)

    try:
        if args.check:
            problems = codegen.check(args.mdl, args.java_root)
        else:
            files = codegen.generate(args.mdl, args.java_root)
            written = codegen.write(files)
            for path in written:
                print(f"生成 {codegen.relative_label(path)}")
            print(f"共 {len(written)} 个文件")
            return 0
    except MdlSyntaxError as error:
        print(f"MDL 校验失败：{error}", file=sys.stderr)
        return 2

    if problems:
        for problem in problems:
            print(f"::error:: {problem}" if _in_github_actions() else problem, file=sys.stderr)
        print(f"生成物与 MDL 不一致，共 {len(problems)} 处。"
              f"请执行 `cd tools/pbpgen && python -m pbpgen` 后提交。", file=sys.stderr)
        return 1

    print("生成物与 MDL 一致")
    return 0


def _in_github_actions() -> bool:
    import os

    return os.environ.get("GITHUB_ACTIONS") == "true"


if __name__ == "__main__":
    raise SystemExit(main())