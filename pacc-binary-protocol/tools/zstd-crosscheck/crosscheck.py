#!/usr/bin/env python3
"""PBP 内置 zstd 子集的交叉校验。

自研的 zstd 子集必须和参考实现（libzstd）对得上，否则"输出是合法 zstd"就只是自称。
本脚本做双向校验：

  1. 用 python 的 zstandard（内含 libzstd）压一批确定性输入，把帧交给 Java 侧解码；
     子集之外（Huffman literals 等）的帧由 Java 侧记入 unsupported 计数，
     但成功解码的参考帧数量必须达到下限，避免"全都没解出来"也算绿。
  2. 让 Java 侧导出我们自己压出的帧，用 libzstd 解压并逐字节比对原文。

zstandard 只作为开发/CI 工具使用，不是仓库的运行依赖：

  python -m pip install zstandard
  python pacc-binary-protocol/tools/zstd-crosscheck/crosscheck.py --mvn mvn

Windows 本地跑的时候 mvn 一般不在 PATH：用 --mvn 指向 tools-local 下的 mvn.cmd，
如果 zstandard 是用 --target 安装的，再加 --zstd-path 指向安装目录。

退出码：0 通过；1 校验失败；2 缺少 zstandard（本地可接受，CI 视为失败）。
"""

from __future__ import annotations

import argparse
import binascii
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MIN_REF_DECODED = 10


def battery():
    """参考帧用的输入电池：不可压数据出 Raw 块、常量出 RLE 块，这两类子集必须能解。"""
    cases = []
    sizes = (0, 1, 17, 100, 1024, 4096, 16384, 65535, 200000)
    for size in sizes:
        rnd = random.Random(size)
        cases.append(bytes(rnd.randrange(256) for _ in range(size)))          # 不可压
        cases.append(bytes([0x5A]) * size)                                     # 常量
        cases.append((b"pacc-pbp-zstd-subset 0123456789" * (size // 29 + 1))[:size])
        cases.append(bytes((i * 7 + size) & 0xFF for i in range(size)))        # 规律字节
    return cases


def build_compressors(zstd):
    configs = [
        zstd.ZstdCompressor(level=level, write_checksum=False,
                            write_content_size=True, write_dict_id=False)
        for level in (1, 3, 9)
    ]
    try:
        from zstandard import ZstdCompressionParameters
        # 小窗口 + fast 策略，多拿一种帧头布局；write_* 参数只能挂在参数对象上
        params = ZstdCompressionParameters.from_level(
            3, window_log=17, strategy=1,
            write_checksum=0, write_content_size=1, write_dict_id=0)
        configs.append(zstd.ZstdCompressor(compression_params=params))
    except Exception as exc:  # noqa: BLE001 - 探测型调用，失败就少跑一种组合
        print(f"[warn] 小窗口压缩参数组合不可用（{exc}），跳过该组合")
    return configs


def write_ref_vectors(zstd, path: Path) -> int:
    lines = []
    for compressor in build_compressors(zstd):
        for data in battery():
            try:
                frame = compressor.compress(data)
            except Exception:  # noqa: BLE001 - 某个组合压不动就跳过该组合的这条
                continue
            lines.append(binascii.hexlify(data).decode() + " " + binascii.hexlify(frame).decode())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def verify_our_dumps(zstd, path: Path) -> list[str]:
    failures = []
    decompressor = zstd.ZstdDecompressor()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        # 空输入的首字段就是空串，按第一个空格切一次即可
        input_hex, frame_hex = line.split(" ", 1)
        data = binascii.unhexlify(input_hex)
        frame = binascii.unhexlify(frame_hex)
        try:
            got = decompressor.decompress(frame, max_output_size=max(len(data), 1))
        except Exception as exc:  # noqa: BLE001 - 记失败继续跑完，最后统一报
            failures.append(f"第 {i} 行: libzstd 解压失败: {exc}")
            continue
        if got != data:
            failures.append(f"第 {i} 行: 解压结果与原文不符（原文 {len(data)} 字节，得到 {len(got)}）")
    return failures


def read_summary(path: Path) -> dict:
    summary = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                summary[key.strip()] = value.strip()
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mvn", default="mvn", help="mvn 可执行文件（Windows 上给 mvn.cmd 全路径）")
    parser.add_argument("--java-home", default=None, help="JAVA_HOME，Windows 上本地跑时通常需要")
    parser.add_argument("--zstd-path", default=None, help="zstandard 包所在目录（--target 安装时用）")
    parser.add_argument("--keep-workdir", action="store_true", help="保留中间文件便于排查")
    args = parser.parse_args()

    if args.zstd_path:
        sys.path.insert(0, args.zstd_path)
    try:
        import zstandard  # noqa: PLC0415 - 依赖可选的开发工具，按需导入
    except ImportError:
        print("[skip] 没装 zstandard：python -m pip install zstandard", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[3]
    pom = repo_root / "pacc-binary-protocol" / "runtime-java" / "pom.xml"
    workdir = Path(tempfile.mkdtemp(prefix="pbp-zstd-crosscheck-"))
    ref_path = workdir / "ref-vectors.txt"
    dump_path = workdir / "ours-frames.txt"
    summary_path = workdir / "summary.txt"
    try:
        ref_count = write_ref_vectors(zstandard, ref_path)
        print(f"[info] 生成参考帧 {ref_count} 条 -> {ref_path}")

        cmd = [
            args.mvn, "-B", "-f", str(pom), "test",
            "-Dtest=PbpZstdCrossCheckTest",
            f"-Dpbp.zstd.refVectors={ref_path}",
            f"-Dpbp.zstd.dumpFile={dump_path}",
            f"-Dpbp.zstd.summaryFile={summary_path}",
        ]
        env = dict(os.environ)
        if args.java_home:
            env["JAVA_HOME"] = args.java_home
        print("[info] 运行 Java 侧交叉校验 ...")
        use_shell = os.name == "nt" and args.mvn.lower().endswith(".cmd")
        result = subprocess.run(cmd, env=env, shell=use_shell)
        if result.returncode != 0:
            print("[fail] Java 侧交叉校验失败", file=sys.stderr)
            return 1

        summary = read_summary(summary_path)
        decoded = int(summary.get("refDecoded", "0"))
        unsupported = int(summary.get("refUnsupported", "0"))
        print(f"[info] 参考帧解码通过 {decoded} 条，子集外跳过 {unsupported} 条")
        if decoded < MIN_REF_DECODED:
            print(f"[fail] 参考帧解码数量不足（{decoded} < {MIN_REF_DECODED}），"
                  f"交叉校验覆盖度不够", file=sys.stderr)
            return 1

        failures = verify_our_dumps(zstandard, dump_path)
        if failures:
            for line in failures[:10]:
                print(f"[fail] {line}", file=sys.stderr)
            print(f"[fail] libzstd 校验我们的帧失败 {len(failures)} 条", file=sys.stderr)
            return 1
        print("[pass] 双向交叉校验通过：我们的帧可被 libzstd 解开，参考帧可被我们解开")
        return 0
    finally:
        if args.keep_workdir:
            print(f"[info] 中间文件保留在 {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())