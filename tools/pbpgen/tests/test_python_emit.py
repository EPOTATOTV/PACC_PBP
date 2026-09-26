"""Python emitter 测试：输出形态、确定性与「生成物能编译」。

生成物入库，手写断言只能盯住自己想到的地方，所以这里还拿 repo 的真实 MDL 走一遍
emit_package 并和磁盘上的 runtime-python/pbp_gen 逐字节比对——漂移检查的同一件事。
编译校验用 py_compile（标准库），不需要额外工具链。
"""

import pathlib
import py_compile
import tempfile
import unittest

from pbpgen import codegen, model, parser
from pbpgen.emit import python as python_emit

COMPLEX = '''
syntax = "pbp1";
package com.example.mdl;
option java_package = "com.example.gen";

enum Level {
    LOW = 0;
    HIGH = 2;
}

message Inner {
    string label = 1;
    int32 weight = 2;
}

message Outer {
    0x0123: id
    option signed = true;
    option frame_timestamp = ts_ms;
    reserved 7, 8;

    string name = 1;
    int64 ts_ms = 2;
    string note = 3; // optional
    bytes blob = 4; // optional
    repeated Inner items = 5;
    repeated string tags = 6;
    map<string, uint16> counters = 9;
    map<int32, string> labels = 10;
    repeated int64 numbers = 11;
    Inner nested = 12;
    Level level = 13;
    repeated Level levels = 14;
    uint8 sig_version = 15;
}

// 不签名 + 带集合字段：差分方法与 lambda 比较路径只有这类消息会走到
message StatusReport {
    0x0124: id

    string pteid = 1;
    repeated Inner items = 2;
    map<string, bytes> evidence = 3;
    Inner nested = 4;
    repeated string tags = 5;
}

// 字段按书写顺序乱排，生成的写入顺序必须按编号升序
message Order {
    0x0125: id

    string second = 2;
    int32 first = 1;
}
'''


def schema_of(source: str, path: str = "t.mdl") -> model.Schema:
    return model.build_schema(parser.parse_source(source, path))


class EmitShapeTest(unittest.TestCase):

    def setUp(self):
        self.files = python_emit.emit_schema(schema_of(COMPLEX), "t.mdl")

    def test_output_paths_follow_snake_case(self):
        self.assertEqual(
            {
                "pbp_gen/__init__.py",
                "pbp_gen/pbp_core.py",
                "pbp_gen/level.py",
                "pbp_gen/inner.py",
                "pbp_gen/outer.py",
                "pbp_gen/status_report.py",
                "pbp_gen/order.py",
            },
            set(self.files),
        )

    def test_header_points_back_at_mdl(self):
        text = self.files["pbp_gen/outer.py"]
        self.assertIn("# 本文件由 tools/pbpgen 生成，请勿手改。", text)
        self.assertIn("# 源定义：t.mdl", text)
        self.assertIn("from __future__ import annotations", text)

    def test_contract_api_present(self):
        text = self.files["pbp_gen/outer.py"]
        for fragment in (
            "class Outer(PbpMessage):",
            "MESSAGE_ID = 0x0123",
            "OPTIONAL_FIELD_COUNT = 2",
            "def new_builder(cls):",
            "def build(self):",
            "def to_bytes(self):",
            "def signing_input(self):",
            "def parse_from(raw):",
            "def set_signature_bytes(self, value):",
        ):
            self.assertIn(fragment, text)

    def test_message_id_matches_mdl(self):
        self.assertIn("MESSAGE_ID = 0x0103", python_emit.emit_schema(
            schema_of("syntax = \"pbp1\";\npackage p;\noption java_package = \"p\";\n"
                      "message Report {\n    0x0103: id\n    string a = 1;\n}\n"), "t.mdl")["pbp_gen/report.py"])

    def test_optional_fields_use_presence_bitmap(self):
        text = self.files["pbp_gen/outer.py"]
        self.assertIn("enc.write_optional_string(self.note)", text)
        self.assertIn("enc.write_optional_bytes(self.blob)", text)
        self.assertIn("self.note = dec.read_optional_string()", text)
        self.assertIn("self.blob = dec.read_optional_bytes()", text)

    def test_trailing_field_decodes_with_remaining_guard(self):
        outer = self.files["pbp_gen/outer.py"]
        self.assertIn("self.sig_version = dec.read_uint8() if dec.remaining() > 0 else 0", outer)
        # 嵌套类型不做：内联编码里没有「读完了」这个信号
        inner = self.files["pbp_gen/inner.py"]
        self.assertNotIn("dec.remaining()", inner)
        self.assertIn("self.weight = dec.read_int32()", inner)

    def test_delta_methods_only_for_unsigned_framed_messages(self):
        status = self.files["pbp_gen/status_report.py"]
        self.assertIn("class StatusReport(PbpMessage, PbpDeltaMessage):", status)
        self.assertIn("def encode_delta(self, enc, previous):", status)
        self.assertIn("def apply_delta(self, dec, previous):", status)
        self.assertIn("enc.write_presence(changed)", status)
        self.assertIn("present = dec.read_presence(5)", status)
        # 带 signed 的消息不发差分方法：签名与基线混用的失败面太大
        self.assertNotIn("PbpDeltaMessage", self.files["pbp_gen/outer.py"])
        # 嵌套类型没有帧，也就没有差分
        self.assertNotIn("PbpDeltaMessage", self.files["pbp_gen/inner.py"])

    def test_delta_copy_keeps_message_fields_deep(self):
        text = self.files["pbp_gen/status_report.py"]
        self.assertIn("PbpDelta.copy(previous.nested, Inner)", text)
        self.assertIn("[PbpDelta.copy(item, Inner) for item in previous.items]", text)

    def test_fields_are_emitted_in_number_order(self):
        text = self.files["pbp_gen/order.py"]
        self.assertLess(text.index("enc.write_int32(self.first)"),
                        text.index("enc.write_string(self.second)"))

    def test_enum_generates_constants(self):
        text = self.files["pbp_gen/level.py"]
        self.assertIn("class Level:", text)
        self.assertIn("LOW = 0", text)
        self.assertIn("HIGH = 2", text)
        self.assertNotIn("IntEnum", text)

    def test_init_exports_core_and_messages(self):
        text = self.files["pbp_gen/__init__.py"]
        for name in ("PbpEncoder", "PbpDecoder", "PbpFrame", "Outer", "StatusReport", "Level"):
            self.assertIn('"%s"' % name, text)

    def test_core_only_uses_stdlib(self):
        core = self.files["pbp_gen/pbp_core.py"]
        imports = [line for line in core.splitlines()
                   if line.startswith("import ") or line.startswith("from ")]
        self.assertEqual(
            ["from __future__ import annotations", "import hashlib", "import hmac", "import struct"],
            sorted(imports),
        )

    def test_core_frame_layout(self):
        core = self.files["pbp_gen/pbp_core.py"]
        for fragment in (
            "MAGIC = 0x5042",
            "VERSION = 1",
            "HEADER_SIZE = 30",
            "SIGNATURE_SIZE = 32",
            "FLAG_COMPRESSED = 0x02",
            "FLAG_DELTA = 0x04",
            "FLAG_SIGNED = 0x08",
            "out[PbpFrame._OFF_MAGIC] = PbpFrame.MAGIC >> 8",
            "header = self._header_bytes(self.flags | PbpFrame.FLAG_SIGNED, len(self.payload))",
            "return header + self.payload",
            "MAX_COLLECTION_SIZE = 1 << 20",
            "MAX_VARINT_BYTES = 10",
        ):
            self.assertIn(fragment, core)

    def test_core_is_schema_independent(self):
        other = python_emit.emit_schema(
            schema_of("syntax = \"pbp1\";\npackage p;\noption java_package = \"p\";\n"
                      "message M {\n    0x0130: id\n    string a = 1;\n}\n"), "u.mdl")
        self.assertEqual(self.files["pbp_gen/pbp_core.py"], other["pbp_gen/pbp_core.py"])

    def test_emit_is_deterministic(self):
        again = python_emit.emit_schema(schema_of(COMPLEX), "t.mdl")
        self.assertEqual(self.files, again)

    def test_emit_package_merges_exports(self):
        merged = python_emit.emit_package([schema_of(COMPLEX, "a.mdl"), schema_of(
            "syntax = \"pbp1\";\npackage p;\noption java_package = \"p\";\n"
            "message Extra {\n    0x0140: id\n    string a = 1;\n}\n", "b.mdl")])
        # core 只有一份，__init__ 聚合两个 MDL 的导出
        self.assertEqual(1, sum(1 for path in merged if path.endswith("pbp_core.py")))
        init = merged["pbp_gen/__init__.py"]
        self.assertIn('"Outer"', init)
        self.assertIn('"Extra"', init)


class CompileTest(unittest.TestCase):
    """用 py_compile 编一遍生成物，语法错误在单测里就拦住。"""

    def test_generated_sources_compile(self):
        files = python_emit.emit_schema(schema_of(COMPLEX), "t.mdl")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for rel, content in files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            for path in sorted(root.glob("pbp_gen/*.py")):
                py_compile.compile(str(path), cfile=str(path) + "c", doraise=True)


class RepoOutputTest(unittest.TestCase):

    RUNTIME_ROOT = codegen.repo_root() / "pacc-binary-protocol/runtime-python"

    def test_repo_generated_output_matches_emitter(self):
        files = python_emit.emit_package(codegen.load_schemas(codegen.find_mdl_files(None)))
        for rel, content in files.items():
            path = self.RUNTIME_ROOT / rel
            self.assertTrue(path.exists(), "生成物缺失：%s" % rel)
            self.assertEqual(content, path.read_text(encoding="utf-8"), "与 MDL 不一致：%s" % rel)

        produced = {(self.RUNTIME_ROOT / rel).resolve() for rel in files}
        for path in sorted((self.RUNTIME_ROOT / "pbp_gen").glob("*.py")):
            self.assertIn(path.resolve(), produced, "多余生成物：%s" % path)


if __name__ == "__main__":
    unittest.main()