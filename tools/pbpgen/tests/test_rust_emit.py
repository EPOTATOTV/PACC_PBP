"""Rust emitter 测试：输出形态、契约 API 与确定性。

只 import emitter 直接校验（不跑 `python -m pbpgen`）：路径布局、契约方法、可选与末尾
字段、差分方法的分发、关键字转义、以及「入库生成物与 MDL 一致」的漂移守护。
"""

import pathlib
import unittest

from pbpgen import codegen, model, parser
from pbpgen.emit.rust import emit_package, emit_schema

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
'''

KEYWORDS = '''
syntax = "pbp1";
package com.example.mdl;
option java_package = "com.example.gen";

message Kw {
    0x0125: id

    string type = 1;
    int32 match = 2;
}
'''

# 第二段 MDL：给 emit_package 的跨 MDL 聚合用例用（类型名不与 COMPLEX 冲突）
WIRE = '''
syntax = "pbp1";
package com.example.mdl;
option java_package = "com.example.gen";

message PaccEnvelope {
    0x2001: id
    string type = 1;
    int64 ts_ms = 2;
}
'''


def schema_of(source: str, path: str = "t.mdl") -> model.Schema:
    return model.build_schema(parser.parse_source(source, path))


class EmitShapeTest(unittest.TestCase):

    def setUp(self):
        self.files = emit_schema(schema_of(COMPLEX), "t.mdl")

    def test_output_paths(self):
        self.assertEqual(
            {
                "gen/mod.rs",
                "gen/Level.rs",
                "gen/Inner.rs",
                "gen/Outer.rs",
                "gen/StatusReport.rs",
            },
            set(self.files),
        )

    def test_header_points_back_at_mdl(self):
        text = self.files["gen/Outer.rs"]
        self.assertIn("本文件由 tools/pbpgen 生成，请勿手改。", text)
        self.assertIn("// 源定义：t.mdl", text)
        # 重新生成提示不带 --rust（与其它语言 emitter 统一）
        self.assertIn("// 重新生成：cd tools/pbpgen && python -m pbpgen", text)
        self.assertNotIn("--rust", text)

    def test_mod_lists_modules_sorted(self):
        text = self.files["gen/mod.rs"]
        self.assertIn('#[path = "Outer.rs"]', text)
        self.assertIn("pub mod outer;", text)
        self.assertIn("pub use outer::Outer;", text)
        order = [line for line in text.splitlines() if line.startswith("pub mod ")]
        self.assertEqual(["pub mod inner;", "pub mod level;", "pub mod outer;", "pub mod status_report;"], order)

    def test_contract_api_present(self):
        text = self.files["gen/Outer.rs"]
        for fragment in (
            "pub struct Outer {",
            "pub const MESSAGE_ID: u16 = 0x0123;",
            "pub fn new() -> Self {",
            "pub fn to_builder(&self) -> Self {",
            "pub fn to_byte_array(&self) -> Result<Vec<u8>> {",
            "pub fn signing_input(&self) -> Result<Vec<u8>> {",
            "pub fn parse_from(raw: &[u8]) -> Result<Self> {",
            "pub fn set_signature_bytes(mut self, value: Vec<u8>) -> Self {",
            "pub fn set_sig_version(mut self, value: u8) -> Self {",
            "impl PbpMessage for Outer {",
        ):
            self.assertIn(fragment, text)

    def test_field_types_and_collections(self):
        text = self.files["gen/Outer.rs"]
        self.assertIn("pub name: String,", text)
        self.assertIn("pub ts_ms: i64,", text)
        self.assertIn("pub items: Vec<Inner>,", text)
        self.assertIn("pub tags: Vec<String>,", text)
        self.assertIn("pub counters: Vec<(String, u16)>,", text)
        self.assertIn("pub labels: Vec<(i32, String)>,", text)
        self.assertIn("pub numbers: Vec<i64>,", text)
        self.assertIn("pub nested: Option<Inner>,", text)
        self.assertIn("pub level: u32,", text)
        self.assertIn("pub levels: Vec<u32>,", text)

    def test_optional_fields_use_option_and_presence(self):
        text = self.files["gen/Outer.rs"]
        self.assertIn("pub note: Option<String>,", text)
        self.assertIn("pub blob: Option<Vec<u8>>,", text)
        self.assertIn("enc.write_optional_string(&self.note);", text)
        self.assertIn("enc.write_optional_bytes(&self.blob);", text)
        self.assertIn("self.note = dec.read_optional_string()?;", text)
        self.assertIn("self.blob = dec.read_optional_bytes()?;", text)
        self.assertIn("pub const OPTIONAL_FIELD_COUNT: usize = 2;", text)

    def test_trailing_field_decodes_with_remaining_guard(self):
        outer = self.files["gen/Outer.rs"]
        self.assertIn("self.sig_version = if dec.remaining() > 0 { dec.read_uint8()? } else { 0 };", outer)
        # 嵌套类型不做：内联编码里没有"读完了"这个信号
        inner = self.files["gen/Inner.rs"]
        self.assertIn("self.weight = dec.read_int32()?;", inner)
        self.assertNotIn("remaining()", inner)

    def test_delta_methods_only_for_unsigned_framed_messages(self):
        status = self.files["gen/StatusReport.rs"]
        self.assertIn("impl PbpDeltaMessage<StatusReport> for StatusReport {", status)
        self.assertIn("fn encode_delta(&self, enc: &mut PbpEncoder, previous: &StatusReport) {", status)
        self.assertIn("fn apply_delta(&mut self, dec: &mut PbpDecoder<'_>, previous: &StatusReport) -> Result<()> {", status)
        self.assertIn("enc.write_presence(&changed);", status)
        # 带 signed 的消息不发差分方法
        self.assertNotIn("PbpDeltaMessage", self.files["gen/Outer.rs"])
        # 嵌套类型没有帧，也就没有差分
        self.assertNotIn("PbpDeltaMessage", self.files["gen/Inner.rs"])

    def test_enum_generates_constants(self):
        text = self.files["gen/Level.rs"]
        self.assertIn("pub const LOW: u32 = 0;", text)
        self.assertIn("pub const HIGH: u32 = 2;", text)

    def test_nested_message_has_no_message_id(self):
        inner = self.files["gen/Inner.rs"]
        self.assertNotIn("MESSAGE_ID", inner)
        self.assertIn("fn message_id(&self) -> u16 {\n        0\n    }", inner)

    def test_imports_only_what_is_used(self):
        inner = self.files["gen/Inner.rs"]
        self.assertNotIn("use crate::codec::PbpCodec;", inner)
        self.assertNotIn("use crate::delta::", inner)
        self.assertNotIn("use crate::frame::PbpFrame;", inner)
        outer = self.files["gen/Outer.rs"]
        self.assertIn("use crate::codec::PbpCodec;", outer)
        self.assertIn("use crate::frame::PbpFrame;", outer)
        self.assertIn("use crate::gen::Inner;", outer)

    def test_emit_is_deterministic(self):
        self.assertEqual(self.files, emit_schema(schema_of(COMPLEX), "t.mdl"))


class KeywordTest(unittest.TestCase):

    def test_rust_keywords_are_escaped(self):
        files = emit_schema(schema_of(KEYWORDS), "t.mdl")
        text = files["gen/Kw.rs"]
        self.assertIn("pub type_: String,", text)
        self.assertIn("pub match_: i32,", text)
        self.assertIn("enc.write_string(&self.type_);", text)
        self.assertIn("enc.write_int32(self.match_);", text)
        self.assertIn("pub fn set_type_(mut self, value: impl Into<String>) -> Self {", text)


class PackageTest(unittest.TestCase):
    """emit_package：跨 MDL 聚合，gen/mod.rs 只出一份、条目按类型名排序且与入参顺序无关。"""

    def setUp(self):
        self.detect = schema_of(COMPLEX, "pacc-binary-protocol/mdl/detection.mdl")
        self.wire = schema_of(WIRE, "pacc-binary-protocol/mdl/pacc_wire.mdl")

    def test_shared_mod_is_union_of_both_schemas(self):
        files = emit_package([self.detect, self.wire])
        self.assertEqual(
            {
                "gen/mod.rs",
                "gen/PaccEnvelope.rs",
                "gen/Inner.rs",
                "gen/Level.rs",
                "gen/Outer.rs",
                "gen/StatusReport.rs",
            },
            set(files),
        )
        mod = files["gen/mod.rs"]
        # header 是多文件花括号列表，按 schema.path 排序
        self.assertIn("// 源定义：pacc-binary-protocol/mdl/{detection.mdl, pacc_wire.mdl}", mod)
        self.assertIn("// 重新生成：cd tools/pbpgen && python -m pbpgen", mod)
        self.assertNotIn("--rust", mod)
        # 条目按类型名排序
        entries = [line for line in mod.splitlines() if line.startswith("pub mod ")]
        self.assertEqual(
            ["pub mod inner;", "pub mod level;", "pub mod outer;", "pub mod pacc_envelope;", "pub mod status_report;"],
            entries,
        )

    def test_type_files_are_not_duplicated_and_keep_source_mdl(self):
        files = emit_package([self.detect, self.wire])
        # 每个类型恰好一个模块文件，没有重复
        type_modules = [path for path in files if path != "gen/mod.rs"]
        self.assertEqual(len(type_modules), len(set(type_modules)))
        # 每个类型文件的源定义指向它自己的 MDL
        self.assertIn("// 源定义：pacc-binary-protocol/mdl/pacc_wire.mdl", files["gen/PaccEnvelope.rs"])
        self.assertIn("// 源定义：pacc-binary-protocol/mdl/detection.mdl", files["gen/Outer.rs"])

    def test_package_is_deterministic_and_order_independent(self):
        self.assertEqual(emit_package([self.detect, self.wire]), emit_package([self.wire, self.detect]))

    def test_single_schema_view_matches_package_type_file(self):
        # emit_schema 的单 schema 视图与聚合视图里同一个类型文件逐字节一致
        single = emit_schema(self.detect, self.detect.path)
        package = emit_package([self.detect, self.wire])
        self.assertEqual(single["gen/Outer.rs"], package["gen/Outer.rs"])


class RepoDriftTest(unittest.TestCase):
    """入库的 runtime-rust 生成物必须与 emit_package 输出逐字节一致（含聚合的 gen/mod.rs）。"""

    def test_generated_files_match_package_output(self):
        root = codegen.repo_root() / "pacc-binary-protocol/runtime-rust/src"
        schemas = codegen.load_schemas(codegen.find_mdl_files(None))
        expected = emit_package(schemas)
        self.assertTrue(expected, "没有找到任何 MDL 输出")
        for rel, content in expected.items():
            target = root / rel
            self.assertTrue(target.exists(), f"生成物缺失：{rel}")
            self.assertEqual(content, target.read_text(encoding="utf-8"), f"生成物与聚合输出不一致：{rel}")

    def test_no_stale_generated_modules(self):
        # 生成目录里不应出现聚合输出之外的 .rs（残留生成物）
        root = codegen.repo_root() / "pacc-binary-protocol/runtime-rust/src"
        expected = emit_package(codegen.load_schemas(codegen.find_mdl_files(None)))
        produced = {p.name for p in (root / "gen").glob("*.rs")}
        self.assertEqual(produced, {pathlib.Path(rel).name for rel in expected})


if __name__ == "__main__":
    unittest.main()