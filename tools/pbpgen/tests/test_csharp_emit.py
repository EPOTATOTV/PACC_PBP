"""C# emitter 测试：输出形态与确定性。

与 test_java_emit.py 对着看：两种语言的生成物在契约上必须一致（字段升序、可选位图、
末尾字段取默认值、差分只发给带 ID 且不 signed 的消息），差异只在 C# 的习惯写法上。
这里只做字符串级断言，不跑 `python -m pbpgen`，也不依赖 dotnet。
"""

import unittest

from pbpgen import codegen, model, parser
from pbpgen.emit.csharp import emit_schema

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


def schema_of(source: str, path: str = "t.mdl") -> model.Schema:
    return model.build_schema(parser.parse_source(source, path))


class EmitShapeTest(unittest.TestCase):

    def setUp(self):
        self.files = emit_schema(schema_of(COMPLEX), "t.mdl")

    def test_output_paths_live_under_gen(self):
        self.assertEqual(
            {"Gen/Level.cs", "Gen/Inner.cs", "Gen/Outer.cs", "Gen/StatusReport.cs"},
            set(self.files),
        )

    def test_header_points_back_at_mdl(self):
        text = self.files["Gen/Outer.cs"]
        self.assertIn("本文件由 tools/pbpgen 生成，请勿手改。", text)
        self.assertIn("// 源定义：t.mdl", text)
        self.assertIn("namespace Potatotv.Pbp.Gen;", text)

    def test_contract_api_present(self):
        text = self.files["Gen/Outer.cs"]
        for fragment in (
            "public sealed class Outer : IPbpMessage",
            "public const int MessageId = 0x0123;",
            "public static Builder NewBuilder()",
            "public Builder ToBuilder()",
            "public static Outer ParseFrom(byte[] raw)",
            "public byte[] ToByteArray()",
            "public byte[] SigningInput()",
            "public Builder SetSignatureBytes(byte[]? value)",
            "public int SigVersion => sigVersion;",
        ):
            self.assertIn(fragment, text)

    def test_nested_message_has_no_message_id(self):
        inner = self.files["Gen/Inner.cs"]
        self.assertNotIn("public const int MessageId", inner)
        self.assertIn("public int GetMessageId() => 0;", inner)
        self.assertNotIn("PbpFrame", inner)

    def test_collection_fields_use_csharp_types(self):
        text = self.files["Gen/Outer.cs"]
        self.assertIn("private List<long> numbers", text)
        self.assertIn("private List<int> levels", text)      # 枚举在 C# 侧就是 int
        self.assertIn("private List<Inner> items", text)
        self.assertIn("private Dictionary<string, int> counters", text)
        self.assertIn("private Dictionary<int, string> labels", text)
        self.assertIn("public IReadOnlyList<long> Numbers", text)
        self.assertIn("public IReadOnlyDictionary<string, int> Counters", text)

    def test_optional_fields_use_presence_bitmap(self):
        text = self.files["Gen/Outer.cs"]
        self.assertIn("public const int OptionalFieldCount = 2;", text)
        self.assertIn("enc.WriteOptionalString(note);", text)
        self.assertIn("enc.WriteOptionalBytes(blob);", text)
        self.assertIn("note = dec.ReadOptionalString();", text)
        self.assertIn("blob = dec.ReadOptionalBytes();", text)
        self.assertIn("public string? Note => note;", text)

    def test_trailing_field_decodes_with_remaining_guard(self):
        # 末尾字段自动 optional：只对带消息 ID 的消息生效
        outer = self.files["Gen/Outer.cs"]
        self.assertIn("sigVersion = dec.Remaining > 0", outer)
        self.assertIn("? dec.ReadUInt8()", outer)
        inner = self.files["Gen/Inner.cs"]
        self.assertIn("weight = dec.ReadInt32();", inner)

    def test_delta_methods_only_for_unsigned_framed_messages(self):
        status = self.files["Gen/StatusReport.cs"]
        self.assertIn("public sealed class StatusReport : IPbpMessage, IPbpDeltaMessage<StatusReport>", status)
        self.assertIn("public void EncodeDelta(PbpEncoder enc, StatusReport previous)", status)
        self.assertIn("public void ApplyDelta(PbpDecoder dec, StatusReport previous)", status)
        self.assertIn("PbpDelta.Differs", status)
        # signed 的消息与嵌套类型都不发差分
        self.assertNotIn("PbpDeltaMessage", self.files["Gen/Outer.cs"])
        self.assertNotIn("PbpDeltaMessage", self.files["Gen/Inner.cs"])

    def test_enum_generates_constants_not_csharp_enum(self):
        text = self.files["Gen/Level.cs"]
        self.assertIn("public static class Level", text)
        self.assertIn("public const int LOW = 0;", text)
        self.assertIn("public const int HIGH = 2;", text)
        self.assertNotIn("enum Level", text)

    def test_size_helpers_use_pascal_case_runtime_calls(self):
        text = self.files["Gen/Outer.cs"]
        self.assertIn("PbpEncoder.Uint8Size()", text)
        # uint16 是定长，sizer 无参；int64 带值
        self.assertIn("PbpEncoder.StringMapSize(counters, static v => PbpEncoder.Uint16Size())", text)
        self.assertIn("PbpEncoder.ListSize(numbers, static v => PbpEncoder.Int64Size(v))", text)

    def test_indentation_is_four_spaces(self):
        text = self.files["Gen/Outer.cs"]
        self.assertIn("    public void Encode(PbpEncoder enc)", text)
        self.assertIn("        enc.WriteString(name);", text)
        self.assertNotIn("\t", text)

    def test_emit_is_deterministic(self):
        again = emit_schema(schema_of(COMPLEX), "t.mdl")
        self.assertEqual(self.files, again)


class GeneratedTreeTest(unittest.TestCase):
    """入库的 runtime-csharp/Gen 必须与当前 MDL 一致（与 Java 侧 codegen.check 同一件事）。"""

    ROOT = "pacc-binary-protocol/runtime-csharp"

    def test_repo_mdl_matches_generated_csharp(self):
        root = codegen.repo_root() / self.ROOT
        problems = []
        expected = {}
        for schema in codegen.load_schemas(codegen.find_mdl_files(None)):
            for rel, content in emit_schema(schema, schema.path).items():
                expected[rel] = content
                path = root / rel
                if not path.exists():
                    problems.append(f"生成物缺失：{rel}")
                elif path.read_text(encoding="utf-8") != content:
                    problems.append(f"生成物与 MDL 不一致：{rel}")
        self.assertEqual([], problems)

    def test_no_stale_generated_files(self):
        root = codegen.repo_root() / self.ROOT
        expected = set()
        for schema in codegen.load_schemas(codegen.find_mdl_files(None)):
            expected.update(emit_schema(schema, schema.path))
        actual = {f"Gen/{p.name}" for p in (root / "Gen").glob("*.cs")}
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()