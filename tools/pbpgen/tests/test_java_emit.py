"""Java emitter 测试：输出形态、确定性与「生成物能编译」。

最后一项是这套测试里最有价值的一条：emitter 全靠字符串拼接，手写断言只能盯住
自己想到的地方，真拿 javac 编一遍才能发现类型不匹配、方法引用签名不对这类问题。
没装 JDK 时跳过，不让本地环境差异变成红灯。
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from pbpgen import codegen, model, parser
from pbpgen.emit import emit_schema

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

    def test_output_paths_follow_java_package(self):
        self.assertEqual(
            {
                "com/example/gen/Level.java",
                "com/example/gen/Inner.java",
                "com/example/gen/Outer.java",
                "com/example/gen/StatusReport.java",
            },
            set(self.files),
        )

    def test_header_points_back_at_mdl(self):
        text = self.files["com/example/gen/Outer.java"]
        self.assertIn("本文件由 tools/pbpgen 生成，请勿手改。", text)
        self.assertIn("// 源定义：t.mdl", text)
        self.assertIn("package com.example.gen;", text)

    def test_contract_api_present(self):
        text = self.files["com/example/gen/Outer.java"]
        for fragment in (
            "public final class Outer implements PbpMessage",
            "public static final int MESSAGE_ID = 0x0123;",
            "public static Builder newBuilder()",
            "public Builder toBuilder()",
            "public static Outer parseFrom(byte[] raw)",
            "public byte[] toByteArray()",
            "public byte[] signingInput()",
            "public Builder setSignatureBytes(byte[] value)",
            "public int getSigVersion()",
        ):
            self.assertIn(fragment, text)

    def test_nested_message_has_no_message_id(self):
        inner = self.files["com/example/gen/Inner.java"]
        self.assertNotIn("MESSAGE_ID", inner)
        self.assertIn("return 0;", inner)
        self.assertNotIn("import com.potatotv.pbp.PbpFrame;", inner)

    def test_collection_fields_use_boxed_types(self):
        text = self.files["com/example/gen/Outer.java"]
        self.assertIn("private List<Long> numbers", text)
        self.assertIn("private List<Integer> levels", text)  # 枚举在 Java 侧就是 int
        self.assertIn("private List<Inner> items", text)     # 消息类型不装箱
        self.assertIn("private Map<String, Integer> counters", text)
        self.assertIn("private Map<Integer, String> labels", text)
        self.assertIn("return Collections.unmodifiableList(", text)
        self.assertIn("return Collections.unmodifiableMap(", text)

    def test_optional_fields_default_to_null(self):
        text = self.files["com/example/gen/Outer.java"]
        self.assertIn("public static final int OPTIONAL_FIELD_COUNT = 2;", text)
        self.assertIn("enc.writeOptionalString(note);", text)
        self.assertIn("enc.writeOptionalBytes(blob);", text)
        self.assertIn("note = dec.readOptionalString();", text)
        self.assertIn("blob = dec.readOptionalBytes();", text)

    def test_trailing_field_decodes_with_remaining_guard(self):
        # 末尾字段自动 optional（设计文档 §3.6.2）：整帧消息的最后一个字段带"读完取默认值"的保护
        outer = self.files["com/example/gen/Outer.java"]
        self.assertIn("sigVersion = dec.remaining() > 0 ? dec.readUInt8() : 0;", outer)
        # 嵌套类型不做：内联编码里没有"读完了"这个信号
        inner = self.files["com/example/gen/Inner.java"]
        self.assertIn("weight = dec.readInt32();", inner)

    def test_delta_methods_only_for_unsigned_framed_messages(self):
        status = self.files["com/example/gen/StatusReport.java"]
        self.assertIn("implements PbpMessage, PbpDeltaMessage<StatusReport>", status)
        self.assertIn("public void encodeDelta(PbpEncoder enc, StatusReport previous) {", status)
        self.assertIn("public void applyDelta(PbpDecoder dec, StatusReport previous) {", status)
        # 带 signed 的消息不发差分方法：签名与基线混用的失败面太大
        self.assertNotIn("PbpDeltaMessage", self.files["com/example/gen/Outer.java"])
        # 嵌套类型没有帧，也就没有差分
        self.assertNotIn("PbpDeltaMessage", self.files["com/example/gen/Inner.java"])

    def test_enum_generates_constants_not_java_enum(self):
        text = self.files["com/example/gen/Level.java"]
        self.assertIn("public static final int LOW = 0;", text)
        self.assertIn("public static final int HIGH = 2;", text)
        self.assertNotIn("enum Level", text)

    def test_message_reference_imports_only_what_is_used(self):
        inner = self.files["com/example/gen/Inner.java"]
        self.assertNotIn("java.util.ArrayList", inner)
        self.assertNotIn("java.util.HexFormat", inner)
        outer = self.files["com/example/gen/Outer.java"]
        self.assertIn("import java.util.ArrayList;", outer)
        self.assertIn("import java.util.HexFormat;", outer)

    def test_imports_are_sorted_and_unique(self):
        text = self.files["com/example/gen/Outer.java"]
        java_imports = [line for line in text.splitlines() if line.startswith("import java.")]
        self.assertEqual(sorted(java_imports), java_imports)
        self.assertEqual(len(java_imports), len(set(java_imports)))

    def test_indentation_is_four_spaces(self):
        text = self.files["com/example/gen/Outer.java"]
        self.assertIn("    public static Builder newBuilder() {", text)
        self.assertIn("        return new Builder();", text)
        self.assertNotIn("\t", text)

    def test_emit_is_deterministic(self):
        again = emit_schema(schema_of(COMPLEX), "t.mdl")
        self.assertEqual(self.files, again)

    def test_repo_mdl_matches_generated_output(self):
        # 生成物入库，CI 的 --check 就是靠这条；这里在单测里先把同一件事盯住
        self.assertEqual([], codegen.check())


class CompileTest(unittest.TestCase):
    """真拿 javac 编一遍生成物（含 runtime-java 源码）。"""

    RUNTIME_SRC = codegen.repo_root() / "pacc-binary-protocol/runtime-java/src/main/java"

    @classmethod
    def setUpClass(cls):
        cls.javac = _find_javac()
        if cls.javac is None:
            raise unittest.SkipTest("找不到 javac，跳过生成物编译校验")

    def test_generated_sources_compile_with_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            files = emit_schema(schema_of(COMPLEX), "t.mdl")
            sources = []
            for rel, content in files.items():
                target = root / "gen" / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                sources.append(target)
            sources.extend(sorted((self.RUNTIME_SRC / "com/potatotv/pbp").glob("*.java")))

            classes = root / "classes"
            classes.mkdir()
            result = subprocess.run(
                [self.javac, "-Xlint:all", "-d", str(classes), *[str(p) for p in sources]],
                capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(0, result.returncode,
                             f"javac 失败：\n{result.stdout}\n{result.stderr}")


def _find_javac():
    found = shutil.which("javac")
    if found:
        return found
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        name = "javac.exe" if os.name == "nt" else "javac"
        candidate = pathlib.Path(java_home) / "bin" / name
        if candidate.exists():
            return str(candidate)
    return None


if __name__ == "__main__":
    unittest.main()