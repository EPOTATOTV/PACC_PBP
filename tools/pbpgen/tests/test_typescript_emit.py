"""TypeScript emitter 测试：输出形态与确定性。

只盯字符串拼接的产物，不跑 `python -m pbpgen`（整体接线还没到位），也不调 tsc——
真编译由 runtime-ts 的 npm test 覆盖。
"""

import unittest

from pbpgen import model, parser
from pbpgen.emit.typescript import emit_schema

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

// 不签名 + 带集合字段：差分方法与字节比较路径只有这类消息会走到
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
            {
                "gen/Level.ts",
                "gen/Inner.ts",
                "gen/Outer.ts",
                "gen/StatusReport.ts",
            },
            set(self.files),
        )

    def test_header_points_back_at_mdl(self):
        text = self.files["gen/Outer.ts"]
        self.assertIn("// 本文件由 tools/pbpgen 生成，请勿手改。", text)
        self.assertIn("// 源定义：t.mdl", text)
        self.assertNotIn("package ", text)

    def test_contract_api_present(self):
        text = self.files["gen/Outer.ts"]
        for fragment in (
            "export class Outer implements PbpMessage",
            "static readonly MESSAGE_ID = 0x0123;",
            "static newBuilder(): OuterBuilder",
            "toBuilder(): OuterBuilder",
            "static parseFrom(raw: Uint8Array): Outer",
            "toByteArray(): Uint8Array",
            "signingInput(): Uint8Array",
            "setSignatureBytes(value: Uint8Array | null): this",
            "setSigVersion(value: number): this",
            "tsMs: bigint = 0n;",
        ):
            self.assertIn(fragment, text)

    def test_nested_message_has_no_message_id(self):
        inner = self.files["gen/Inner.ts"]
        self.assertNotIn("MESSAGE_ID", inner)
        self.assertIn("return 0;", inner)
        self.assertNotIn("PbpFrame", inner)

    def test_optional_fields_use_presence_bitmap(self):
        text = self.files["gen/Outer.ts"]
        self.assertIn("static readonly OPTIONAL_FIELD_COUNT = 2;", text)
        self.assertIn("enc.writeOptionalString(this.note);", text)
        self.assertIn("enc.writeOptionalBytes(this.blob);", text)
        self.assertIn("this.note = dec.readOptionalString();", text)
        self.assertIn("this.blob = dec.readOptionalBytes();", text)
        self.assertIn("note: string | null = null;", text)

    def test_trailing_field_decodes_with_remaining_guard(self):
        # 末尾字段自动 optional：整帧消息的最后一个字段带"读完取默认值"的保护
        outer = self.files["gen/Outer.ts"]
        self.assertIn("this.sigVersion = dec.remaining() > 0 ? dec.readUInt8() : 0;", outer)
        status = self.files["gen/StatusReport.ts"]
        self.assertIn("this.tags = dec.remaining() > 0 ? dec.readStringList() : [];", status)
        # 嵌套类型不做：内联编码里没有"读完了"这个信号
        inner = self.files["gen/Inner.ts"]
        self.assertIn("this.weight = dec.readInt32();", inner)

    def test_delta_methods_only_for_unsigned_framed_messages(self):
        status = self.files["gen/StatusReport.ts"]
        self.assertIn("implements PbpMessage, PbpDeltaMessage<StatusReport>", status)
        self.assertIn("encodeDelta(enc: PbpEncoder, previous: StatusReport): void {", status)
        self.assertIn("applyDelta(dec: PbpDecoder, previous: StatusReport): void {", status)
        self.assertIn("enc.writePresence(changed);", status)
        # 带 signed 的消息不发差分方法
        self.assertNotIn("PbpDeltaMessage", self.files["gen/Outer.ts"])
        # 嵌套类型没有帧，也就没有差分
        self.assertNotIn("PbpDeltaMessage", self.files["gen/Inner.ts"])

    def test_enum_generates_constants_not_ts_enum(self):
        text = self.files["gen/Level.ts"]
        self.assertIn("export const Level = {", text)
        self.assertIn("  LOW: 0,", text)
        self.assertIn("  HIGH: 2,", text)
        self.assertIn("} as const;", text)
        self.assertNotIn("enum Level", text)

    def test_collection_and_map_expressions(self):
        text = self.files["gen/Outer.ts"]
        self.assertIn("numbers: bigint[] = [];", text)
        self.assertIn("levels: number[] = [];", text)
        self.assertIn("counters: Map<string, number> = new Map();", text)
        self.assertIn("labels: Map<number, string> = new Map();", text)
        self.assertIn("enc.writeList(this.numbers, (e, v) => e.writeInt64(v));", text)
        self.assertIn("enc.writeStringMap(this.counters, (e, v) => e.writeUInt16(v));", text)
        self.assertIn("PbpEncoder.mapSize(this.labels, PbpEncoder.int32Size, PbpEncoder.stringSize)", text)
        self.assertIn("dec.readMap<number, string>(() => new Map(),", text)
        self.assertIn("dec.readList<number>(() => [], (d) => d.readEnum())", text)

    def test_message_reference_imports_only_what_is_used(self):
        inner = self.files["gen/Inner.ts"]
        self.assertNotIn("PbpCodec", inner)
        self.assertNotIn("PbpCrypto", inner)
        self.assertNotIn("PbpDelta", inner)
        outer = self.files["gen/Outer.ts"]
        self.assertIn('import { PbpCodec } from "../PbpCodec.js";', outer)
        self.assertIn('import { bytesFromHex, bytesToHex } from "../PbpCrypto.js";', outer)
        self.assertIn('import { Inner } from "./Inner.js";', outer)
        self.assertIn('import type { PbpMessage } from "../PbpMessage.js";', outer)
        self.assertNotIn('import { Inner } from "./Inner.js";', inner)

    def test_imports_are_sorted_and_unique(self):
        text = self.files["gen/Outer.ts"]
        imports = [line for line in text.splitlines() if line.startswith("import ")]
        self.assertEqual(sorted(imports), imports)
        self.assertEqual(len(imports), len(set(imports)))

    def test_indentation_is_two_spaces(self):
        text = self.files["gen/Outer.ts"]
        self.assertIn("  static newBuilder(): OuterBuilder {", text)
        self.assertIn("    return new OuterBuilder();", text)
        self.assertNotIn("\t", text)

    def test_emit_is_deterministic(self):
        again = emit_schema(schema_of(COMPLEX), "t.mdl")
        self.assertEqual(self.files, again)


if __name__ == "__main__":
    unittest.main()