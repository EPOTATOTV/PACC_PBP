"""MDL 语义校验测试：每条校验都对应设计文档里的一条约束。"""

import unittest

from pbpgen import model, parser
from pbpgen.lexer import MdlSyntaxError


def build(body: str, package_line: str = "package com.example.mdl;") -> model.Schema:
    source = f'syntax = "pbp1";\n{package_line}\n{body}\n'
    return model.build_schema(parser.parse_source(source, "t.mdl"))


def build_error(test: unittest.TestCase, body: str, package_line: str = "package com.example.mdl;") -> str:
    with test.assertRaises(MdlSyntaxError) as ctx:
        build(body, package_line)
    return str(ctx.exception)


class ValidSchemaTest(unittest.TestCase):

    def test_java_package_option_wins(self):
        schema = build(
            'option java_package = "com.example.gen";\nmessage M {\n 0x0100: id\n string a = 1;\n}',
            package_line="package com.example.mdl;")
        self.assertEqual("com.example.gen", schema.java_package)
        self.assertEqual(1, len(schema.messages))

    def test_package_falls_back_when_no_option(self):
        schema = build('message M {\n string a = 1;\n}')
        self.assertEqual("com.example.mdl", schema.java_package)

    def test_fields_are_sorted_by_number(self):
        schema = build(
            "message M {\n"
            " string c = 30;\n"
            " string a = 10;\n"
            " string b = 20;\n"
            "}")
        self.assertEqual([10, 20, 30], [f.number for f in schema.messages[0].fields])

    def test_java_names(self):
        schema = build("message M {\n int64 ts_ms = 1;\n string a = 2;\n}")
        by_number = {f.number: f for f in schema.messages[0].fields}
        self.assertEqual("TsMs", by_number[1].java_name)
        self.assertEqual("tsMs", by_number[1].field_name)
        self.assertEqual("A", by_number[2].java_name)

    def test_message_without_id_is_not_framed(self):
        schema = build("message Inner {\n string a = 1;\n}")
        self.assertFalse(schema.messages[0].framed)
        self.assertIsNone(schema.messages[0].message_id)
        self.assertFalse(schema.messages[0].signed)

    def test_signed_message_resolves_timestamp_field(self):
        schema = build(
            "message M {\n"
            " 0x0123: id\n"
            " option signed = true;\n"
            " option frame_timestamp = ts_ms;\n"
            " int64 ts_ms = 1;\n"
            " string note = 2; // optional\n"
            "}")
        message = schema.messages[0]
        self.assertTrue(message.framed)
        self.assertTrue(message.signed)
        self.assertEqual("ts_ms", message.frame_timestamp_field.name)
        self.assertEqual(1, message.optional_field_count)

    def test_enum_resolves_to_int(self):
        schema = build(
            "enum E {\n A = 0;\n B = 1;\n}\n"
            "message M {\n E level = 1;\n}")
        field = schema.messages[0].fields[0]
        self.assertEqual("enum", field.value_type.kind)
        self.assertEqual("int", field.value_type.java)
        self.assertEqual("writeEnum", field.value_type.writer)

    def test_id_range_label(self):
        self.assertIn("双向", model.id_range_label(0x2001))
        self.assertIn("预留", model.id_range_label(0x3000))
        self.assertIn("客户端 → 服务端", model.id_range_label(0x0100))


class SchemaErrorTest(unittest.TestCase):

    def test_missing_package_and_option(self):
        self.assertIn("缺少 package", build_error(self, "message M {\n string a = 1;\n}", package_line=""))

    def test_bad_syntax_version(self):
        with self.assertRaises(MdlSyntaxError) as ctx:
            model.build_schema(parser.parse_source(
                'syntax = "proto3";\npackage a.b;\nmessage M {\n string a = 1;\n}', "t.mdl"))
        self.assertIn("syntax 必须是", str(ctx.exception))

    def test_invalid_java_package(self):
        # package 声明走词法（每段必须是标识符），所以不合法包名要靠 option 传字符串才碰得到校验
        self.assertIn("Java 包名不合法", build_error(self, 'message M {\n string a = 1;\n}',
                                                 package_line='option java_package = "9bad";'))

    def test_duplicate_type_name(self):
        self.assertIn("重复声明", build_error(self, "message M {\n string a = 1;\n}\nenum M {\n A = 0;\n}"))

    def test_unknown_type(self):
        self.assertIn("未知类型", build_error(self, "message M {\n Widget a = 1;\n}"))

    def test_duplicate_message_id(self):
        self.assertIn("已被", build_error(self,
            "message A {\n 0x0100: id\n string a = 1;\n}\n"
            "message B {\n 0x0100: id\n string b = 1;\n}"))

    def test_reserved_id_range_rejected(self):
        self.assertIn("预留消息 ID", build_error(self, "message A {\n 0x3000: id\n string a = 1;\n}"))

    def test_message_id_over_16_bits(self):
        self.assertIn("超出 16 位", build_error(self, "message A {\n 0x10000: id\n string a = 1;\n}"))

    def test_field_number_must_start_at_one(self):
        self.assertIn("编号必须从 1 起", build_error(self, "message M {\n string a = 0;\n}"))

    def test_field_number_collision(self):
        self.assertIn("撞车", build_error(self, "message M {\n string a = 1;\n string b = 1;\n}"))

    def test_field_number_hitting_reserved(self):
        self.assertIn("保留编号", build_error(self, "message M {\n reserved 2;\n string a = 2;\n}"))

    def test_field_names_colliding_after_camel_case(self):
        self.assertIn("转成 Java 名后撞车", build_error(self, "message M {\n string foo_bar = 1;\n string fooBar = 2;\n}"))

    def test_optional_on_non_nullable_scalar(self):
        self.assertIn("不支持可空", build_error(self, "message M {\n uint8 a = 1; // optional\n}"))

    def test_optional_and_repeated_together(self):
        self.assertIn("不能同时是 repeated 与 optional",
                      build_error(self, "message M {\n repeated string a = 1; // optional\n}"))

    def test_map_key_cannot_be_message(self):
        self.assertIn("键不能是消息类型", build_error(self,
            "message Inner {\n string a = 1;\n}\n"
            "message Outer {\n map<Inner, string> m = 1;\n}"))

    def test_map_cannot_be_repeated(self):
        self.assertIn("不能同时是 repeated", build_error(self, "message M {\n repeated map<string, int32> m = 1;\n}"))

    def test_map_cannot_be_optional(self):
        self.assertIn("不能是 optional", build_error(self, "message M {\n map<string, int32> m = 1; // optional\n}"))

    def test_enum_without_values(self):
        self.assertIn("没有任何取值", build_error(self, "enum E {\n}\nmessage M {\n E e = 1;\n}"))

    def test_enum_negative_value(self):
        # 词法层就把 '-' 拦下了，模型里的"取值不能为负"是第二道防线
        self.assertIn("不认识的字符", build_error(self, "enum E {\n A = -1;\n}\nmessage M {\n E e = 1;\n}"))

    def test_enum_duplicate_number(self):
        self.assertIn("撞车", build_error(self, "enum E {\n A = 0;\n B = 0;\n}\nmessage M {\n E e = 1;\n}"))

    def test_signed_requires_message_id(self):
        self.assertIn("没有消息 ID", build_error(self,
            "message M {\n option signed = true;\n option frame_timestamp = ts_ms;\n int64 ts_ms = 1;\n}"))

    def test_signed_requires_frame_timestamp_option(self):
        self.assertIn("必须同时用 option frame_timestamp", build_error(self,
            "message M {\n 0x0123: id\n option signed = true;\n int64 ts_ms = 1;\n}"))

    def test_frame_timestamp_must_point_at_existing_field(self):
        self.assertIn("不存在", build_error(self,
            "message M {\n 0x0123: id\n option signed = true;\n option frame_timestamp = missing;\n int64 ts_ms = 1;\n}"))

    def test_frame_timestamp_must_be_64_bit(self):
        self.assertIn("必须是 int64/uint64", build_error(self,
            "message M {\n 0x0123: id\n option signed = true;\n option frame_timestamp = when;\n int32 when = 1;\n}"))

    def test_duplicate_message_option(self):
        self.assertIn("重复声明", build_error(self,
            "message M {\n 0x0123: id\n option signed = true;\n option signed = false;\n int64 ts_ms = 1;\n}"))

    def test_all_errors_are_reported_together(self):
        text = build_error(self, "message M {\n string a = 0;\n Widget b = 0;\n}")
        self.assertIn("编号必须从 1 起", text)
        self.assertIn("未知类型", text)


if __name__ == "__main__":
    unittest.main()