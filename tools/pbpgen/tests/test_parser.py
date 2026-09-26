"""MDL 词法与语法分析测试。"""

import unittest

from pbpgen import parser
from pbpgen.lexer import MdlSyntaxError

BASIC = '''
// 顶部注释
syntax = "pbp1";
package com.example.mdl;
option java_package = "com.example.gen";

enum Level {
    LOW = 0;
    HIGH = 2;
}

message Inner {
    string label = 1;
}

message Outer {
    0x0123: id
    option signed = true;
    option frame_timestamp = ts_ms;
    reserved 7, 8;

    string name = 1;
    int64 ts_ms = 2;
    string note = 3;  // optional 说明文字
    repeated Inner items = 4;
    map<string, uint16> counters = 5;
    Inner nested = 6;
}
'''


class ParseFileTest(unittest.TestCase):

    def setUp(self):
        self.node = parser.parse_source(BASIC, "basic.mdl")

    def test_file_level_declarations(self):
        self.assertEqual("pbp1", self.node.syntax)
        self.assertEqual("com.example.mdl", self.node.package)
        self.assertEqual("com.example.gen", self.node.option("java_package").value)

    def test_enum_values(self):
        self.assertEqual(1, len(self.node.enums))
        level = self.node.enums[0]
        self.assertEqual("Level", level.name)
        self.assertEqual([("LOW", 0), ("HIGH", 2)], [(v.name, v.number) for v in level.values])

    def test_message_id_needs_no_semicolon(self):
        outer = self._message("Outer")
        self.assertEqual(0x0123, outer.message_id)
        self.assertEqual(["signed", "frame_timestamp"], [o.name for o in outer.options])
        self.assertEqual([7, 8], list(outer.reserved))

    def test_field_kinds(self):
        outer = self._message("Outer")
        by_name = {f.name: f for f in outer.fields}
        self.assertFalse(by_name["name"].repeated)
        self.assertIsNone(by_name["name"].type.map_key)
        self.assertTrue(by_name["items"].repeated)
        self.assertEqual("Inner", by_name["items"].type.name)
        self.assertEqual("string", by_name["counters"].type.map_key.name)
        self.assertEqual("uint16", by_name["counters"].type.name)
        self.assertEqual("Inner", by_name["nested"].type.name)

    def test_optional_marker_taken_from_same_line_comment(self):
        outer = self._message("Outer")
        by_name = {f.name: f for f in outer.fields}
        self.assertTrue(by_name["note"].optional)
        self.assertFalse(by_name["name"].optional)

    def test_line_numbers_are_tracked(self):
        outer = self._message("Outer")
        name = next(f for f in outer.fields if f.name == "name")
        self.assertGreater(name.line, outer.line)

    def _message(self, name):
        return next(m for m in self.node.messages if m.name == name)


class OptionalMarkerTest(unittest.TestCase):

    def test_comment_on_own_line_is_not_a_marker(self):
        node = parser.parse_source(
            'syntax = "pbp1";\npackage a.b;\nmessage M {\n  string a = 1;\n  // optional\n  string b = 2;\n}\n',
            "x.mdl")
        fields = {f.name: f for f in node.messages[0].fields}
        self.assertFalse(fields["a"].optional)
        self.assertFalse(fields["b"].optional)

    def test_marker_requires_optional_as_first_word(self):
        node = parser.parse_source(
            'syntax = "pbp1";\npackage a.b;\nmessage M {\n  string a = 1; // not optional\n}\n',
            "x.mdl")
        self.assertFalse(node.messages[0].fields[0].optional)

    def test_bare_identifier_option_value(self):
        # `option frame_timestamp = ts_ms;` 引用字段名，按字符串取值
        node = parser.parse_source(
            'syntax = "pbp1";\npackage a.b;\nmessage M {\n  option frame_timestamp = ts_ms;\n  int64 ts_ms = 1;\n}\n',
            "x.mdl")
        self.assertEqual("ts_ms", node.messages[0].options[0].value)


class ParseErrorTest(unittest.TestCase):

    def _error(self, source):
        with self.assertRaises(MdlSyntaxError) as ctx:
            parser.parse_source(source, "bad.mdl")
        self.assertIn("bad.mdl", str(ctx.exception))
        return str(ctx.exception)

    def test_unknown_character(self):
        self.assertIn("不认识的字符", self._error('syntax = "pbp1";\npackage a;\nmessage M { string a = 1; }\n@'))

    def test_unclosed_string(self):
        self.assertIn("字符串没有闭合", self._error('syntax = "pbp1;'))

    def test_string_with_newline(self):
        self.assertIn("字符串里不能出现换行", self._error('syntax = "pbp1\n";\n'))

    def test_unsupported_escape(self):
        self.assertIn("不支持的转义", self._error('syntax = "pbp1";\npackage a;\noption x = "a\\nb";\n'))

    def test_unclosed_block_comment(self):
        self.assertIn("块注释没有闭合", self._error('syntax = "pbp1";\n/* 没关\n'))

    def test_hex_without_digits(self):
        self.assertIn("0x 后面没有十六进制数字", self._error('syntax = "pbp1";\npackage a;\nmessage M {\n 0x: id\n}\n'))

    def test_syntax_value_must_be_string(self):
        self.assertIn("syntax 的值必须是字符串", self._error("syntax = pbp1;\n"))

    def test_duplicate_syntax(self):
        self.assertIn("syntax 重复声明", self._error('syntax = "pbp1";\nsyntax = "pbp1";\n'))

    def test_unknown_file_level_keyword(self):
        self.assertIn("文件级不认识的关键字", self._error("syntax = \"pbp1\";\nstruct S {}\n"))

    def test_message_not_closed(self):
        self.assertIn("没有闭合", self._error('syntax = "pbp1";\npackage a;\nmessage M {\n string a = 1;\n'))

    def test_field_number_must_be_number(self):
        self.assertIn("期望字段编号", self._error('syntax = "pbp1";\npackage a;\nmessage M {\n string a = ;\n}\n'))

    def test_duplicate_message_id_rejected(self):
        source = ('syntax = "pbp1";\npackage a;\nmessage M {\n 0x0001: id\n 0x0002: id\n}\n')
        self.assertIn("重复声明消息 ID", self._error(source))

    def test_map_value_cannot_be_map(self):
        source = ('syntax = "pbp1";\npackage a;\nmessage M {\n map<string, map<string, int32>> m = 1;\n}\n')
        self.assertIn("map 的值类型不能再是 map", self._error(source))


if __name__ == "__main__":
    unittest.main()