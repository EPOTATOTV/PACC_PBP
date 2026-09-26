"""PBP Python 运行时与 test-vectors/interop.txt 的互操作与自洽测试。

向量由 Java 参考实现导出（PbpInteropVectorsTest），Python 侧能逐字节复现才算互操作成立。
Python 运行时不实现 zstd，涉及压缩的 big_frame_compressed 一条跳过，理由见对应测试。
"""

import pathlib
import py_compile
import tempfile
import unittest

import pbp_gen
from pbp_gen import (
    ApmSnapshot,
    DetectionEvent,
    DetectionReport,
    PaccEnvelope,
    PbpCodec,
    PbpCrypto,
    PbpDecoder,
    PbpDeltaChain,
    PbpEncoder,
    PbpErrorCode,
    PbpException,
    PbpFrame,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS_PATH = REPO_ROOT / "pacc-binary-protocol" / "test-vectors" / "interop.txt"

TS_MS = 1_700_000_000_000


def load_vectors():
    vectors = {}
    for line in VECTORS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        vectors[key.strip()] = value.strip()
    return vectors


VECTORS = load_vectors()


def envelope():
    env = PaccEnvelope()
    env.type = "inspect_offer"
    env.ts_ms = TS_MS
    env.nonce = "0123456789abcdef"
    env.session_id = "sess-1"
    env.pteid = "PT0001"
    env.payload_json = "{}"
    env.sig_version = 1
    return env


def codec_report():
    event = DetectionEvent()
    event.event_type = 2
    event.confidence = 0.75
    event.timestamp = 1_700_000_000_001
    event.evidence = {"module": "pacc-probe".encode("utf-8")}
    event.detail = "内存段校验不一致"

    apm = ApmSnapshot()
    apm.cpu_usage = 23.5
    apm.memory_usage_kb = 450_000
    apm.fps = 120.0
    apm.detection_latency_ms = 12
    apm.active_rules = 50
    apm.custom_metrics = {"gc_ms": 3.5}

    report = DetectionReport()
    report.pteid = "PT0001"
    report.timestamp = -1_700_000_000_000
    report.client_version = "5.4.0-验证"
    report.platform = "windows"
    report.events = [event]
    report.apm = apm
    report.signature = bytes(range(1, 33))
    return report


def status_report(ts, cpu_percent, rules, gc_ms):
    event = DetectionEvent()
    event.event_type = 2
    event.confidence = 0.87
    event.timestamp = 900
    event.evidence = {"module": b"pacc-probe"}
    event.detail = "可疑进程"

    apm = ApmSnapshot()
    apm.cpu_usage = cpu_percent / 100.0
    apm.memory_usage_kb = 450_000
    apm.fps = 120.0
    apm.detection_latency_ms = 12
    apm.active_rules = rules
    apm.custom_metrics = {"gc_ms": gc_ms}

    report = DetectionReport()
    report.pteid = "PT0001"
    report.timestamp = ts
    report.client_version = "5.4.0"
    report.platform = "windows"
    report.events = [event]
    report.apm = apm
    return report


class InteropVectorTest(unittest.TestCase):
    """逐字节复现 Java 参考实现的向量。"""

    def test_envelope_payload_and_frame(self):
        env = envelope()
        self.assertEqual(VECTORS["envelope_payload"], PbpCodec.payload_of(env).hex())
        self.assertEqual(VECTORS["envelope_frame"], env.to_bytes().hex())

    def test_envelope_signed_frame(self):
        env = envelope()
        # secret_hex_text 是那串文本的 UTF-8 字节的十六进制，fromhex 出来的就是 key 本身
        secret = bytes.fromhex(VECTORS["secret_hex_text"])
        signature = PbpCrypto.hmac_sha256(secret, env.signing_input())
        frame = PbpCodec.frame_of(env, env.ts_ms).with_signature(signature)
        self.assertEqual(VECTORS["envelope_signed_frame"], frame.encode().hex())

    def test_envelope_parse_back(self):
        raw = bytes.fromhex(VECTORS["envelope_signed_frame"])
        env = PaccEnvelope.parse_from(raw)
        self.assertEqual("inspect_offer", env.type)
        self.assertEqual(TS_MS, env.ts_ms)
        self.assertEqual("PT0001", env.pteid)
        self.assertEqual(bytes.fromhex(VECTORS["envelope_signed_frame"])[-32:], env.signature)

    def test_codec_payload(self):
        report = codec_report()
        payload = PbpCodec.payload_of(report)
        self.assertEqual(VECTORS["codec_payload"], payload.hex())
        decoded = DetectionReport()
        decoded.decode(PbpDecoder(payload))
        self.assertEqual(-1_700_000_000_000, decoded.timestamp)
        self.assertEqual("5.4.0-验证", decoded.client_version)
        self.assertEqual("内存段校验不一致", decoded.events[0].detail)
        self.assertEqual({"module": b"pacc-probe"}, decoded.events[0].evidence)
        self.assertAlmostEqual(23.5, decoded.apm.cpu_usage, places=5)
        self.assertEqual(bytes(range(1, 33)), decoded.signature)

    def test_delta_chain(self):
        msg1 = status_report(2_000, 20, 50, 3.5)
        msg2 = status_report(2_001, 24, 50, 4.5)

        sender = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        frame1 = sender.encode(msg1, 2_000)
        frame2 = sender.encode(msg2, 2_001)
        self.assertFalse(frame1.delta())
        self.assertTrue(frame2.delta())
        self.assertEqual(VECTORS["delta_frame1"], frame1.encode().hex())
        self.assertEqual(VECTORS["delta_frame2"], frame2.encode().hex())

        receiver = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        got1 = receiver.decode(frame1.encode())
        got2 = receiver.decode(frame2.encode())
        self.assertEqual(2_000, got1.timestamp)
        self.assertEqual(2_001, got2.timestamp)
        self.assertAlmostEqual(0.24, got2.apm.cpu_usage, places=5)
        self.assertAlmostEqual(4.5, got2.apm.custom_metrics["gc_ms"], places=5)
        # 差分回放的结果重编码后必须与 Java 的完整载荷向量一致
        self.assertEqual(VECTORS["delta_payload2"], PbpCodec.payload_of(got2).hex())

    @unittest.skip("Python 运行时不实现 zstd：编码不压缩，压缩互操作由 Java/TS/Rust/C# 四端覆盖")
    def test_big_frame_compressed(self):
        big = envelope()
        big.type = "inspect_result"
        big.payload_json = "A" * 3000
        self.assertEqual(VECTORS["big_frame_compressed"], big.to_bytes().hex())

    def test_compressed_frame_is_rejected_not_silently_decoded(self):
        # 不实现解压时，声明压缩的帧必须显式失败，不能把压缩字节当明文载荷解析
        frame = PbpFrame.of(0x2001, 0, b"payload").with_flag(PbpFrame.FLAG_COMPRESSED)
        with self.assertRaises(PbpException) as ctx:
            PbpCodec.payload_of_frame(frame)
        self.assertEqual(PbpErrorCode.UNSUPPORTED, ctx.exception.code)


class CoreSelfCheckTest(unittest.TestCase):
    """不依赖向量的自洽检查：覆盖 core 的隐蔽行为。"""

    def test_frame_header_layout(self):
        raw = bytes.fromhex(VECTORS["envelope_frame"])
        self.assertEqual(b"PB", raw[0:2])
        self.assertEqual(0x01, raw[2])
        self.assertEqual(0x00, raw[3])
        self.assertEqual(0x2001, raw[4] | (raw[5] << 8))
        frame = PbpFrame.parse(raw)
        self.assertEqual(0x2001, frame.message_id)
        self.assertEqual(TS_MS, frame.timestamp_ms)
        self.assertEqual(len(bytes.fromhex(VECTORS["envelope_payload"])), frame.payload_length())

    def test_signing_input_covers_header_and_payload(self):
        env = envelope()
        frame = PbpCodec.frame_of(env, env.ts_ms)
        signing = frame.signing_input()
        self.assertEqual(PbpFrame.FLAG_SIGNED, signing[3])
        self.assertEqual(frame.payload, signing[PbpFrame.HEADER_SIZE:])
        # 未签名的实际帧头 flags 为 0，签名输入用 FLAG_SIGNED 置位后的形态
        self.assertEqual(0x00, frame.encode()[3])

    def test_frame_rejects_bad_magic_version_and_flags(self):
        raw = bytearray(PbpFrame.of(0x2001, 0, b"x").encode())

        bad = bytearray(raw)
        bad[0] = 0x00
        with self.assertRaises(PbpException) as ctx:
            PbpFrame.parse(bytes(bad))
        self.assertEqual(PbpErrorCode.BAD_MAGIC, ctx.exception.code)

        bad = bytearray(raw)
        bad[2] = PbpFrame.VERSION + 1
        with self.assertRaises(PbpException) as ctx:
            PbpFrame.parse(bytes(bad))
        self.assertEqual(PbpErrorCode.BAD_VERSION, ctx.exception.code)

        bad = bytearray(raw)
        bad[3] = 0x10
        with self.assertRaises(PbpException) as ctx:
            PbpFrame.parse(bytes(bad))
        self.assertEqual(PbpErrorCode.UNSUPPORTED_FLAG, ctx.exception.code)

        bad = bytearray(raw)
        bad[3] = PbpFrame.FLAG_ENCRYPTED
        with self.assertRaises(PbpException) as ctx:
            PbpFrame.parse(bytes(bad))
        self.assertEqual(PbpErrorCode.UNSUPPORTED_FLAG, ctx.exception.code)

    def test_decoder_rejects_truncation(self):
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(b"").read_bool()
        self.assertEqual(PbpErrorCode.TRUNCATED, ctx.exception.code)
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(b"\x05ab").read_string()
        self.assertEqual(PbpErrorCode.TRUNCATED, ctx.exception.code)

    def test_decoder_rejects_invalid_utf8(self):
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(b"\x02\xff\xfe").read_string()
        self.assertEqual(PbpErrorCode.BAD_FORMAT, ctx.exception.code)

    def test_decoder_rejects_bad_bool_and_oversized_collection(self):
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(b"\x02").read_bool()
        self.assertEqual(PbpErrorCode.BAD_FORMAT, ctx.exception.code)

        enc = PbpEncoder()
        enc.write_uint32((1 << 20) + 1)
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(enc.to_bytes()).read_list(PbpDecoder.read_uint8)
        self.assertEqual(PbpErrorCode.BAD_FORMAT, ctx.exception.code)

    def test_decoder_rejects_overlong_varint(self):
        with self.assertRaises(PbpException) as ctx:
            PbpDecoder(b"\x80" * 11).read_uint64()
        self.assertEqual(PbpErrorCode.BAD_VARINT, ctx.exception.code)

    def test_zigzag_roundtrip(self):
        for value in (0, -1, 1, -2, 2, -123456789, 123456789, -(1 << 31) + 1):
            enc = PbpEncoder()
            enc.write_int32(value)
            self.assertEqual(value, PbpDecoder(enc.to_bytes()).read_int32())
        for value in (0, -1, 1, -2, -(1 << 62), (1 << 62)):
            enc = PbpEncoder()
            enc.write_int64(value)
            self.assertEqual(value, PbpDecoder(enc.to_bytes()).read_int64())
        enc = PbpEncoder()
        enc.write_int32(-1)
        enc.write_int64(-1)
        self.assertEqual(b"\x01\x01", enc.to_bytes())

    def test_multibyte_utf8_roundtrip(self):
        text = "内存段校验不一致 ✅ 数据"
        enc = PbpEncoder()
        enc.write_string(text)
        self.assertEqual(text, PbpDecoder(enc.to_bytes()).read_string())

    def test_core_list_and_map_roundtrip(self):
        enc = PbpEncoder()
        enc.write_list([1, -2, 3], PbpEncoder.write_int64)
        enc.write_map({2: "b", 1: "a"}, PbpEncoder.write_int32, PbpEncoder.write_string)
        enc.write_string_map({"k": b"\x00\x01"}, PbpEncoder.write_bytes)
        dec = PbpDecoder(enc.to_bytes())
        self.assertEqual([1, -2, 3], dec.read_list(PbpDecoder.read_int64))
        self.assertEqual({2: "b", 1: "a"}, dec.read_map(PbpDecoder.read_int32, PbpDecoder.read_string))
        self.assertEqual({"k": b"\x00\x01"}, dec.read_string_map(PbpDecoder.read_bytes))

    def test_optional_presence_roundtrip(self):
        report = DetectionReport()
        report.pteid = "PT0001"
        report.client_version = "v"
        report.platform = "windows"
        first = DetectionEvent()
        first.event_type = 1
        first.evidence = {"a": b"\x01", "b": b"\x02"}
        second = DetectionEvent()
        second.event_type = 2
        second.evidence = {}
        report.events = [first, second]
        report.apm = None

        decoded = DetectionReport()
        decoded.decode(PbpDecoder(PbpCodec.payload_of(report)))
        self.assertIsNone(decoded.apm)
        self.assertEqual(2, len(decoded.events))
        self.assertEqual({"a": b"\x01", "b": b"\x02"}, decoded.events[0].evidence)
        self.assertIsNone(decoded.events[0].detail)

        report.apm = ApmSnapshot()
        report.apm.active_rules = 7
        decoded = DetectionReport()
        decoded.decode(PbpDecoder(PbpCodec.payload_of(report)))
        self.assertIsNotNone(decoded.apm)
        self.assertEqual(7, decoded.apm.active_rules)

    def test_trailing_field_defaults_when_payload_ends(self):
        # 模拟旧端载荷：末尾字段（signature）没发，解码取默认值而不是报错
        enc = PbpEncoder()
        enc.write_string("PT0001")
        enc.write_int64(0)
        enc.write_string("")
        enc.write_string("")
        enc.write_message_list([])
        enc.write_optional_message(None)
        report = DetectionReport()
        report.decode(PbpDecoder(enc.to_bytes()))
        self.assertEqual(b"", report.signature)

        # 新端多发的尾部字节应被忽略（向前兼容）
        extended = enc.to_bytes() + b"\x00"
        decoded = DetectionReport()
        decoded.decode(PbpDecoder(extended))
        self.assertEqual(b"", decoded.signature)

    def test_delta_chain_sends_full_after_ten_consecutive(self):
        sender = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        frames = [sender.encode(status_report(2_000 + i, 20, 50, 3.5), 2_000 + i) for i in range(12)]
        self.assertFalse(frames[0].delta())
        for i in range(1, 11):
            self.assertTrue(frames[i].delta(), "第 %d 条应为差分" % (i + 1))
        self.assertFalse(frames[11].delta(), "连续 10 条差分后必须回到完整消息")
        self.assertEqual(PbpDeltaChain.MAX_CONSECUTIVE, 10)

    def test_delta_decode_requires_baseline(self):
        sender = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        sender.encode(status_report(2_000, 20, 50, 3.5), 2_000)
        delta = sender.encode(status_report(2_001, 24, 50, 4.5), 2_001)
        receiver = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        with self.assertRaises(PbpException) as ctx:
            receiver.decode(delta.encode())
        self.assertEqual(PbpErrorCode.BAD_FORMAT, ctx.exception.code)

    def test_delta_decode_rejects_more_than_ten_consecutive(self):
        sender = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        sent = [sender.encode(status_report(2_000 + i, 20, 50, 3.5), 2_000 + i) for i in range(12)]
        receiver = PbpDeltaChain(DetectionReport.MESSAGE_ID, DetectionReport)
        for frame in sent[:11]:
            receiver.decode(frame.encode())
        with self.assertRaises(PbpException) as ctx:
            receiver.decode(sent[1].encode())
        self.assertEqual(PbpErrorCode.BAD_FORMAT, ctx.exception.code)

    def test_all_generated_modules_compile(self):
        package_dir = pathlib.Path(pbp_gen.__file__).resolve().parent
        sources = sorted(package_dir.glob("*.py"))
        self.assertTrue(sources)
        with tempfile.TemporaryDirectory() as tmp:
            for source in sources:
                target = pathlib.Path(tmp) / (source.stem + ".pyc")
                py_compile.compile(str(source), cfile=str(target), doraise=True)


if __name__ == "__main__":
    unittest.main()