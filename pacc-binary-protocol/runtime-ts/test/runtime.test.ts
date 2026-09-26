import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { PaccEnvelope } from "../src/gen/PaccEnvelope.js";
import { DetectionReport } from "../src/gen/DetectionReport.js";
import { PbpCodec } from "../src/PbpCodec.js";
import { PbpDeltaChain } from "../src/PbpDeltaChain.js";
import { PbpDecoder } from "../src/PbpDecoder.js";
import { PbpEncoder } from "../src/PbpEncoder.js";
import { PbpFrame } from "../src/PbpFrame.js";
import { compress, decompress } from "../src/PbpZstd.js";
import { codecReport, expectThrow, hex, statusReport, utf8 } from "./support.js";

const MAX = PbpFrame.MAX_PAYLOAD_SIZE;
const BLOCK_MAX = 128 * 1024;

describe("标量与变长字段往返", () => {
  it("Bool / 定长整数 / VarInt / ZigZag / 浮点 / UTF-8 / bytes", () => {
    const enc = new PbpEncoder();
    enc.writeBool(true);
    enc.writeInt8(-128);
    enc.writeUInt8(255);
    enc.writeInt16(-32768);
    enc.writeUInt16(65535);
    enc.writeInt32(-1234567);
    enc.writeUInt32(4294967295);
    enc.writeInt64(-1700000000000n);
    enc.writeUInt64(18446744073709551615n);
    enc.writeFloat32(1.5);
    enc.writeFloat64(-2.25);
    enc.writeString("中文😀");
    enc.writeBytes(new Uint8Array([0, 1, 2, 255]));

    const dec = new PbpDecoder(enc.toByteArray());
    assert.equal(dec.readBool(), true);
    assert.equal(dec.readInt8(), -128);
    assert.equal(dec.readUInt8(), 255);
    assert.equal(dec.readInt16(), -32768);
    assert.equal(dec.readUInt16(), 65535);
    assert.equal(dec.readInt32(), -1234567);
    assert.equal(dec.readUInt32(), 4294967295);
    assert.equal(dec.readInt64(), -1700000000000n);
    assert.equal(dec.readUInt64(), 18446744073709551615n);
    assert.equal(dec.readFloat32(), 1.5);
    assert.equal(dec.readFloat64(), -2.25);
    assert.equal(dec.readString(), "中文😀");
    assert.deepEqual(Array.from(dec.readBytes()), [0, 1, 2, 255]);
    assert.equal(dec.remaining(), 0);
  });

  it("ZigZag 让负数取短编码（-1 的 int32 只占 1 字节）", () => {
    assert.equal(PbpEncoder.int32Size(-1), 1);
    assert.equal(PbpEncoder.int32Size(1), 1);
    assert.equal(PbpEncoder.int64Size(-1n), 1);
    const enc = new PbpEncoder();
    enc.writeInt32(-1);
    assert.equal(hex(enc.toByteArray()), "01");
  });

  it("集合 / 映射 / 可选字段往返（含 UTF-8 与二进制值）", () => {
    const report = codecReport();
    const back = DetectionReport.parseFrom(report.toByteArray());
    assert.equal(hex(PbpCodec.payloadOf(back)), hex(PbpCodec.payloadOf(report)));
    assert.equal(back.events.length, 1);
    assert.equal(back.events[0].detail, "内存段校验不一致");
    const moduleEvidence = back.events[0].evidence.get("module");
    assert.ok(moduleEvidence);
    assert.deepEqual(Array.from(moduleEvidence), Array.from(utf8("pacc-probe")));
    assert.equal(back.apm?.customMetrics.get("gc_ms"), 3.5);
  });

  it("可选字段清空后仍可往返（apm = null）", () => {
    const cleared = codecReport().toBuilder().setApm(null).build();
    const back = DetectionReport.parseFrom(cleared.toByteArray());
    assert.equal(back.apm, null);
    assert.equal(hex(PbpCodec.payloadOf(back)), hex(PbpCodec.payloadOf(cleared)));
  });

  it("末尾字段读完取默认值（旧端载荷缺字段的向前兼容落点）", () => {
    const enc = new PbpEncoder();
    enc.writeString("inspect_offer");
    enc.writeInt64(1_700_000_000_000n);
    enc.writeString("0123456789abcdef");
    enc.writeString("sess-1");
    enc.writeString("PT0001");
    enc.writeString("{}");
    const frame = PbpFrame.of(PaccEnvelope.MESSAGE_ID, 1_700_000_000_000n, enc.toByteArray());
    const msg = PaccEnvelope.parseFrom(frame.encode());
    assert.equal(msg.type, "inspect_offer");
    assert.equal(msg.sigVersion, 0);
  });
});

describe("解析错误一律拒绝，不静默截断", () => {
  it("严格 UTF-8 解码拒绝非法字节序列", () => {
    const dec = new PbpDecoder(new Uint8Array([0x01, 0xff]));
    assert.equal(expectThrow(() => dec.readString()).code, "BAD_FORMAT");
  });

  it("VarInt 第 10 字节溢出被拒绝", () => {
    const dec = new PbpDecoder(new Uint8Array(10).fill(0x80));
    assert.equal(expectThrow(() => dec.readUInt32()).code, "BAD_VARINT");
  });

  it("集合长度越界被拒绝", () => {
    const enc = new PbpEncoder();
    enc.writeUInt32(0x7fffffff);
    const dec = new PbpDecoder(enc.toByteArray());
    assert.equal(expectThrow(() => dec.readStringList()).code, "BAD_FORMAT");
  });

  it("加密标志位被拒绝", () => {
    const raw = PaccEnvelope.newBuilder().setType("x").build().toByteArray().slice();
    raw[3] = PbpFrame.FLAG_ENCRYPTED;
    assert.equal(expectThrow(() => PbpFrame.parse(raw)).code, "UNSUPPORTED_FLAG");
  });

  it("帧长与 PayloadLen 不符被拒绝", () => {
    const raw = PaccEnvelope.newBuilder().setType("x").build().toByteArray().slice();
    raw[26] = (raw[26] + 1) & 0xff;
    assert.equal(expectThrow(() => PbpFrame.parse(raw)).code, "BAD_LENGTH");
  });
});

describe("zstd 子集自洽性", () => {
  it("空载荷与极小输入往返", () => {
    assert.equal(hex(decompress(compress(new Uint8Array(0)), MAX)), "");
    assert.equal(hex(decompress(compress(new Uint8Array([42])), MAX)), "2a");
    assert.equal(hex(decompress(compress(utf8("hello pbp")), MAX)), hex(utf8("hello pbp")));
  });

  it("全同字节走 RLE 块（帧长极小）", () => {
    const data = new Uint8Array(50_000).fill(0x5a);
    const frame = compress(data);
    assert.ok(frame.length < 32, `全同字节帧长应很小，实际 ${frame.length}`);
    assert.equal(hex(decompress(frame, MAX)), hex(data));
  });

  it("多块与块边界尺寸往返", () => {
    const sizes = [BLOCK_MAX - 1, BLOCK_MAX, BLOCK_MAX + 1, BLOCK_MAX * 2 + 12345];
    for (const size of sizes) {
      const data = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        data[i] = (i * 31) ^ (i >>> 7);
      }
      assert.equal(hex(decompress(compress(data), MAX)), hex(data), `尺寸 ${size} 往返失败`);
    }
  });

  it("随机形态往返（含不可压数据走 Raw 回退）", () => {
    let x = 0x9e3779b9;
    for (let round = 0; round < 20; round++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      const size = x % 20_000;
      const data = new Uint8Array(size);
      const pattern = round % 3;
      for (let i = 0; i < size; i++) {
        x = (x * 1103515245 + 12345) & 0x7fffffff;
        data[i] = pattern === 0 ? i & 0x0f : pattern === 1 ? (x >>> 7) & 0xff : (i < size / 2 ? 0 : 0x7f);
      }
      assert.equal(hex(decompress(compress(data), MAX)), hex(data), `第 ${round} 轮失败`);
    }
  });

  it("解压上限与非法输入被拒绝", () => {
    const frame = compress(utf8("abcdefabcdefabcdef"));
    assert.equal(expectThrow(() => decompress(frame, 4)).code, "BAD_LENGTH");
    assert.equal(expectThrow(() => decompress(new Uint8Array([1, 2, 3]), MAX)).code, "TRUNCATED");
    assert.equal(
      expectThrow(() => decompress(new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0xa0]), MAX)).code,
      "TRUNCATED",
    );
    const dirty = new Uint8Array(frame.length + 1);
    dirty.set(frame);
    assert.equal(expectThrow(() => decompress(dirty, MAX)).code, "BAD_FORMAT");
  });
});

describe("差分链协议规则", () => {
  const chain = () =>
    new PbpDeltaChain<DetectionReport>(DetectionReport.MESSAGE_ID, () => DetectionReport.newBuilder().build());

  it("连续 10 条差分后强制完整消息", () => {
    const sender = chain();
    const frames = [];
    for (let i = 0; i < 15; i++) {
      frames.push(sender.encode(statusReport(3000 + i, 30 + i, 50, 3.5), BigInt(3000 + i)));
    }
    assert.ok(!frames[0].delta());
    for (let i = 1; i <= 10; i++) {
      assert.ok(frames[i].delta(), `第 ${i} 条应为差分`);
    }
    assert.ok(!frames[11].delta(), "第 11 条差分之后必须重发完整消息");
    assert.equal(sender.consecutive(), 3);
  });

  it("差分往返逐条还原", () => {
    const sender = chain();
    const receiver = chain();
    for (let i = 0; i < 12; i++) {
      const message = statusReport(7000 + i, 20 + i, 50 + i, 3.5);
      const decoded = receiver.decode(sender.encode(message, BigInt(7000 + i)).encode());
      assert.equal(hex(PbpCodec.payloadOf(decoded)), hex(PbpCodec.payloadOf(message)), `第 ${i} 条回放不一致`);
    }
  });

  it("接收侧拒绝无基线的差分帧", () => {
    const sender = chain();
    sender.encode(statusReport(4000, 20, 50, 3.5), 4000n);
    const delta = sender.encode(statusReport(4001, 21, 50, 3.5), 4001n);
    assert.ok(delta.delta());
    const fresh = chain();
    assert.equal(expectThrow(() => fresh.decode(delta.encode())).code, "BAD_FORMAT");
  });

  it("接收侧拒绝第 11 条连续差分", () => {
    const sender = chain();
    const receiver = chain();
    receiver.decode(sender.encode(statusReport(5000, 20, 50, 3.5), 5000n).encode());
    for (let i = 1; i <= 10; i++) {
      receiver.decode(sender.encode(statusReport(5000 + i, 20 + i, 50, 3.5), BigInt(5000 + i)).encode());
    }
    assert.equal(receiver.consecutive(), 10);

    // 合规发送方不会发第 11 条差分，这里手工造一条，接收侧必须拒绝
    const baseline = statusReport(5010, 30, 50, 3.5);
    const eleventh = statusReport(5011, 31, 50, 3.5);
    const enc = new PbpEncoder();
    eleventh.encodeDelta(enc, baseline);
    const raw = PbpFrame.of(DetectionReport.MESSAGE_ID, 5011n, enc.toByteArray())
      .withFlag(PbpFrame.FLAG_DELTA)
      .encode();
    assert.equal(expectThrow(() => receiver.decode(raw)).code, "BAD_FORMAT");
  });

  it("reset 丢弃基线后下一条发完整消息", () => {
    const sender = chain();
    sender.encode(statusReport(6000, 20, 50, 3.5), 6000n);
    assert.ok(sender.encode(statusReport(6001, 21, 50, 3.5), 6001n).delta());
    sender.reset();
    assert.ok(!sender.encode(statusReport(6002, 22, 50, 3.5), 6002n).delta());
  });
});