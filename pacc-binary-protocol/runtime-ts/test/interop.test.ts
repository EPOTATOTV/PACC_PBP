import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { PaccEnvelope } from "../src/gen/PaccEnvelope.js";
import { DetectionReport } from "../src/gen/DetectionReport.js";
import { PbpCodec } from "../src/PbpCodec.js";
import { hmacSha256 } from "../src/PbpCrypto.js";
import { PbpDeltaChain } from "../src/PbpDeltaChain.js";
import { PbpFrame } from "../src/PbpFrame.js";
import { compress, decompress } from "../src/PbpZstd.js";
import {
  blockyPayload,
  codecReport,
  fromHex,
  hex,
  loadVectors,
  mixedPayload,
  noisePayload,
  rampPayload,
  repeatPayload,
  rlePayload,
  statusReport,
  utf8,
  vector,
} from "./support.js";

/**
 * 跨语言互操作断言：逐字节对照 pacc-binary-protocol/test-vectors/interop.txt。
 * 向量由 Java 参考实现导出，能逐字节复现才说明多语言运行时行为一致。
 */
const TS_MS = 1_700_000_000_000n;
const MAX = PbpFrame.MAX_PAYLOAD_SIZE;
const vectors = loadVectors();

function envelope(type: string, payloadJson: string): PaccEnvelope {
  return PaccEnvelope.newBuilder()
    .setType(type)
    .setTsMs(TS_MS)
    .setNonce("0123456789abcdef")
    .setSessionId("sess-1")
    .setPteid("PT0001")
    .setPayloadJson(payloadJson)
    .setSigVersion(1)
    .build();
}

describe("信封帧与签名向量", () => {
  it("载荷 / 未签名帧 / 帧头时间戳逐字节一致", () => {
    const env = envelope("inspect_offer", "{}");
    assert.equal(hex(PbpCodec.payloadOf(env)), vector(vectors, "envelope_payload"));
    const raw = env.toByteArray();
    assert.equal(hex(raw), vector(vectors, "envelope_frame"));
    assert.equal(hex(raw.slice(10, 18)), vector(vectors, "envelope_ts_ms"));
  });

  it("HMAC-SHA256 覆盖帧头+载荷，签名帧逐字节一致", () => {
    const env = envelope("inspect_offer", "{}");
    const secret = utf8("000102030405060708090a0b0c0d0e0f");
    const signature = hmacSha256(secret, env.signingInput());
    const signed = env.toBuilder().setSignatureBytes(signature).build();
    assert.equal(hex(signed.toByteArray()), vector(vectors, "envelope_signed_frame"));

    const tail = fromHex(vector(vectors, "envelope_signed_frame")).slice(-32);
    assert.equal(hex(signature), hex(tail));

    const back = PaccEnvelope.parseFrom(signed.toByteArray());
    assert.equal(back.getSignatureHex(), hex(signature));
    assert.equal(back.type, "inspect_offer");
    assert.equal(back.tsMs, TS_MS);
    assert.equal(back.pteid, "PT0001");
    assert.equal(back.sigVersion, 1);
  });
});

describe("编解码边界载荷向量", () => {
  it("codec_payload 逐字节一致（负时间戳 / 中文 / 浮点 / 集合 / 嵌套 / 可选）", () => {
    assert.equal(hex(PbpCodec.payloadOf(codecReport())), vector(vectors, "codec_payload"));
  });
});

describe("大载荷自动压缩向量", () => {
  it("big_frame_compressed 逐字节一致且带 FLAG_COMPRESSED", () => {
    const env = envelope("inspect_result", "A".repeat(3000));
    const raw = env.toByteArray();
    assert.equal(hex(raw), vector(vectors, "big_frame_compressed"));
    const frame = PbpFrame.parse(raw);
    assert.ok(frame.compressed());
    assert.equal(hex(PbpCodec.payloadOfFrame(frame)), hex(PbpCodec.payloadOf(env)));
  });
});

describe("zstd 子集压缩向量", () => {
  const cases: Array<[string, Uint8Array]> = [
    ["zstd_repeat", repeatPayload()],
    ["zstd_rle", rlePayload()],
    ["zstd_ramp", rampPayload()],
    ["zstd_noise", noisePayload()],
    ["zstd_blocky", blockyPayload()],
    ["zstd_mixed", mixedPayload()],
  ];
  for (const [name, plain] of cases) {
    it(`${name}：压缩逐字节一致，解压还原明文`, () => {
      const compressed = compress(plain);
      assert.equal(hex(compressed), vector(vectors, `${name}_compressed`));
      assert.equal(hex(decompress(compressed, MAX)), hex(plain));
      assert.equal(hex(decompress(fromHex(vector(vectors, `${name}_compressed`)), MAX)), hex(plain));
    });
  }
});

describe("差分链向量", () => {
  it("frame1/frame2 逐字节一致，解码回放与 delta_payload2 一致", () => {
    const sender = new PbpDeltaChain<DetectionReport>(
      DetectionReport.MESSAGE_ID,
      () => DetectionReport.newBuilder().build(),
    );
    const receiver = new PbpDeltaChain<DetectionReport>(
      DetectionReport.MESSAGE_ID,
      () => DetectionReport.newBuilder().build(),
    );
    const msg1 = statusReport(2000, 20, 50, 3.5);
    const msg2 = statusReport(2001, 24, 50, 4.5);
    const frame1 = sender.encode(msg1, 2000n);
    const frame2 = sender.encode(msg2, 2001n);

    assert.equal(hex(frame1.encode()), vector(vectors, "delta_frame1"));
    assert.equal(hex(frame2.encode()), vector(vectors, "delta_frame2"));
    assert.ok(!frame1.delta());
    assert.ok(frame2.delta());

    const decoded1 = receiver.decode(frame1.encode());
    const decoded2 = receiver.decode(frame2.encode());
    assert.equal(hex(PbpCodec.payloadOf(decoded1)), hex(PbpCodec.payloadOf(msg1)));
    assert.equal(hex(PbpCodec.payloadOf(decoded2)), vector(vectors, "delta_payload2"));

    // 直接解向量文件里的帧
    const fromVectorChain = new PbpDeltaChain<DetectionReport>(
      DetectionReport.MESSAGE_ID,
      () => DetectionReport.newBuilder().build(),
    );
    fromVectorChain.decode(fromHex(vector(vectors, "delta_frame1")));
    const replayed = fromVectorChain.decode(fromHex(vector(vectors, "delta_frame2")));
    assert.equal(hex(PbpCodec.payloadOf(replayed)), vector(vectors, "delta_payload2"));
  });
});