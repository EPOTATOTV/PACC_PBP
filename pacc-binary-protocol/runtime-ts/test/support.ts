import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ApmSnapshot } from "../src/gen/ApmSnapshot.js";
import { DetectionEvent } from "../src/gen/DetectionEvent.js";
import { DetectionReport } from "../src/gen/DetectionReport.js";
import { bytesFromHex, bytesToHex } from "../src/PbpCrypto.js";
import { PbpException } from "../src/PbpException.js";

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function hex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(s: string): Uint8Array {
  return bytesFromHex(s);
}

/** 读 pacc-binary-protocol/test-vectors/interop.txt（key = hex）。 */
export function loadVectors(): Map<string, string> {
  const here = dirname(fileURLToPath(import.meta.url));
  const path = join(here, "../../../test-vectors/interop.txt");
  const text = readFileSync(path, "utf8");
  const vectors = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      continue;
    }
    const index = trimmed.indexOf("=");
    if (index < 0) {
      continue;
    }
    vectors.set(trimmed.slice(0, index).trim(), trimmed.slice(index + 1).trim());
  }
  return vectors;
}

export function vector(vectors: Map<string, string>, key: string): string {
  const value = vectors.get(key);
  if (value === undefined) {
    throw new Error(`向量缺失: ${key}`);
  }
  return value;
}

export function expectThrow(fn: () => unknown): PbpException {
  try {
    fn();
  } catch (error) {
    if (error instanceof PbpException) {
      return error;
    }
    throw error;
  }
  throw new Error("期望抛出 PbpException，但调用正常返回");
}

/** 互操作向量 PbpInteropVectorsTest#codecReport 的等价构造。 */
export function codecReport(): DetectionReport {
  const signature = new Uint8Array(32);
  for (let i = 0; i < signature.length; i++) {
    signature[i] = i + 1;
  }
  return DetectionReport.newBuilder()
    .setPteid("PT0001")
    .setTimestamp(-1700000000000n)
    .setClientVersion("5.4.0-验证")
    .setPlatform("windows")
    .addEvents(
      DetectionEvent.newBuilder()
        .setEventType(2)
        .setConfidence(0.75)
        .setTimestamp(1700000000001n)
        .putEvidence("module", utf8("pacc-probe"))
        .setDetail("内存段校验不一致")
        .build(),
    )
    .setApm(
      ApmSnapshot.newBuilder()
        .setCpuUsage(23.5)
        .setMemoryUsageKb(450_000)
        .setFps(120.0)
        .setDetectionLatencyMs(12)
        .setActiveRules(50)
        .putCustomMetrics("gc_ms", 3.5)
        .build(),
    )
    .setSignature(signature)
    .build();
}

/** 互操作向量 PbpInteropVectorsTest#statusReport 的等价构造。 */
export function statusReport(ts: number, cpuPercent: number, rules: number, gcMs: number): DetectionReport {
  return DetectionReport.newBuilder()
    .setPteid("PT0001")
    .setTimestamp(BigInt(ts))
    .setClientVersion("5.4.0")
    .setPlatform("windows")
    .addEvents(
      DetectionEvent.newBuilder()
        .setEventType(2)
        .setConfidence(0.87)
        .setTimestamp(900n)
        .putEvidence("module", utf8("pacc-probe"))
        .setDetail("可疑进程")
        .build(),
    )
    .setApm(
      ApmSnapshot.newBuilder()
        .setCpuUsage(cpuPercent / 100)
        .setMemoryUsageKb(450_000)
        .setFps(120.0)
        .setDetectionLatencyMs(12)
        .setActiveRules(rules)
        .putCustomMetrics("gc_ms", gcMs)
        .build(),
    )
    .build();
}

/** 向量的明文生成公式（见 interop.txt 注释）。 */
export function repeatPayload(): Uint8Array {
  const data = new Uint8Array(16_384);
  const pattern = utf8("pacc-pbp-zstd");
  for (let i = 0; i < data.length; i++) {
    data[i] = pattern[i % pattern.length];
  }
  return data;
}

export function rlePayload(): Uint8Array {
  return new Uint8Array(4096).fill(0x5a);
}

export function rampPayload(): Uint8Array {
  const data = new Uint8Array(4096);
  for (let i = 0; i < data.length; i++) {
    data[i] = (i * i * 31 + i * 7 + 11) & 0xff;
  }
  return data;
}

export function noisePayload(): Uint8Array {
  const data = new Uint8Array(4096);
  let x = 0x12345678;
  for (let i = 0; i < data.length; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    data[i] = x & 0xff;
  }
  return data;
}

export function blockyPayload(): Uint8Array {
  const data = new Uint8Array(8192);
  for (let i = 0; i < data.length; i++) {
    data[i] = i % 37 < 20 ? i & 0x0f : (i * 3) & 0xff;
  }
  return data;
}

export function mixedPayload(): Uint8Array {
  const data = new Uint8Array(140_000);
  for (let i = 0; i < data.length; i++) {
    data[i] = (i * 7 + 140_000) & 0xff;
  }
  return data;
}