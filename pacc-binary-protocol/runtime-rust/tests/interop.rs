//! 跨语言互操作与自洽性测试（设计文档 §3.7/§3.8，验收项 B09/B11）。
//!
//! 读 `pacc-binary-protocol/test-vectors/interop.txt`（由 Java 参考实现导出），逐字节比对：
//! 能复现参考实现的压缩输出、能解开参考帧，才算互操作成立。

use pacc_binary_protocol::codec::PbpCodec;
use pacc_binary_protocol::crypto;
use pacc_binary_protocol::delta::{PbpDeltaChain, PbpDeltaMessage};
use pacc_binary_protocol::decoder::PbpDecoder;
use pacc_binary_protocol::encoder::PbpEncoder;
use pacc_binary_protocol::error::PbpError;
use pacc_binary_protocol::frame::PbpFrame;
use pacc_binary_protocol::gen::{ApmSnapshot, DetectionEvent, DetectionReport, PaccEnvelope};
use pacc_binary_protocol::message::PbpMessage;
use pacc_binary_protocol::zstd::PbpZstd;

const VECTORS: &str = include_str!("../../test-vectors/interop.txt");
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const TS_MS: i64 = 1_700_000_000_000;

// ------------------------------------------------------------ 向量读取

fn raw_vector(name: &str) -> String {
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == name {
                return value.trim().to_string();
            }
        }
    }
    panic!("向量文件里缺少 {name}");
}

fn vector(name: &str) -> Vec<u8> {
    crypto::hex_decode(&raw_vector(name)).unwrap_or_else(|| panic!("向量 {name} 不是合法十六进制"))
}

/// HMAC 密钥是 secret_hex_text 这串文本的 UTF-8 字节（PACC 两侧的既有约定）：
/// 向量存的是该文本 UTF-8 字节的十六进制，所以要先解出文本本身。
fn secret_bytes() -> Vec<u8> {
    crypto::hex_decode(&raw_vector("secret_hex_text")).expect("secret_hex_text 不是合法十六进制")
}

// ------------------------------------------------------------ 载荷构造

fn envelope(type_: &str, payload_json: &str) -> PaccEnvelope {
    PaccEnvelope::new()
        .set_type_(type_)
        .set_ts_ms(TS_MS)
        .set_nonce("0123456789abcdef")
        .set_session_id("sess-1")
        .set_pteid("PT0001")
        .set_payload_json(payload_json)
        .set_sig_version(1)
}

fn codec_report() -> DetectionReport {
    let signature: Vec<u8> = (1..=32u8).collect();
    let event = DetectionEvent::new()
        .set_event_type(2)
        .set_confidence(0.75)
        .set_timestamp(1_700_000_000_001)
        .put_evidence("module", b"pacc-probe".to_vec())
        .set_detail(Some("内存段校验不一致".to_string()));
    let apm = ApmSnapshot::new()
        .set_cpu_usage(23.5)
        .set_memory_usage_kb(450_000)
        .set_fps(120.0)
        .set_detection_latency_ms(12)
        .set_active_rules(50)
        .put_custom_metrics("gc_ms", 3.5);
    DetectionReport::new()
        .set_pteid("PT0001")
        .set_timestamp(-1_700_000_000_000)
        .set_client_version("5.4.0-验证")
        .set_platform("windows")
        .add_events(event)
        .set_apm(Some(apm))
        .set_signature(signature)
}

fn status_report(ts: i64, cpu_percent: i32, rules: i32, gc_ms: f32) -> DetectionReport {
    let event = DetectionEvent::new()
        .set_event_type(2)
        .set_confidence(0.87)
        .set_timestamp(900)
        .put_evidence("module", b"pacc-probe".to_vec())
        .set_detail(Some("可疑进程".to_string()));
    let apm = ApmSnapshot::new()
        .set_cpu_usage(cpu_percent as f32 / 100.0)
        .set_memory_usage_kb(450_000)
        .set_fps(120.0)
        .set_detection_latency_ms(12)
        .set_active_rules(rules)
        .put_custom_metrics("gc_ms", gc_ms);
    DetectionReport::new()
        .set_pteid("PT0001")
        .set_timestamp(ts)
        .set_client_version("5.4.0")
        .set_platform("windows")
        .add_events(event)
        .set_apm(Some(apm))
}

// ------------------------------------------------------------ 1. 信封帧

#[test]
fn envelope_payload_matches_vector() {
    let payload = PbpCodec::payload_of(&envelope("inspect_offer", "{}"));
    assert_eq!(payload, vector("envelope_payload"));
}

#[test]
fn envelope_unsigned_frame_matches_vector() {
    let frame = envelope("inspect_offer", "{}").to_byte_array().unwrap();
    assert_eq!(frame, vector("envelope_frame"));
    // 帧头时间戳来自 MDL 的 frame_timestamp 字段
    let parsed = PbpFrame::parse(&vector("envelope_frame")).unwrap();
    assert_eq!(parsed.timestamp_ms, TS_MS);
    assert_eq!(parsed.message_id, PaccEnvelope::MESSAGE_ID);
}

#[test]
fn envelope_signed_frame_matches_vector() {
    let msg = envelope("inspect_offer", "{}");
    let signature = crypto::hmac_sha256(&secret_bytes(), &msg.signing_input().unwrap());
    assert_eq!(
        crypto::hex_encode(&signature),
        "f3ae51a23a95c9c26b762839e39b493f5b74f3226f58ad28c55464b0266881e0"
    );
    let signed = msg.clone().set_signature_bytes(signature.to_vec()).to_byte_array().unwrap();
    assert_eq!(signed, vector("envelope_signed_frame"));

    // 签名前后 signing_input 必须是同一串字节
    assert_eq!(msg.signing_input().unwrap(), signed_envelope_input(&signed));
}

fn signed_envelope_input(raw: &[u8]) -> Vec<u8> {
    // 验签方从帧里重建覆盖面：帧头（FLAG_SIGNED 已置位）+ 载荷
    let frame = PbpFrame::parse(raw).unwrap();
    let mut signed = frame.clone();
    signed.signature = Vec::new();
    signed.signing_input()
}

// ------------------------------------------------------------ 2. 编解码边界载荷

#[test]
fn codec_payload_matches_vector() {
    let payload = PbpCodec::payload_of(&codec_report());
    assert_eq!(payload, vector("codec_payload"));

    // 逐字段往返：负数 ZigZag、多字节 UTF-8、浮点、集合、嵌套、可选、bytes
    let mut decoded = DetectionReport::new();
    decoded.decode(&mut PbpDecoder::new(&vector("codec_payload"))).unwrap();
    assert_eq!(decoded.timestamp, -1_700_000_000_000);
    assert_eq!(decoded.client_version, "5.4.0-验证");
    assert_eq!(decoded.events.len(), 1);
    assert_eq!(decoded.events[0].detail.as_deref(), Some("内存段校验不一致"));
    assert_eq!(PbpCodec::payload_of(&decoded), vector("codec_payload"));
}

// ------------------------------------------------------------ 3. 大载荷自动压缩

#[test]
fn big_frame_auto_compresses_and_matches_vector() {
    let big = envelope("inspect_result", &"A".repeat(3000));
    let frame_bytes = big.to_byte_array().unwrap();
    assert_eq!(frame_bytes, vector("big_frame_compressed"));
    let parsed = PbpFrame::parse(&vector("big_frame_compressed")).unwrap();
    assert!(parsed.compressed(), "载荷超 1KB 应触发自动压缩");
}

// ------------------------------------------------------------ 4. zstd 子集

fn check_zstd(name: &str, plain: &[u8]) {
    let expected = vector(&format!("{name}_compressed"));
    let compressed = PbpZstd::compress(plain).unwrap();
    assert_eq!(compressed, expected, "{name} 压缩输出与向量不一致");
    let restored = PbpZstd::decompress(&expected, MAX_PAYLOAD).unwrap();
    assert_eq!(restored, plain, "{name} 解压结果与明文不一致");
}

#[test]
fn zstd_vectors_round_trip() {
    check_zstd("zstd_repeat", &repeat_payload());
    check_zstd("zstd_rle", &rle_payload());
    check_zstd("zstd_ramp", &ramp_payload());
    check_zstd("zstd_noise", &noise_payload());
    check_zstd("zstd_blocky", &blocky_payload());
    check_zstd("zstd_mixed", &mixed_payload());
}

fn repeat_payload() -> Vec<u8> {
    let pattern = b"pacc-pbp-zstd";
    (0..16_384).map(|i| pattern[i % pattern.len()]).collect()
}

fn rle_payload() -> Vec<u8> {
    vec![0x5A; 4096]
}

fn ramp_payload() -> Vec<u8> {
    (0..4096i64).map(|i| ((i * i * 31 + i * 7 + 11) & 0xFF) as u8).collect()
}

fn noise_payload() -> Vec<u8> {
    let mut x: u32 = 0x12345678;
    let mut data = Vec::with_capacity(4096);
    for _ in 0..4096 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.push((x & 0xFF) as u8);
    }
    data
}

fn blocky_payload() -> Vec<u8> {
    (0..8192i64)
        .map(|i| if i % 37 < 20 { (i & 0x0F) as u8 } else { ((i * 3) & 0xFF) as u8 })
        .collect()
}

fn mixed_payload() -> Vec<u8> {
    (0..140_000i64).map(|i| ((i * 7 + 140_000) & 0xFF) as u8).collect()
}

// ------------------------------------------------------------ 5. 差分链

#[test]
fn delta_chain_decodes_reference_frames() {
    let msg1 = status_report(2000, 20, 50, 3.5);
    let msg2 = status_report(2001, 24, 50, 4.5);

    // 发送侧输出与向量逐字节一致（首条完整、第二条差分）
    let mut sender = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    let frame1 = sender.encode(&msg1, 2000).unwrap();
    assert!(!frame1.delta());
    assert_eq!(frame1.encode().unwrap(), vector("delta_frame1"));
    let frame2 = sender.encode(&msg2, 2001).unwrap();
    assert!(frame2.delta());
    assert!(!frame2.compressed());

    // 接收侧解开参考帧
    let mut receiver = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    let decoded1 = receiver.decode(&vector("delta_frame1")).unwrap();
    let decoded2 = receiver.decode(&vector("delta_frame2")).unwrap();
    assert_eq!(PbpCodec::payload_of(&decoded1), PbpCodec::payload_of(&msg1));
    // msg2 重新编码的完整载荷与向量一致（差分只改了 timestamp 与 apm）
    assert_eq!(PbpCodec::payload_of(&msg2), vector("delta_payload2"));
    assert_eq!(PbpCodec::payload_of(&decoded2), vector("delta_payload2"));

    let reference2 = PbpFrame::parse(&vector("delta_frame2")).unwrap();
    assert!(reference2.delta());
}

#[test]
fn delta_chain_forces_full_message_after_ten_consecutive_deltas() {
    let mut sender = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    let mut frames = Vec::new();
    for i in 0..15 {
        let msg = status_report(3000 + i, 30 + i as i32, 50, 3.5);
        frames.push(sender.encode(&msg, 3000 + i).unwrap());
    }
    assert!(!frames[0].delta());
    for i in 1..=10 {
        assert!(frames[i].delta(), "第 {i} 条应为差分");
    }
    assert!(!frames[11].delta(), "第 11 条差分之后必须重发完整消息");
    for i in 12..=14 {
        assert!(frames[i].delta());
    }
    assert_eq!(sender.consecutive(), 3);
}

#[test]
fn receiver_rejects_delta_without_baseline() {
    let mut sender = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    sender.encode(&status_report(4000, 20, 50, 3.5), 4000).unwrap();
    let delta = sender.encode(&status_report(4001, 21, 50, 3.5), 4001).unwrap();
    assert!(delta.delta());

    let mut fresh = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    assert_eq!(fresh.decode(&delta.encode().unwrap()).unwrap_err(), PbpError::BadFormat);
}

#[test]
fn receiver_rejects_eleventh_consecutive_delta() {
    let mut sender = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);
    let mut receiver = PbpDeltaChain::<DetectionReport>::new(DetectionReport::MESSAGE_ID);

    let mut current = status_report(5000, 20, 50, 3.5);
    receiver.decode(&sender.encode(&current, 5000).unwrap().encode().unwrap()).unwrap();
    for i in 1..=10 {
        let next = status_report(5000 + i, 20 + i as i32, 50, 3.5);
        receiver.decode(&sender.encode(&next, 5000 + i).unwrap().encode().unwrap()).unwrap();
        current = next;
    }
    assert_eq!(receiver.consecutive(), 10);

    // 手工造"第 11 条差分"：合规发送方不会发，接收侧必须拒绝
    let eleventh = status_report(5011, 31, 50, 3.5);
    let mut encoder = PbpEncoder::new();
    eleventh.encode_delta(&mut encoder, &current);
    let raw = PbpFrame::of(DetectionReport::MESSAGE_ID, 5011, encoder.into_bytes())
        .with_flag(PbpFrame::FLAG_DELTA)
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(receiver.decode(&raw).unwrap_err(), PbpError::BadFormat);
}

// ------------------------------------------------------------ 6. 自洽性

#[test]
fn frame_round_trips_and_rejects_garbage() {
    let frame = PbpFrame::of(0x2001, TS_MS, b"hello".to_vec());
    let encoded = frame.encode().unwrap();
    assert_eq!(PbpFrame::parse(&encoded).unwrap(), frame);

    assert_eq!(PbpFrame::parse(&[0u8; 10]).unwrap_err(), PbpError::Truncated);
    assert_eq!(PbpFrame::parse(&[]).unwrap_err(), PbpError::Truncated);
    // 加密位一旦被置位就显式失败，绝不把未加密载荷当明文解析
    let mut encrypted = frame.clone();
    encrypted.flags = PbpFrame::FLAG_ENCRYPTED;
    assert_eq!(encrypted.encode().unwrap_err(), PbpError::UnsupportedFlag);
}

#[test]
fn zstd_round_trips_arbitrary_inputs() {
    // 空载荷、单字节、全同字节、多块边界、伪随机
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![42],
        b"hello pbp".to_vec(),
        vec![0x5A; 50_000],
        (0..(128 * 1024 * 2 + 12345)).map(|i| ((i * 31) ^ (i >> 7)) as u8).collect(),
        (0..20_000u32).map(|i| ((i.wrapping_mul(2654435761)) >> 24) as u8).collect(),
    ];
    for (index, data) in cases.iter().enumerate() {
        let frame = PbpZstd::compress(data).unwrap();
        assert_eq!(&PbpZstd::decompress(&frame, MAX_PAYLOAD).unwrap(), data, "第 {index} 组往返失败");
    }
}

#[test]
fn zstd_rejects_oversized_window_and_garbage() {
    let frame = PbpZstd::compress(b"abcdefabcdefabcdef").unwrap();
    assert!(PbpZstd::decompress(&frame, 4).is_err());
    assert!(PbpZstd::decompress(&[1, 2, 3], MAX_PAYLOAD).is_err());
    assert!(PbpZstd::decompress(&[0x28, 0xB5, 0x2F, 0xFD, 0xA0], MAX_PAYLOAD).is_err());

    // 帧尾多一个字节应被拒绝
    let mut dirty = frame.clone();
    dirty.push(0);
    assert!(PbpZstd::decompress(&dirty, MAX_PAYLOAD).is_err());
}

#[test]
fn optional_and_collection_round_trip() {
    let full = codec_report();
    let with_apm = PbpCodec::payload_of(&full);
    let mut decoded = DetectionReport::new();
    decoded.decode(&mut PbpDecoder::new(&with_apm)).unwrap();
    assert_eq!(PbpCodec::payload_of(&decoded), with_apm);

    // 清空可空字段：apm 走位图 0，payload 随之变短
    let without_apm = full.clone().set_apm(None);
    let bytes = PbpCodec::payload_of(&without_apm);
    assert!(bytes.len() < with_apm.len());
    let mut decoded = DetectionReport::new();
    decoded.decode(&mut PbpDecoder::new(&bytes)).unwrap();
    assert_eq!(decoded.apm, None);
    assert_eq!(PbpCodec::payload_of(&decoded), bytes);
    assert_eq!(decoded.events[0].evidence.len(), 1);
    assert_eq!(PbpCodec::payload_of(&decoded), bytes);
}

#[test]
fn signed_message_verifies_after_round_trip() {
    let msg = envelope("inspect_offer", "{}");
    let signature = crypto::hmac_sha256(&secret_bytes(), &msg.signing_input().unwrap());
    let raw = msg.set_signature_bytes(signature.to_vec()).to_byte_array().unwrap();
    let parsed = PaccEnvelope::parse_from(&raw).unwrap();
    assert!(crypto::verify_hmac(&secret_bytes(), &parsed.signing_input().unwrap(), &parsed.signature));
}

#[test]
fn decoder_rejects_bad_utf8_and_truncation() {
    // 字符串长度声明超出剩余字节
    let bad = vec![0x05u8, b'a', b'b'];
    assert_eq!(DetectionReport::new().decode(&mut PbpDecoder::new(&bad)).unwrap_err(), PbpError::Truncated);

    // 长度为 1 但字节非法 UTF-8
    let invalid_utf8 = vec![0x01u8, 0xFF];
    let mut decoder = PbpDecoder::new(&invalid_utf8);
    assert_eq!(decoder.read_string().unwrap_err(), PbpError::BadFormat);
}