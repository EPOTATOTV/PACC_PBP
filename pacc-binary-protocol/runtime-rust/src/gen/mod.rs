// 本文件由 tools/pbpgen 生成，请勿手改。
// 源定义：pacc-binary-protocol/mdl/{detection.mdl, pacc_wire.mdl}
// 重新生成：cd tools/pbpgen && python -m pbpgen

#[path = "ApmSnapshot.rs"]
pub mod apm_snapshot;
pub use apm_snapshot::ApmSnapshot;

#[path = "DetectionEvent.rs"]
pub mod detection_event;
pub use detection_event::DetectionEvent;

#[path = "DetectionReport.rs"]
pub mod detection_report;
pub use detection_report::DetectionReport;

#[path = "PaccEnvelope.rs"]
pub mod pacc_envelope;
pub use pacc_envelope::PaccEnvelope;
