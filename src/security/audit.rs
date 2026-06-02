use std::{
    net::IpAddr,
    path::Path,
    sync::{LazyLock, Mutex},
};

use serde::Serialize;
use tracing::info;

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_ip: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

static AUDIT_WRITER: LazyLock<Mutex<Option<AuditWriter>>> =
    LazyLock::new(|| Mutex::new(None));

struct AuditWriter {
    writer: tracing_appender::non_blocking::NonBlocking,
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

pub fn init_audit_log(log_dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(log_dir) {
        tracing::error!("Failed to create audit log dir: {e}");
        return;
    }
    let file_appender =
        tracing_appender::rolling::Builder::new()
            .max_log_files(30)
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("audit")
            .filename_suffix("jsonl")
            .build(log_dir)
            .expect("Failed to create audit log appender");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    let mut w = AUDIT_WRITER.lock().unwrap();
    *w = Some(AuditWriter {
        writer,
        _guard: guard,
    });
    info!("Audit log initialized at {}", log_dir.display());
}

pub fn audit(event: &'static str, ip: Option<IpAddr>, success: bool, details: Option<String>) {
    let entry = AuditEvent {
        ts: chrono::Utc::now().to_rfc3339(),
        event,
        actor_ip: ip.map(|i| i.to_string()),
        success,
        details,
    };
    let Ok(json) = serde_json::to_string(&entry) else {
        return;
    };

    if let Ok(mut guard) = AUDIT_WRITER.lock() {
        if let Some(ref mut w) = *guard {
            use std::io::Write;
            let _ = writeln!(w.writer, "{json}");
        }
    }

    if success {
        info!(audit_event = event, "audit: {event}");
    } else {
        tracing::warn!(audit_event = event, "audit: {event} (failed)");
    }
}
