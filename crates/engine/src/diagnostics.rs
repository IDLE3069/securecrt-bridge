//! Local lifecycle diagnostics. Never log entry descriptors or terminal contents.
use std::{io::Write, sync::Mutex};

static LOG_LOCK: Mutex<()> = Mutex::new(());

fn log_path() -> std::path::PathBuf {
    #[cfg(test)]
    {
        static DIRECTORY: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        DIRECTORY
            .get_or_init(|| {
                let path = std::env::temp_dir().join(format!(
                    "scb-engine-tests-{}-{}",
                    std::process::id(),
                    scb_core::id()
                ));
                std::fs::create_dir_all(&path).unwrap();
                path
            })
            .join("diagnostics.log")
    }
    #[cfg(not(test))]
    {
        scb_core::data_dir().join("diagnostics.log")
    }
}

pub fn write(message: &str) {
    let Ok(_lock) = LOG_LOCK.lock() else { return };
    let path = log_path();
    // Keep the previous segment instead of deleting the only evidence.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 256 * 1024) {
        let previous = path.with_extension("log.1");
        let _ = std::fs::remove_file(&previous);
        let _ = std::fs::rename(&path, previous);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(
            file,
            "{} pid={} version={} {}",
            scb_core::now_ms(),
            std::process::id(),
            scb_core::VERSION,
            message.replace(['\r', '\n'], " ")
        );
    }
}

#[cfg(test)]
pub fn read() -> String {
    std::fs::read_to_string(log_path()).unwrap()
}

pub struct Trace(pub String);
impl Trace {
    pub fn new() -> Self {
        Self(scb_core::id())
    }
    pub fn event(&self, stage: &str, detail: &str) {
        write(&format!("engine={} stage={} {}", self.0, stage, detail));
    }
    pub fn checked<T>(
        &self,
        stage: &str,
        result: windows::core::Result<T>,
    ) -> windows::core::Result<T> {
        result.inspect_err(|error| self.event(stage, &format!("failed: {error:#}")))
    }
}
