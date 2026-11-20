// SPDX-License-Identifier: AGPL-3.0-only

//! Capture mode: every outgoing request exactly as it left, and the response as received.
//!
//! For each request four files are written to the capture directory, named
//! `<unix-millis>-<seq>-<route>.`:
//!
//! - `request.json`: method, upstream URI, HTTP version and headers;
//! - `request.body`: the outgoing body, byte-identical to what the upstream received;
//! - `response.json`: status and headers;
//! - `response.body`: the upstream's body before placeholder resolution.
//!
//! Only post-redaction bytes are ever written. Header values are recorded only for a short list
//! of non-sensitive headers; every other value (including `authorization`, `x-api-key`, cookies)
//! is written as `[masked]`. Files are created with mode 0600 and the directory must not be
//! accessible to group or others. A capture that cannot record a request refuses that request.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::config::CaptureConfig;

/// Headers whose values are recorded. All others are masked.
pub const RECORDED_HEADERS: &[&str] = &[
    "accept",
    "anthropic-beta",
    "anthropic-version",
    "content-length",
    "content-type",
    "openai-beta",
    "request-id",
    "x-request-id",
    "retry-after",
    "user-agent",
];

/// Capture could not be set up or written.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// I/O error.
    #[error("capture: {0}")]
    Io(#[from] std::io::Error),
    /// The directory is readable or writable by others.
    #[error("capture directory {0} is accessible to group or others (mode {1:o}); use mode 0700")]
    Permissive(PathBuf, u32),
}

/// The capture sink.
#[derive(Debug)]
pub struct Capture {
    dir: PathBuf,
    seq: AtomicU64,
    retention: Duration,
}

fn headers_json(h: &http::HeaderMap) -> serde_json::Value {
    let mut v = Vec::with_capacity(h.len());
    for (k, val) in h {
        let name = k.as_str();
        let shown = if RECORDED_HEADERS.contains(&name) {
            String::from_utf8_lossy(val.as_bytes()).into_owned()
        } else {
            "[masked]".to_string()
        };
        v.push(serde_json::json!([name, shown]));
    }
    serde_json::Value::Array(v)
}

#[cfg(unix)]
fn check_dir(dir: &Path) -> Result<(), CaptureError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CaptureError::Permissive(dir.to_path_buf(), mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_dir(dir: &Path) -> Result<(), CaptureError> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

async fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut o = tokio::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(path).await?;
    f.write_all(bytes).await?;
    f.flush().await
}

impl Capture {
    /// Opens (creating if needed) the capture directory and checks its permissions.
    pub fn open(cfg: &CaptureConfig) -> Result<Arc<Self>, CaptureError> {
        check_dir(&cfg.dir)?;
        Ok(Arc::new(Self {
            dir: cfg.dir.clone(),
            seq: AtomicU64::new(0),
            retention: Duration::from_secs(cfg.retention_secs),
        }))
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Deletes capture files older than the retention. Returns how many were removed.
    pub fn sweep(&self) -> std::io::Result<usize> {
        let now = SystemTime::now();
        let mut n = 0;
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !(name.ends_with(".body") || name.ends_with(".json")) {
                continue;
            }
            let md = e.metadata()?;
            if !md.is_file() {
                continue;
            }
            let age = md
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or_default();
            if age > self.retention {
                std::fs::remove_file(e.path())?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Runs [`Capture::sweep`] now and then periodically until the returned task is aborted.
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        let every = (self.retention / 4).clamp(Duration::from_secs(1), Duration::from_secs(3600));
        tokio::spawn(async move {
            loop {
                let m = me.clone();
                match tokio::task::spawn_blocking(move || m.sweep()).await {
                    Ok(Ok(n)) if n > 0 => tracing::info!(removed = n, "capture retention sweep"),
                    Ok(Err(e)) => tracing::warn!(error = %e, "capture retention sweep failed"),
                    _ => {}
                }
                tokio::time::sleep(every).await;
            }
        })
    }

    /// Records an outgoing request. Must succeed before the request is forwarded.
    pub async fn request(
        &self,
        route: &str,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Result<Record, CaptureError> {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let safe_route: String = route
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let stem = self.dir.join(format!("{ms}-{seq:06}-{safe_route}"));
        let meta = serde_json::json!({
            "method": method.as_str(),
            "uri": uri.to_string(),
            "headers": headers_json(headers),
        });
        write_new(
            &with_ext(&stem, "request.json"),
            &serde_json::to_vec_pretty(&meta).unwrap_or_default(),
        )
        .await?;
        write_new(&with_ext(&stem, "request.body"), body).await?;
        Ok(Record { stem })
    }
}

fn with_ext(stem: &Path, ext: &str) -> PathBuf {
    let mut s = stem.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// One captured exchange.
#[derive(Debug)]
pub struct Record {
    stem: PathBuf,
}

impl Record {
    /// Path of one of this record's files (`request.json`, `request.body`, `response.json`,
    /// `response.body`).
    pub fn path(&self, ext: &str) -> PathBuf {
        with_ext(&self.stem, ext)
    }

    /// Records the response head and returns a writer for its body. Failures are logged and
    /// stop the response capture; they never affect the response.
    pub async fn response(
        self,
        status: http::StatusCode,
        headers: &http::HeaderMap,
    ) -> Option<BodyTee> {
        let meta =
            serde_json::json!({ "status": status.as_u16(), "headers": headers_json(headers) });
        if let Err(e) = write_new(
            &self.path("response.json"),
            &serde_json::to_vec_pretty(&meta).unwrap_or_default(),
        )
        .await
        {
            tracing::warn!(error = %e, "capture: response head not recorded");
            return None;
        }
        let path = self.path("response.body");
        let mut o = tokio::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        o.mode(0o600);
        let mut f = match o.open(&path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "capture: response body not recorded");
                return None;
            }
        };
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if let Err(e) = f.write_all(&b).await {
                    tracing::warn!(error = %e, "capture: response body write failed");
                    break;
                }
            }
            let _ = f.flush().await;
            let _ = done_tx.send(());
        });
        Some(BodyTee {
            tx,
            done: Some(done_rx),
        })
    }
}

/// Copies response body chunks to the capture file in the background.
#[derive(Debug)]
pub struct BodyTee {
    tx: mpsc::UnboundedSender<Bytes>,
    done: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl BodyTee {
    /// Queues a chunk.
    pub fn write(&self, b: &Bytes) {
        let _ = self.tx.send(b.clone());
    }

    /// Closes the file; resolves once everything queued is written.
    pub fn close(mut self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        self.done.take()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn writes_masked_headers_and_exact_body() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("cap");
        let cap = Capture::open(&CaptureConfig {
            dir: cdir.clone(),
            retention_secs: 60,
        })
        .unwrap();
        assert_eq!(
            std::fs::metadata(&cdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut h = http::HeaderMap::new();
        h.insert("authorization", "Bearer agent-token-value".parse().unwrap());
        h.insert("x-api-key", "agent-api-key-value".parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        let body = b"{\"a\":\"\xe2\x9f\xa6scrim:x:0123456789ab\xe2\x9f\xa7\"}";
        let rec = cap
            .request(
                "anthropic",
                &http::Method::POST,
                &"http://u/v1/messages".parse().unwrap(),
                &h,
                body,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(rec.path("request.body")).unwrap(), body);
        let meta = std::fs::read_to_string(rec.path("request.json")).unwrap();
        assert!(!meta.contains("agent-token-value") && !meta.contains("agent-api-key-value"));
        assert!(meta.contains("application/json") && meta.contains("[masked]"));
        let mode = std::fs::metadata(rec.path("request.body"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let body_path = rec.path("response.body");
        let tee = rec
            .response(http::StatusCode::OK, &http::HeaderMap::new())
            .await
            .unwrap();
        tee.write(&Bytes::from_static(b"part1 "));
        tee.write(&Bytes::from_static(b"part2"));
        tee.close().unwrap().await.unwrap();
        assert_eq!(std::fs::read(body_path).unwrap(), b"part1 part2");
    }

    #[test]
    fn refuses_world_readable_dir() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("open");
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Capture::open(&CaptureConfig {
                dir: p,
                retention_secs: 1
            }),
            Err(CaptureError::Permissive(..))
        ));
    }

    #[test]
    fn sweep_removes_old_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c");
        let cap = Capture::open(&CaptureConfig {
            dir: p.clone(),
            retention_secs: 3600,
        })
        .unwrap();
        let old = p.join("1-000000-a.request.body");
        let new = p.join("2-000001-a.request.body");
        let other = p.join("notes.txt");
        for f in [&old, &new, &other] {
            std::fs::write(f, b"x").unwrap();
        }
        let past = SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(past)
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&other)
            .unwrap()
            .set_modified(past)
            .unwrap();
        assert_eq!(cap.sweep().unwrap(), 1);
        assert!(!old.exists() && new.exists() && other.exists());
    }
}
