//! Test support (Linux, feature `tpm`): a fresh `swtpm` per test (D12) and a
//! recording transport proxy for the parameter-encryption tests (F103).
//! Only `swtpm` is ever used; no real TPM (spec 0 item 8; E2).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::TpmTarget;

/// Whether a missing `swtpm` must fail the test run (CI sets it).
fn required() -> bool {
    std::env::var_os("PVAULT_TEST_REQUIRE_SWTPM").is_some()
}

/// Two consecutive free local ports (command, control).
fn free_pair() -> Option<u16> {
    for _ in 0..64 {
        let a = TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let p = a.local_addr().ok()?.port();
        if p == u16::MAX {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", p + 1)).is_ok() {
            return Some(p);
        }
    }
    None
}

/// A running emulator with its own throwaway state.
pub(crate) struct Swtpm {
    child: Child,
    dir: PathBuf,
    /// Command port (control is `port + 1`).
    pub(crate) port: u16,
}

impl Swtpm {
    /// Starts a fresh emulator, or returns `None` (with a notice) when
    /// `swtpm` is not installed and `PVAULT_TEST_REQUIRE_SWTPM` is unset.
    pub(crate) fn start() -> Option<Self> {
        // Starts processes: only in the isolated test process.
        crate::test_process::assert_isolated();
        if Command::new("swtpm").arg("--version").output().is_err() {
            assert!(!required(), "swtpm is required (PVAULT_TEST_REQUIRE_SWTPM)");
            eprintln!("skipped: swtpm is not installed");
            return None;
        }
        for _ in 0..8 {
            let Some(port) = free_pair() else { continue };
            let dir = std::env::temp_dir().join(format!(
                "pvault-swtpm-{}-{}",
                std::process::id(),
                hex::encode(crate::crypto::random::array::<8>().unwrap())
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let child = Command::new("swtpm")
                .args(["socket", "--tpm2", "--tpmstate"])
                .arg(format!("dir={}", dir.display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
                .args(["--flags", "not-need-init,startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut s = Self { child, dir, port };
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Some(s);
                }
                if s.child.try_wait().ok().flatten().is_some() {
                    break; // port taken meanwhile: retry with another pair
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = s.child.kill();
        }
        panic!("swtpm did not start");
    }

    pub(crate) fn target(&self) -> TpmTarget {
        TpmTarget::Swtpm { port: self.port }
    }

    /// Runs a `tpm2-tools` command against this emulator only.
    pub(crate) fn tool(&self, args: &[&str]) -> Output {
        let out = Command::new(args[0])
            .args(&args[1..])
            .env(
                "TPM2TOOLS_TCTI",
                format!("swtpm:host=127.0.0.1,port={}", self.port),
            )
            .output()
            .unwrap_or_else(|e| panic!("{}: {e}", args[0]));
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Short lockout parameters on this emulator (D12): `tries` failures,
    /// then lockout for 600 s.
    pub(crate) fn short_lockout(&self, tries: u32) {
        self.tool(&[
            "tpm2_dictionarylockout",
            "--setup-parameters",
            &format!("--max-tries={tries}"),
            "--recovery-time=600",
            "--lockout-recovery-time=600",
        ]);
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Lower-case hex without a dependency.
mod hex {
    pub(crate) fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
    }
}

/// A transparent proxy in front of an emulator that records every byte of
/// the command channel in both directions (F103). The control channel is
/// forwarded unrecorded.
pub(crate) struct Recorder {
    /// The proxy's command port (control is `port + 1`).
    pub(crate) port: u16,
    captured: Arc<Mutex<Vec<u8>>>,
}

fn pump(mut from: TcpStream, mut to: TcpStream, log: Option<Arc<Mutex<Vec<u8>>>>) {
    let mut buf = [0u8; 4096];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(std::net::Shutdown::Write);
                return;
            }
            Ok(n) => {
                if let Some(l) = &log {
                    l.lock().unwrap().extend_from_slice(&buf[..n]);
                }
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

fn forward(listener: TcpListener, upstream: u16, log: Option<Arc<Mutex<Vec<u8>>>>) {
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { return };
            let Ok(server) = TcpStream::connect(("127.0.0.1", upstream)) else {
                return;
            };
            let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let (l1, l2) = (log.clone(), log.clone());
            std::thread::spawn(move || pump(client, server, l1));
            std::thread::spawn(move || pump(s2, c2, l2));
        }
    });
}

impl Recorder {
    pub(crate) fn start(upstream: &Swtpm) -> Self {
        let port = free_pair().expect("free ports");
        let cmd = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let ctrl = TcpListener::bind(("127.0.0.1", port + 1)).unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        forward(cmd, upstream.port, Some(captured.clone()));
        forward(ctrl, upstream.port + 1, None);
        Self { port, captured }
    }

    pub(crate) fn target(&self) -> TpmTarget {
        TpmTarget::Swtpm { port: self.port }
    }

    /// Everything recorded so far.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.captured.lock().unwrap().clone()
    }

    /// Whether `needle` occurs in the recorded bytes.
    pub(crate) fn saw(&self, needle: &[u8]) -> bool {
        let hay = self.bytes();
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }
}
