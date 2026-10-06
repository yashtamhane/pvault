//! Cross-process scenario and crash tests for Milestone 4 (spec 11, 12;
//! `docs/M4_READINESS.md` 1.2, 6.1, 9.6, 7.5, 11.2).
//!
//! This test binary is also the CLI under test: when started with
//! `PVAULT_TEST_CLI` (or as the estimator child) it runs `pvault_cli::main`,
//! built with `fault-injection`. Each crash test starts it with
//! `PVAULT_FAILPOINT=<name>[#n]`, lets it abort there, then restarts it in a
//! new process and checks the exact state on disk. Children never read a
//! terminal (`PVAULT_TEST_NO_TERMINAL`), so every confirmation is declined,
//! as in a non-interactive run; the one exception is the PNG workflow, whose
//! child gets a pseudo-terminal of its own (Unix).

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "PVAULT_TEST_CLI";
const PW: &[u8] = b"correct horse battery staple violin quantum harbor 9172\n";
const FAST: [&str; 6] = [
    "--kdf-memory",
    "256",
    "--kdf-iterations",
    "3",
    "--kdf-parallelism",
    "1",
];

fn main() -> ExitCode {
    let first = std::env::args_os().nth(1);
    if std::env::var_os(CHILD_ENV).is_some()
        || first.as_deref() == Some(OsStr::new(pvault_core::estimator::CHILD_ARG))
    {
        return pvault_cli::main();
    }
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let tests: Vec<(&str, fn())> = vec![
        (
            "basic_commands_and_copied_vault",
            basic_commands_and_copied_vault,
        ),
        ("noninteractive_init_branches", noninteractive_init_branches),
        (
            "png_verification_waits_for_terminal_acknowledgment",
            png_verification_waits_for_terminal_acknowledgment,
        ),
        ("fat_exfat_images", fat_exfat_images),
        (
            "digital_cards_through_the_cli",
            digital_cards_through_the_cli,
        ),
        ("digital_crash_at_each_step", digital_crash_at_each_step),
        #[cfg(unix)]
        (
            "digital_card_check_after_commit",
            digital_card_check_after_commit,
        ),
        (
            "ownership_ignored_mounts_are_refused",
            ownership_ignored_mounts_are_refused,
        ),
        (
            "unverifiable_destinations_are_refused",
            unverifiable_destinations_are_refused,
        ),
        #[cfg(unix)]
        (
            "native_termination_and_cancellation",
            native_termination_and_cancellation,
        ),
        ("init_crash_at_each_step", init_crash_at_each_step),
        ("add_crash_at_each_step", add_crash_at_each_step),
        ("replace_crash_at_each_step", replace_crash_at_each_step),
        ("rm_crash_at_each_step", rm_crash_at_each_step),
        ("export_crash_at_each_step", export_crash_at_each_step),
        (
            "native_paths_are_rendered_safely",
            native_paths_are_rendered_safely,
        ),
    ];
    let selected: Vec<_> = tests
        .into_iter()
        .filter(|(n, _)| filter.is_empty() || filter.iter().any(|f| n.contains(f.as_str())))
        .collect();
    println!("running {} tests", selected.len());
    let started = Instant::now();
    let failed = std::sync::Mutex::new(Vec::new());
    let counts = std::sync::Mutex::new((0usize, 0usize)); // passed, skipped
    let queue = std::sync::Mutex::new(selected);
    std::thread::scope(|s| {
        for _ in 0..3 {
            s.spawn(|| {
                loop {
                    let Some((name, f)) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let t = Instant::now();
                    SKIPS.with(|k| k.borrow_mut().clear());
                    let ok = std::panic::catch_unwind(f).is_ok();
                    let skips = SKIPS.with(|k| k.borrow_mut().split_off(0));
                    let whole = skips.iter().any(|(all, _)| *all);
                    let status = match (ok, whole, skips.is_empty()) {
                        (false, _, _) => "FAILED".to_owned(),
                        (true, true, _) => "SKIPPED".to_owned(),
                        (true, false, true) => "ok".to_owned(),
                        (true, false, false) => "ok, with parts skipped".to_owned(),
                    };
                    println!(
                        "test {name} ... {status} ({:.1}s)",
                        t.elapsed().as_secs_f64()
                    );
                    for (_, why) in &skips {
                        println!("    skipped: {why}");
                    }
                    if !ok {
                        failed.lock().unwrap().push(name);
                    } else if whole {
                        counts.lock().unwrap().1 += 1;
                    } else {
                        counts.lock().unwrap().0 += 1;
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap();
    let (passed, skipped) = counts.into_inner().unwrap();
    println!(
        "\ntest result: {}. {passed} passed; {} failed; {skipped} skipped; finished in {:.1}s",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len(),
        started.elapsed().as_secs_f64()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        for f in failed {
            println!("    {f}");
        }
        ExitCode::from(101)
    }
}

// ---------------------------------------------------------------- harness

thread_local! {
    /// Skips reported by the running test: (whole test?, reason).
    static SKIPS: std::cell::RefCell<Vec<(bool, String)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Reports that this whole test could not run here (never shown as "ok").
fn skip_all(reason: impl Into<String>) {
    SKIPS.with(|k| k.borrow_mut().push((true, reason.into())));
}

/// Reports that part of this test could not run here.
fn skip_part(reason: impl Into<String>) {
    SKIPS.with(|k| k.borrow_mut().push((false, reason.into())));
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    /// Aborted at the failpoint. Unix: killed by SIGABRT (no exit code).
    /// Windows: Rust's `abort` is a fast-fail, which ends the process with
    /// `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409).
    fn crashed(&self) -> bool {
        if cfg!(windows) {
            self.code == Some(0xC000_0409_u32 as i32)
        } else {
            self.code.is_none()
        }
    }

    fn expect(&self, code: i32, what: &str) -> &Self {
        assert_eq!(
            self.code,
            Some(code),
            "{what}: exit {:?}\nstdout: {}\nstderr: {}",
            self.code,
            self.stdout,
            self.stderr
        );
        self
    }

    fn says(&self, text: &str) -> bool {
        self.stderr.contains(text)
    }
}

struct Env {
    dir: tempfile::TempDir,
    /// The vault folder, when not `<root>/vault` (for example on an image).
    vault_at: Option<PathBuf>,
    /// The card folder, when not `<root>/cards`.
    cards_at: Option<PathBuf>,
}

fn arg<S: AsRef<OsStr> + ?Sized>(s: &S) -> OsString {
    s.as_ref().to_owned()
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("pvault-scn-")
            .tempdir()
            .unwrap();
        std::fs::create_dir(dir.path().join("cards")).unwrap();
        Self {
            dir,
            vault_at: None,
            cards_at: None,
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn vault(&self) -> PathBuf {
        self.vault_at
            .clone()
            .unwrap_or_else(|| self.root().join("vault"))
    }

    fn cards(&self) -> PathBuf {
        self.cards_at
            .clone()
            .unwrap_or_else(|| self.root().join("cards"))
    }

    /// Runs with a pseudo-terminal as the child's controlling terminal
    /// (Unix): each `(prompt, reply)` waits for `prompt` on the terminal and
    /// types `reply` and Enter. Standard input stays a pipe.
    // Used by the Linux non-UTF-8 cleanup case.
    #[cfg(target_os = "linux")]
    fn run_tty(&self, args: &[OsString], stdin: &[u8], answers: &[(&str, &str)]) -> (Out, String) {
        let tty = pty::open();
        let mut cmd = self.command(args, None);
        cmd.env_remove("PVAULT_TEST_NO_TERMINAL");
        pty::make_controlling(&mut cmd, &tty.slave);
        let mut child = cmd.spawn().unwrap();
        let screen = pty::Screen::start(&tty.master);
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin);
        drop(input);
        for (prompt, reply) in answers {
            let deadline = Instant::now() + Duration::from_secs(180);
            while !screen.text().contains(prompt) {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "ended before {prompt:?}: {}",
                    screen.text()
                );
                assert!(Instant::now() < deadline, "no prompt {prompt:?}");
                std::thread::sleep(Duration::from_millis(20));
            }
            (&tty.master)
                .write_all(format!("{reply}\n").as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let shown = screen.text();
        drop(tty);
        (
            Out {
                code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            },
            shown,
        )
    }

    fn command(&self, args: &[OsString], failpoint: Option<&str>) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.arg("--secrets-stdin")
            .args(args)
            .env(CHILD_ENV, "1")
            .env("PVAULT_TEST_NO_TERMINAL", "1")
            .env("PVAULT_CONFIG_DIR", self.root().join("settings"))
            .env_remove("PVAULT_FAILPOINT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(fp) = failpoint {
            c.env("PVAULT_FAILPOINT", fp);
        }
        c
    }

    fn run(&self, args: &[OsString], stdin: &[u8], failpoint: Option<&str>) -> Out {
        self.run_env(args, stdin, failpoint, &[])
    }

    /// As `run`, with extra environment variables for the child.
    fn run_env(
        &self,
        args: &[OsString],
        stdin: &[u8],
        failpoint: Option<&str>,
        vars: &[(&str, &OsStr)],
    ) -> Out {
        let mut cmd = self.command(args, failpoint);
        cmd.envs(vars.iter().copied());
        let mut child = cmd.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin);
        drop(input);
        let out = child.wait_with_output().unwrap();
        Out {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Runs a vault command with the passphrase on standard input.
    fn pv(&self, cmd: &str, rest: &[&str], failpoint: Option<&str>) -> Out {
        let mut args = vec![arg(cmd), arg(&self.vault())];
        args.extend(rest.iter().map(arg));
        self.run(&args, PW, failpoint)
    }

    fn source(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.root().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn add(&self, src: &Path, path: &str, extra: &[&str], failpoint: Option<&str>) -> Out {
        let mut rest = vec![src.to_str().unwrap(), path];
        rest.extend(extra);
        self.pv("add", &rest, failpoint)
    }

    fn list(&self) -> Out {
        self.pv("list", &[], None)
    }

    /// The card files, once both are completely written.
    fn card_files(&self) -> Option<(String, String)> {
        let mut a = None;
        let mut b = None;
        for e in std::fs::read_dir(self.cards()).ok()? {
            let p = e.ok()?.path();
            // macOS keeps extended attributes of files on FAT/exFAT in
            // `._<name>` AppleDouble sidecars; they are not card files.
            if p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("._"))
            {
                continue;
            }
            let text = std::fs::read_to_string(&p).ok()?;
            if !text.ends_with("</svg>\n") {
                return None;
            }
            let name = p.file_name()?.to_string_lossy().into_owned();
            if name.ends_with("card-a.svg") {
                a = Some(text);
            } else if name.ends_with("card-b.svg") {
                b = Some(text);
            }
        }
        Some((a?, b?))
    }

    /// `init`, supplying the card lines only after the cards exist (CLI
    /// 6.1). `lines` builds the remaining input from the two card texts.
    /// `close_early`: standard input ends after `first` (the command must
    /// stop before the cards).
    fn init_with(
        &self,
        first: &[u8],
        extra: &[&str],
        failpoint: Option<&str>,
        close_early: bool,
        lines: impl FnOnce(&str, &str) -> Vec<u8>,
    ) -> Out {
        let mut args = vec![
            arg("init"),
            arg(&self.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&self.cards()),
            arg("--custom"),
        ];
        args.extend(FAST.iter().map(arg));
        args.extend(extra.iter().map(arg));
        let mut child = self.command(&args, failpoint).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(first);
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut lines = Some(lines);
        if close_early {
            drop(input);
            let out = child.wait_with_output().unwrap();
            return Out {
                code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            };
        }
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if let Some((a, b)) = self.card_files() {
                let rest = lines.take().unwrap()(&card_text(&a), &card_text(&b));
                let _ = input.write_all(&rest);
                break;
            }
            assert!(Instant::now() < deadline, "init did not write its cards");
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(input);
        let out = child.wait_with_output().unwrap();
        Out {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn init(&self, failpoint: Option<&str>) -> Out {
        self.init_with(&[PW, PW].concat(), &[], failpoint, false, |a, b| {
            [a.as_bytes(), b"\n", b.as_bytes(), b"\n", PW].concat()
        })
    }

    /// Runs `init` with PNG card verification through the real CLI, with
    /// a pseudo-terminal as the child's controlling terminal (decided
    /// 2026-10-06, O1). Secrets come from standard input (`--secrets-stdin`);
    /// the printing acknowledgment comes from the terminal. The photos are
    /// written only after the acknowledgment prompt has appeared on the
    /// terminal, and Enter is pressed only after they are complete, so the
    /// CLI can only succeed if it opens them after the acknowledgment.
    /// `photos(a_svg, b_svg)` returns the photo bytes for Card A and B (B
    /// ignored unless `both`).
    #[cfg(unix)]
    fn init_with_terminal_pngs(
        &self,
        both: bool,
        photos: impl FnOnce(&str, &str) -> (Option<Vec<u8>>, Vec<u8>),
    ) -> (Out, String) {
        let a_png = self.root().join("card-a.png");
        let b_png = self.root().join("card-b.png");
        let mut args = vec![
            arg("init"),
            arg(&self.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&self.cards()),
            arg("--custom"),
            arg("--card-a-png"),
            arg(&a_png),
        ];
        if both {
            args.extend([arg("--card-b-png"), arg(&b_png)]);
        }
        args.extend(FAST.iter().map(arg));
        let tty = pty::open();
        let mut cmd = self.command(&args, None);
        cmd.env_remove("PVAULT_TEST_NO_TERMINAL");
        pty::make_controlling(&mut cmd, &tty.slave);
        let mut child = cmd.spawn().unwrap();
        let screen = pty::Screen::start(&tty.master);
        let mut input = child.stdin.take().unwrap();
        // Lines 1 and 2; with two photos the type-back line too (3 lines).
        let mut first = [PW, PW].concat();
        if both {
            first.extend_from_slice(PW);
        }
        input.write_all(&first).unwrap();
        let prompt = "save the PNG photos at the paths you gave, then press Enter";
        let deadline = Instant::now() + Duration::from_secs(180);
        while !screen.text().contains(prompt) {
            assert!(
                child.try_wait().unwrap().is_none(),
                "init ended before the acknowledgment: {}",
                screen.text()
            );
            assert!(Instant::now() < deadline, "no acknowledgment prompt");
            std::thread::sleep(Duration::from_millis(20));
        }
        // The prompt is waiting: only now do the photos come into being.
        let (a, b) = self.card_files().expect("cards written before the prompt");
        let (pa, pb) = photos(&a, &b);
        if let Some(pa) = pa {
            std::fs::write(&a_png, pa).unwrap();
        }
        if both {
            std::fs::write(&b_png, pb).unwrap();
        } else {
            // Four lines: Card B's text, then the type-back.
            input
                .write_all(&[card_text(&b).as_bytes(), b"\n", PW].concat())
                .unwrap();
        }
        drop(input);
        (&tty.master).write_all(b"\n").unwrap();
        let out = child.wait_with_output().unwrap();
        let shown = screen.text();
        drop(tty);
        (
            Out {
                code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            },
            shown,
        )
    }

    fn names(&self, dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn vault_names(&self) -> Vec<String> {
        self.names(&self.vault())
    }

    /// A copy of `from`'s vault folder (F15: a copied vault opens).
    fn copy_vault_from(from: &Env) -> Env {
        let to = Env::new();
        copy_tree(&from.vault(), &to.vault());
        to
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

/// The Base32 lines of a card file, joined with spaces (one stdin line).
fn card_text(svg: &str) -> String {
    svg.split("font-size=\"16\">")
        .skip(1)
        .map(|s| s.split('<').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(unix)]
/// A PNG containing the SVG card's exact QR payload. This deliberately
/// crosses the public card APIs used by the CLI rather than calling a
/// core-only test helper.
fn card_png(svg: &str) -> Vec<u8> {
    let payload = pvault_core::card::decode_base32(card_text(svg).as_bytes()).unwrap();
    let (width, dark) = pvault_core::card::qr_matrix(payload.expose_secret()).unwrap();
    let scale = 5usize;
    let side = (width + 8) * scale;
    let mut gray = vec![255u8; side * side];
    for y in 0..width {
        for x in 0..width {
            if dark[y * width + x] {
                for dy in 0..scale {
                    for dx in 0..scale {
                        gray[((y + 4) * scale + dy) * side + (x + 4) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, side as u32, side as u32);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().unwrap();
        writer.write_image_data(&gray).unwrap();
    }
    out
}

/// A pseudo-terminal for the PNG workflow (Unix). The child becomes a
/// session leader with the slave as its controlling terminal, so the CLI's
/// `/dev/tty` is this terminal while standard input stays a pipe.
#[cfg(unix)]
#[allow(unsafe_code)]
mod pty {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    pub struct Pty {
        pub master: File,
        pub slave: File,
    }

    pub fn open() -> Pty {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both out-pointers are valid; the optional arguments are
        // null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // SAFETY: `openpty` returned two new descriptors owned by nothing
        // else.
        unsafe {
            Pty {
                master: File::from_raw_fd(master),
                slave: File::from_raw_fd(slave),
            }
        }
    }

    pub fn make_controlling(cmd: &mut Command, slave: &File) {
        let fd = slave.as_raw_fd();
        // SAFETY: the closure runs in the forked child before `exec` and
        // calls only async-signal-safe functions (`setsid`, `ioctl`); `fd`
        // stays open in the child until `exec` (close-on-exec).
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(fd, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// Whether the terminal's echo flag is set.
    pub fn echo_on(slave: &File) -> bool {
        let mut t = core::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `slave` is an open terminal descriptor; `t` is writable.
        let rc = unsafe { libc::tcgetattr(slave.as_raw_fd(), t.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SAFETY: `tcgetattr` succeeded and initialized `t`.
        unsafe { t.assume_init() }.c_lflag & libc::ECHO != 0
    }

    /// Everything the child writes to its terminal.
    pub struct Screen(Arc<Mutex<Vec<u8>>>);

    impl Screen {
        pub fn start(master: &File) -> Self {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let (sink, mut reader) = (buf.clone(), master.try_clone().unwrap());
            std::thread::spawn(move || {
                let mut chunk = [0u8; 1024];
                while let Ok(n) = reader.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&chunk[..n]);
                }
            });
            Self(buf)
        }

        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }
}

const LOCKS: [&str; 2] = ["vault.gate", "vault.lock"];

// ------------------------------------------------------------------ tests

/// F15, F16, F79 (argument part), CLI 6.2 to 6.7.
fn basic_commands_and_copied_vault() {
    let env = Env::new();
    env.init(None).expect(0, "init");
    assert!(env.names(&env.cards()).is_empty(), "card files deleted");
    let src = env.source("a.txt", &vec![3u8; 50_000]);
    env.add(&src, "docs/a.txt", &[], None).expect(0, "add");
    let listing = env.list();
    listing.expect(0, "list");
    assert!(listing.stdout.contains("file\t50000\t") && listing.stdout.ends_with("\tdocs/a.txt\n"));
    let dest = env.root().join("out.txt");
    env.pv("get", &["docs/a.txt", dest.to_str().unwrap()], None)
        .expect(0, "get");
    assert_eq!(std::fs::read(&dest).unwrap(), std::fs::read(&src).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "F51: owner-only export");
    }
    // F15: a copy opens; F16: a wrong passphrase is `Unlock failed.`
    let copy = Env::copy_vault_from(&env);
    copy.list().expect(0, "copied vault list");
    let wrong = copy.run(
        &[arg("list"), arg(&copy.vault())],
        b"not the passphrase\n",
        None,
    );
    wrong.expect(1, "wrong passphrase");
    assert!(wrong.says("Unlock failed."));
    // Refusals.
    env.pv("get", &["docs/a.txt", "x", "--force"], None)
        .expect(2, "--force");
    let bound = env.run(
        &[
            arg("init"),
            arg(&env.root().join("v2")),
            arg("--mode"),
            arg("bound"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&env.cards()),
        ],
        b"",
        None,
    );
    bound.expect(2, "bound mode");
    assert!(bound.says("Bound mode is not available in this version."));
    env.run(
        &[
            arg("list"),
            arg(&env.vault()),
            arg("--passphrase"),
            arg("x"),
        ],
        b"",
        None,
    )
    .expect(2, "no secret options (F79)");
    let generated = env.run(
        &[
            arg("init"),
            arg(&env.root().join("v3")),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&env.cards()),
        ],
        b"",
        None,
    );
    generated.expect(6, "generated mode needs a terminal");
    assert_eq!(env.names(&env.root().join("v3")), LOCKS);
    // status: public state on stdout, no passphrase read.
    let status = env.run(&[arg("status"), arg(&env.vault())], b"", None);
    status.expect(0, "status");
    assert!(status.stdout.contains("Mode:                portable"));
    assert!(
        status
            .stdout
            .contains("Generation:          2   (key table 2)")
    );
    // rm.
    env.pv("rm", &["docs"], None)
        .expect(1, "rm non-empty folder");
    env.pv("rm", &["docs", "--recursive"], None)
        .expect(0, "rm -r");
    assert!(env.names(&env.vault().join("objects")).is_empty());
    env.run(&[arg("clean-partials")], b"", None)
        .expect(0, "clean-partials");
}

/// F79 and CLI 6.1: every non-interactive `init` branch and its line count.
fn noninteractive_init_branches() {
    let early = |first: &[u8]| {
        let env = Env::new();
        let out = env.init_with(first, &[], None, true, |_, _| Vec::new());
        (env, out)
    };
    let fresh = |lines: fn(&str, &str) -> Vec<u8>| {
        let env = Env::new();
        let out = env.init_with(&[PW, PW].concat(), &[], None, false, lines);
        (env, out)
    };
    let rolled_back = |env: &Env| {
        assert_eq!(
            env.vault_names(),
            LOCKS,
            "only the bootstrap creations remain"
        );
        assert!(env.names(&env.cards()).is_empty(), "card files deleted");
    };
    // Mismatched confirmation: two lines, nothing written.
    let (env, out) = early(&[PW, b"other\n"].concat());
    out.expect(1, "mismatch");
    assert!(out.says("The passphrases do not match."));
    rolled_back(&env);
    // End of input at line 2, and an unterminated line 2.
    let (env, out) = early(PW);
    out.expect(1, "eof at line 2");
    assert!(out.says("Input ended before all secrets were read."));
    rolled_back(&env);
    let (env, out) = early(&[PW, &PW[..PW.len() - 1]].concat());
    out.expect(1, "unterminated line 2");
    rolled_back(&env);
    // Weak: refused, nothing written.
    let (env, out) = early(b"password1\npassword1\n");
    out.expect(1, "weak");
    assert!(out.says("too weak"));
    rolled_back(&env);
    // Card mismatch (Card B's text for Card A): one attempt, rolled back.
    let (env, out) = fresh(|_, b| [b.as_bytes(), b"\n", b.as_bytes(), b"\n", PW].concat());
    out.expect(1, "card mismatch");
    assert!(
        out.says("Card A does not match what was printed."),
        "{}",
        out.stderr
    );
    rolled_back(&env);
    env.run(&[arg("clean-partials")], b"", None)
        .expect(0, "no stale cards");
    // 215 and 217 symbols.
    let (env, out) = fresh(|a, _| [&a.as_bytes()[..a.len() - 1], b"\n"].concat());
    out.expect(1, "215 symbols");
    assert!(
        out.says("The card text must have 216 characters; 215 were entered."),
        "{}",
        out.stderr
    );
    rolled_back(&env);
    let (env, out) = fresh(|a, _| [a.as_bytes(), b"Z\n"].concat());
    out.expect(1, "217 symbols");
    assert!(out.says("more than 216 symbols"));
    rolled_back(&env);
    // End of input at Card B and at the type-back line.
    let (env, out) = fresh(|a, _| [a.as_bytes(), b"\n"].concat());
    out.expect(1, "eof at card B");
    assert!(out.says("Input ended before all secrets were read."));
    rolled_back(&env);
    let (env, out) = fresh(|a, b| [a.as_bytes(), b"\n", b.as_bytes(), b"\n"].concat());
    out.expect(1, "eof at type-back");
    rolled_back(&env);
    // Type-back mismatch: one attempt.
    let (env, out) = fresh(|a, b| [a.as_bytes(), b"\n", b.as_bytes(), b"\n", b"wrong\n"].concat());
    out.expect(1, "type-back mismatch");
    rolled_back(&env);
    // Five lines: success.
    let env = Env::new();
    env.init(None).expect(0, "five lines");
}

/// O1 (2026-10-06): PNG card verification needs a terminal, also with
/// `--secrets-stdin`, and opens the photos only after the printing
/// acknowledgment. Without a terminal: refused before anything exists. With
/// one (Unix pseudo-terminal): the approved 3-line and 4-line branches; a
/// photo of the wrong card and a photo still missing at Enter are refused
/// and roll back. Windows has no pseudo-terminal here: manual gate step 13.
fn png_verification_waits_for_terminal_acknowledgment() {
    let env = Env::new();
    let png = env.root().join("a.png");
    let out = env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&env.cards()),
            arg("--custom"),
            arg("--card-a-png"),
            arg(&png),
        ],
        &[PW, PW, PW].concat(),
        None,
    );
    out.expect(6, "png without a terminal");
    assert!(out.says("needs a terminal"), "{}", out.stderr);
    assert!(!env.vault().exists(), "nothing was written");
    assert!(
        !env.root().join("settings").exists(),
        "not even the settings folder"
    );
    #[cfg(unix)]
    {
        // Three lines: both cards from photos.
        let env = Env::new();
        let (out, screen) =
            env.init_with_terminal_pngs(true, |a, b| (Some(card_png(a)), card_png(b)));
        out.expect(0, &format!("three-line two-PNG init; terminal: {screen}"));
        assert!(env.vault().join("vault.hdr").exists());
        assert!(env.names(&env.cards()).is_empty());
        // Four lines: Card A from a photo, Card B typed on standard input.
        let env = Env::new();
        let (out, screen) =
            env.init_with_terminal_pngs(false, |a, _| (Some(card_png(a)), Vec::new()));
        out.expect(0, &format!("four-line one-PNG init; terminal: {screen}"));
        // A photo of Card B given for Card A: one attempt, rolled back.
        let env = Env::new();
        let (out, _) = env.init_with_terminal_pngs(true, |a, b| (Some(card_png(b)), card_png(a)));
        out.expect(1, "wrong photo");
        assert!(
            out.says("Card A does not match what was printed."),
            "{}",
            out.stderr
        );
        assert_eq!(env.vault_names(), LOCKS);
        assert!(env.names(&env.cards()).is_empty());
        // No photo when Enter is pressed: refused, rolled back.
        let env = Env::new();
        let (out, _) = env.init_with_terminal_pngs(true, |_, b| (None, card_png(b)));
        out.expect(1, "missing photo");
        assert_eq!(env.vault_names(), LOCKS);
    }
}

/// Every file under `dir` with its bytes.
fn tree_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(tree_bytes(&p));
        } else {
            out.push((p.clone(), std::fs::read(&p).unwrap()));
        }
    }
    out.sort();
    out
}

/// 6.3, F74, and the O3 destination refusals on real FAT, exFAT and (Linux)
/// FUSE `fuseblk` file systems (disposable
/// images mounted by CI or by hand; `PVAULT_TEST_FAT_DIR`,
/// `PVAULT_TEST_EXFAT_DIR`, each a writable folder on a mounted image).
/// Without them the test reports SKIPPED; with `PVAULT_TEST_REQUIRE_IMAGES`
/// a missing image fails. A mocked file-system type does not replace this.
fn fat_exfat_images() {
    let require = std::env::var_os("PVAULT_TEST_REQUIRE_IMAGES").is_some();
    let mut images = Vec::new();
    // `fuseblk`: exFAT mounted through FUSE (`exfat-fuse`), Linux only.
    for (label, var, needed) in [
        ("FAT", "PVAULT_TEST_FAT_DIR", true),
        ("exFAT", "PVAULT_TEST_EXFAT_DIR", true),
        (
            "exFAT via FUSE (fuseblk)",
            "PVAULT_TEST_FUSEBLK_DIR",
            cfg!(target_os = "linux"),
        ),
    ] {
        match std::env::var_os(var) {
            Some(dir) => images.push((label, PathBuf::from(dir))),
            None if require && needed => panic!("{var} is required but not set"),
            None => skip_part(format!("{label}: no image mounted ({var} not set)")),
        }
    }
    if images.is_empty() {
        skip_all("no FAT or exFAT image mounted");
        return;
    }
    let template = Env::new();
    template.init(None).expect(0, "template init");
    let data = vec![6u8; 70_000];
    template
        .add(&template.source("a", &data), "a", &[], None)
        .expect(0, "template add");
    for (label, root) in images {
        let base = tempfile::Builder::new()
            .prefix("pv-")
            .tempdir_in(&root)
            .unwrap();
        println!("    {label} image at {}", root.display());
        // The accepted vault-artifact identity (8.1) needs a birth time
        // (FUSE has none) and, on Windows, FILE_ID_INFO (FAT and exFAT have
        // none), so no vault there opens: it fails closed (exit 6).
        let reads = !label.contains("fuseblk") && !cfg!(windows);
        image_vault_refused(label, &template, base.path(), reads);
        image_export(label, &template, base.path());
        image_cards(label, base.path());
    }
}

/// F74: a vault on the image: `init` refused before creating its folder; a
/// copied vault opens read-only (list, get, status) and refuses add and rm
/// with nothing changed.
fn image_vault_refused(label: &str, template: &Env, base: &Path, reads: bool) {
    let mut env = Env::new();
    env.vault_at = Some(base.join("new-vault"));
    let out = env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&env.cards()),
            arg("--custom"),
        ],
        &[PW, PW].concat(),
        None,
    );
    out.expect(6, &format!("{label}: init on the image"));
    assert!(
        out.says("cannot safely store vault changes"),
        "{}",
        out.stderr
    );
    assert!(!env.vault().exists(), "{label}: nothing created");
    let mut env = Env::new();
    env.vault_at = Some(base.join("copied-vault"));
    copy_tree(&template.vault(), &env.vault());
    let before = tree_bytes(&env.vault());
    if !reads {
        // Fails closed before anything: the vault lock cannot be taken
        // without a stable file identity (8.1). Nothing is changed.
        for out in [
            env.list(),
            env.add(&env.source("b", b"b"), "b", &[], None),
            env.pv("rm", &["a"], None),
            env.run(&[arg("status"), arg(&env.vault())], b"", None),
        ] {
            out.expect(6, &format!("{label}: vault without a stable identity"));
            assert!(
                out.says("no stable file identity"),
                "{label}: {}",
                out.stderr
            );
        }
        assert_eq!(tree_bytes(&env.vault()), before, "{label}: vault unchanged");
        println!(
            "    {label}: vault refused (exit 6, no stable file identity, 8.1); reads unsupported"
        );
        return;
    }
    let list = env.list();
    list.expect(0, &format!("{label}: list on the image"));
    assert!(list.stdout.ends_with("\ta\n"));
    let dest = env.root().join("out");
    env.pv("get", &["a", dest.to_str().unwrap()], None)
        .expect(0, &format!("{label}: get from the image"));
    let add = env.add(&env.source("b", b"b"), "b", &[], None);
    add.expect(6, &format!("{label}: add on the image"));
    assert!(
        add.says("cannot safely store vault changes"),
        "{}",
        add.stderr
    );
    env.pv("rm", &["a"], None)
        .expect(6, &format!("{label}: rm on the image"));
    let status = env.run(&[arg("status"), arg(&env.vault())], b"", None);
    status.expect(0, &format!("{label}: status"));
    assert!(
        status.stdout.contains("read-only for pvault"),
        "{}",
        status.stdout
    );
    // The read-only commands may update nothing in the vault; the lock files
    // are opened, never written.
    assert_eq!(tree_bytes(&env.vault()), before, "{label}: vault unchanged");
}

/// Files and folders under `dir`, except macOS AppleDouble `._*` sidecars.
fn visible_entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with("._"))
        .collect();
    v.sort();
    v
}

/// O3 (decided 2026-10-06): exported plaintext on the image is refused
/// with exit 6 before any destination file exists, with an explanation and
/// a suggested destination; nothing is recorded either.
fn image_export(label: &str, template: &Env, base: &Path) {
    let env = Env::copy_vault_from(template);
    let dest_dir = base.join("exports");
    std::fs::create_dir(&dest_dir).unwrap();
    for name in ["out.bin".to_owned(), "n".repeat(250)] {
        let dest = dest_dir.join(&name);
        let out = env.pv("get", &["a", dest.to_str().unwrap()], None);
        out.expect(6, &format!("{label}: export to the image"));
        assert!(out.says("only where it can confirm"), "{}", out.stderr);
        assert!(out.says("Nothing was written.") && out.says("Choose a folder on"));
        assert!(
            visible_entries(&dest_dir).is_empty(),
            "{label}: no destination file"
        );
    }
    // Nothing was registered: there is nothing stale to clean.
    env.run(&[arg("clean-partials")], b"", None)
        .expect(0, &format!("{label}: no export recorded"));
    println!("    {label}: export refused (exit 6), no destination file");
}

/// O3: a card folder on the image is refused with exit 6 before anything is
/// created: no card file, no vault folder, no secret line read.
fn image_cards(label: &str, base: &Path) {
    let cards = base.join("cards");
    std::fs::create_dir(&cards).unwrap();
    let mut env = Env::new();
    env.cards_at = Some(cards.clone());
    let out = env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&cards),
            arg("--custom"),
        ],
        &[PW, PW, PW].concat(),
        None,
    );
    out.expect(6, &format!("{label}: card folder on the image"));
    assert!(out.says("only where it can confirm"), "{}", out.stderr);
    assert!(visible_entries(&cards).is_empty(), "{label}: no card file");
    assert!(!env.vault().exists(), "{label}: no vault folder");
    env.run(&[arg("clean-partials")], b"", None)
        .expect(0, &format!("{label}: no card file recorded"));
    // Digital: a card folder on the image is refused the same way.
    let env = Env::new();
    let mut args = env.digital_args(&ACK);
    let a = args.iter().position(|x| x == "--card-a-dir").unwrap();
    args[a + 1] = arg(&cards);
    let out = env.run(&args, &[PW, PW, PW].concat(), None);
    out.expect(6, &format!("{label}: digital card folder on the image"));
    assert!(out.says("only where it can confirm"), "{}", out.stderr);
    assert!(visible_entries(&cards).is_empty() && !env.vault().exists());
    println!("    {label}: card folder refused (exit 6), nothing created (paper and digital)");
}

/// O2 (2026-10-06), `docs/CLI.md` 3, on the real CLI with a terminal and no
/// `--secrets-stdin` (Unix): end of input (Ctrl-D) at the hidden passphrase
/// prompt is cancellation, exit 7; Ctrl-C is native termination by SIGINT
/// (no pvault exit code). Echo is off at the prompt; its restoration is
/// covered by the terminal module's pty tests.
#[cfg(unix)]
fn native_termination_and_cancellation() {
    use std::os::unix::process::ExitStatusExt;
    let env = Env::new();
    env.init(None).expect(0, "init");
    for (key, name) in [(4u8, "Ctrl-D"), (3u8, "Ctrl-C")] {
        let tty = pty::open();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([arg("list"), arg(&env.vault())])
            .env(CHILD_ENV, "1")
            .env("PVAULT_CONFIG_DIR", env.root().join("settings"))
            .env_remove("PVAULT_FAILPOINT")
            .env_remove("PVAULT_TEST_NO_TERMINAL")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        pty::make_controlling(&mut cmd, &tty.slave);
        let child = cmd.spawn().unwrap();
        let screen = pty::Screen::start(&tty.master);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !screen.text().contains("Passphrase: ") {
            assert!(Instant::now() < deadline, "{name}: no prompt");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Echo is off while the prompt waits.
        assert!(!pty::echo_on(&tty.slave), "{name}: echo off at the prompt");
        (&tty.master).write_all(&[key]).unwrap();
        let out = child.wait_with_output().unwrap();
        // The terminal is revoked when the session leader exits (macOS), so
        // echo restoration is checked by the terminal module's pty tests
        // (`restored_after_sigint`, `restored_after_cancellation`).
        match key {
            4 => assert_eq!(
                out.status.code(),
                Some(7),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
            _ => {
                assert_eq!(out.status.code(), None, "{name}: no pvault exit code");
                assert_eq!(
                    out.status.signal(),
                    Some(libc::SIGINT),
                    "{name}: ended by SIGINT"
                );
            }
        }
        drop(tty);
    }
}

/// O3 (fail closed) with real destinations that cannot be verified, through
/// the real CLI and with **empty standard input**: a refusal must come
/// before any secret is read (otherwise the exit would be 1, "Input ended"),
/// before the settings folder or the vault folder is created, and with no
/// destination file. Unknown types: Linux `/proc` (`proc`), macOS `/dev`
/// (`devfs`). Network: Windows loopback share `\\localhost\C$\...`, which
/// the 8.5 identification refuses as remote.
fn unverifiable_destinations_are_refused() {
    let template = Env::new();
    template.init(None).expect(0, "template init");
    template
        .add(&template.source("a", b"x"), "a", &[], None)
        .expect(0, "add");
    #[cfg(target_os = "linux")]
    let places = vec![("proc", PathBuf::from("/proc"))];
    #[cfg(target_os = "macos")]
    let places = vec![("devfs", PathBuf::from("/dev"))];
    #[cfg(windows)]
    let places = {
        let local = std::fs::canonicalize(template.root()).unwrap();
        let text = local
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_owned();
        let (drive, rest) = text.split_once(':').expect("a drive path");
        vec![(
            "loopback share",
            PathBuf::from(format!(r"\\localhost\{drive}${rest}")),
        )]
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let places: Vec<(&str, PathBuf)> = Vec::new();
    for (label, dir) in places {
        // Export: refused before the unlock.
        let env = Env::copy_vault_from(&template);
        let dest = dir.join("pvault-o3-out.bin");
        let out = env.run(
            &[arg("get"), arg(&env.vault()), arg("a"), arg(&dest)],
            b"",
            None,
        );
        out.expect(6, &format!("{label}: export"));
        assert!(
            out.says("only where it can confirm"),
            "{label}: {}",
            out.stderr
        );
        assert!(!out.says("Input ended"), "{label}: no secret read");
        assert!(!dest.exists(), "{label}: no destination file");
        assert!(
            !env.root().join("settings").exists(),
            "{label}: nothing created"
        );
        // Card folder: refused before the vault folder exists.
        let env = Env::new();
        let out = env.run(
            &[
                arg("init"),
                arg(&env.vault()),
                arg("--mode"),
                arg("portable"),
                arg("--cards"),
                arg("paper"),
                arg("--cards-dir"),
                arg(&dir),
                arg("--custom"),
            ],
            b"",
            None,
        );
        out.expect(6, &format!("{label}: card folder"));
        assert!(
            out.says("only where it can confirm"),
            "{label}: {}",
            out.stderr
        );
        assert!(!env.vault().exists(), "{label}: no vault folder");
        // The vault itself stays readable: export to a private folder.
        let ok = template
            .root()
            .join(format!("ok-{}.bin", label.replace(' ', "-")));
        let env = Env::copy_vault_from(&template);
        env.pv("get", &["a", ok.to_str().unwrap()], None)
            .expect(0, &format!("{label}: export to a private folder"));
        println!("    {label}: export and card folder refused (exit 6) before any secret");
    }
    // A vault on such a place is read-only by 8.5; that is F74 (images).
    // A Windows network vault is refused by 8.5 as well (Milestone 3, Q2).
}

/// G1 (decided 2026-10-06) on real macOS volumes: APFS images attached with
/// ownership ignored (`PVAULT_TEST_NOOWNERS_DIR`) and enforced
/// (`PVAULT_TEST_OWNERS_DIR`), each a writable folder on the image. On the
/// first, exports and card folders are refused (exit 6) before any secret
/// or file, and a settings folder there is not private; the second is the
/// control and accepts an export. Required on macOS with
/// `PVAULT_TEST_REQUIRE_IMAGES`; Linux and Windows have no such mounts.
fn ownership_ignored_mounts_are_refused() {
    let dirs = (
        std::env::var_os("PVAULT_TEST_NOOWNERS_DIR").map(PathBuf::from),
        std::env::var_os("PVAULT_TEST_OWNERS_DIR").map(PathBuf::from),
    );
    let (Some(noowners), Some(owners)) = dirs else {
        if cfg!(target_os = "macos") && std::env::var_os("PVAULT_TEST_REQUIRE_IMAGES").is_some() {
            panic!("PVAULT_TEST_NOOWNERS_DIR and PVAULT_TEST_OWNERS_DIR are required");
        }
        skip_all("no ownership-ignored image mounted (macOS only)");
        return;
    };
    let template = Env::new();
    template.init(None).expect(0, "template init");
    template
        .add(&template.source("a", b"x"), "a", &[], None)
        .expect(0, "add");
    let off = tempfile::Builder::new()
        .prefix("pv-")
        .tempdir_in(&noowners)
        .unwrap();
    let on = tempfile::Builder::new()
        .prefix("pv-")
        .tempdir_in(&owners)
        .unwrap();
    // Export to the ownership-ignored volume: refused before the unlock.
    let env = Env::copy_vault_from(&template);
    let dest = off.path().join("out.bin");
    let out = env.run(
        &[arg("get"), arg(&env.vault()), arg("a"), arg(&dest)],
        b"",
        None,
    );
    out.expect(6, "export to an ownership-ignored volume");
    assert!(out.says("ownership ignored"), "{}", out.stderr);
    assert!(
        visible_entries(off.path()).is_empty(),
        "no destination file"
    );
    // Card folder there: refused before anything is created.
    let mut env = Env::new();
    env.cards_at = Some(off.path().to_path_buf());
    let out = env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(off.path()),
            arg("--custom"),
        ],
        b"",
        None,
    );
    out.expect(6, "card folder on an ownership-ignored volume");
    assert!(out.says("ownership ignored"), "{}", out.stderr);
    assert!(!env.vault().exists() && visible_entries(off.path()).is_empty());
    // A digital card folder there: refused the same way.
    let env = Env::new();
    let mut args = env.digital_args(&ACK);
    let a = args.iter().position(|x| x == "--card-a-dir").unwrap();
    args[a + 1] = arg(off.path());
    let out = env.run(&args, &[PW, PW, PW].concat(), None);
    out.expect(6, "digital card folder on an ownership-ignored volume");
    assert!(out.says("ownership ignored"), "{}", out.stderr);
    assert!(!env.vault().exists() && visible_entries(off.path()).is_empty());
    // A settings folder there is not private.
    let env = Env::copy_vault_from(&template);
    let ok = env.root().join("ok.bin");
    let mut cmd = env.command(&[arg("get"), arg(&env.vault()), arg("a"), arg(&ok)], None);
    cmd.env("PVAULT_CONFIG_DIR", off.path().join("settings"));
    let child = cmd.spawn().unwrap();
    let res = child.wait_with_output().unwrap();
    assert_eq!(
        res.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(String::from_utf8_lossy(&res.stderr).contains("is not private to you"));
    assert!(!ok.exists());
    // Control: the same kind of volume with ownership enforced works.
    let env = Env::copy_vault_from(&template);
    let good = on.path().join("out.bin");
    env.pv("get", &["a", good.to_str().unwrap()], None)
        .expect(0, "export to an ownership-enforced APFS volume");
    assert_eq!(std::fs::read(&good).unwrap(), b"x");
    // Digital cards: Card A on the enforced image, Card B on the local
    // volume. Two volumes: no same-volume acknowledgment is needed.
    let env = Env::new();
    let card_a = tempfile::Builder::new()
        .prefix("pv-")
        .tempdir_in(&owners)
        .unwrap();
    let mut args = env.digital_args(&["--accept-risk", "digital-cards"]);
    let a = args.iter().position(|x| x == "--card-a-dir").unwrap();
    args[a + 1] = arg(card_a.path());
    let out = env.run(&args, &[PW, PW, PW].concat(), None);
    out.expect(0, "digital cards on two volumes");
    assert!(!out.says("same volume"), "{}", out.stderr);
    assert_eq!(visible_entries(card_a.path()).len(), 1);
    println!(
        "    ownership ignored: export, card folders and settings refused; enforced: export and a digital card folder work"
    );
}

impl Env {
    /// Digital `init` arguments with Card A and Card B in `<root>/a` and
    /// `<root>/b` (created), plus `extra`.
    fn digital_args(&self, extra: &[&str]) -> Vec<OsString> {
        for d in ["a", "b"] {
            let _ = std::fs::create_dir(self.root().join(d));
        }
        let mut args = vec![
            arg("init"),
            arg(&self.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("digital"),
            arg("--card-a-dir"),
            arg(&self.root().join("a")),
            arg("--card-b-dir"),
            arg(&self.root().join("b")),
            arg("--custom"),
        ];
        args.extend(FAST.iter().map(arg));
        args.extend(extra.iter().map(arg));
        args
    }

    /// The files in `<root>/a` and `<root>/b`.
    fn digital_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = ["a", "b"]
            .iter()
            .flat_map(|d| {
                std::fs::read_dir(self.root().join(d))
                    .map(|r| r.map(|e| e.unwrap().path()).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect();
        v.sort();
        v
    }
}

const ACK: [&str; 4] = [
    "--accept-risk",
    "digital-cards",
    "--accept-risk",
    "same-volume",
];

/// SI-52 F95 and F100 through the real CLI: digital `init` reads exactly
/// three lines and asks for no printing acknowledgment; missing
/// acknowledgments, the same folder and mixed options are refused before
/// anything is read or created; everyday commands take no card files.
fn digital_cards_through_the_cli() {
    let env = Env::new();
    let out = env.run(&env.digital_args(&[]), &[PW, PW, PW].concat(), None);
    out.expect(4, "no acknowledgment without a terminal");
    assert!(out.says("--accept-risk digital-cards"), "{}", out.stderr);
    assert!(
        out.says("together open this vault without the passphrase"),
        "risk text always shown"
    );
    assert!(!env.vault().exists() && !env.root().join("settings").exists());
    assert!(env.digital_files().is_empty());
    // No environment variable gives an acknowledgment.
    let yes = OsStr::new("digital-cards");
    let out = env.run_env(
        &env.digital_args(&[]),
        &[PW, PW, PW].concat(),
        None,
        &[
            ("PVAULT_ACCEPT_RISK", yes),
            ("PVAULT_CARDS", OsStr::new("digital")),
        ],
    );
    out.expect(4, "environment variables are not acknowledgments");
    assert!(!env.vault().exists() && env.digital_files().is_empty());
    let out = env.run(
        &env.digital_args(&["--accept-risk", "digital-cards"]),
        &[PW, PW, PW].concat(),
        None,
    );
    out.expect(4, "same volume without its acknowledgment");
    assert!(out.says("--accept-risk same-volume"), "{}", out.stderr);
    assert!(!env.vault().exists() && env.digital_files().is_empty());
    // The same folder twice.
    let mut args = env.digital_args(&ACK);
    let b = args.iter().position(|a| a == "--card-b-dir").unwrap();
    args[b + 1] = arg(&env.root().join("a"));
    env.run(&args, &[PW, PW, PW].concat(), None)
        .expect(2, "same folder");
    // Mixed or missing options.
    let mut mixed = env.digital_args(&ACK);
    mixed.extend([arg("--cards-dir"), arg(&env.cards())]);
    env.run(&mixed, b"", None)
        .expect(2, "digital with --cards-dir");
    let paper_with_dirs = env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards"),
            arg("paper"),
            arg("--cards-dir"),
            arg(&env.cards()),
            arg("--card-a-dir"),
            arg(&env.root().join("a")),
        ],
        b"",
        None,
    );
    paper_with_dirs.expect(2, "paper with --card-a-dir");
    env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--mode"),
            arg("portable"),
            arg("--cards-dir"),
            arg(&env.cards()),
        ],
        b"",
        None,
    )
    .expect(2, "missing --cards");
    assert!(!env.vault().exists());
    // A resume takes no card options.
    env.run(
        &[
            arg("init"),
            arg(&env.vault()),
            arg("--accept-risk"),
            arg("digital-cards"),
        ],
        b"",
        None,
    )
    .expect(2, "card options on a resume");
    assert!(!env.vault().exists());
    // Success: exactly three lines.
    let out = env.run(&env.digital_args(&ACK), &[PW, PW, PW].concat(), None);
    out.expect(0, "digital init");
    assert!(!out.says("Press Enter"), "no printing acknowledgment");
    assert!(
        !out.says("Optional check"),
        "R5 is not offered without a terminal"
    );
    let files = env.digital_files();
    assert_eq!(files.len(), 2);
    for f in &files {
        pvault_core::card::parse_card_file(&std::fs::read(f).unwrap()).unwrap();
    }
    env.run(&[arg("clean-partials")], b"", None)
        .expect(0, "records released");
    // Everyday commands keep the passphrase: no card-file options.
    let card_unlock = env.run(
        &[
            arg("list"),
            arg(&env.vault()),
            arg("--card-a-file"),
            arg(&files[0]),
            arg("--card-b-file"),
            arg(&files[1]),
        ],
        b"",
        None,
    );
    card_unlock.expect(2, "no card unlock for list");
    env.list().expect(0, "list with the passphrase");
    assert_eq!(env.digital_files(), files, "files kept");
    // R4: a folder under a listed sync root is warned about.
    let env = Env::new();
    let synced = env.root().join("home").join("Dropbox").join("a");
    std::fs::create_dir_all(&synced).unwrap();
    let mut args = env.digital_args(&ACK);
    let a = args.iter().position(|x| x == "--card-a-dir").unwrap();
    args[a + 1] = arg(&synced);
    let home = env.root().join("home");
    let out = env.run_env(
        &args,
        &[PW, PW, PW].concat(),
        None,
        &[("HOME", home.as_os_str())],
    );
    out.expect(0, "digital init under a sync root");
    assert!(
        out.says("usually synced to a cloud account"),
        "{}",
        out.stderr
    );
    assert!(
        out.says("no warning does not mean not synced"),
        "{}",
        out.stderr
    );
}

/// SI-52 R5 through the real CLI on a pseudo-terminal (Unix), interactive
/// (no `--secrets-stdin`): after "Vault created", the optional check is
/// offered with every handle released. Enter skips it; CHECK after the
/// card folder was removed and recreated ("ejected and re-inserted") passes;
/// CHECK after a card file changed fails with exit 1, and the vault and both
/// files stay.
#[cfg(unix)]
fn digital_card_check_after_commit() {
    let pw = std::str::from_utf8(PW).unwrap().trim_end();
    type Before = Option<Box<dyn FnOnce()>>;
    let run = |env: &Env, check: &str, before: Before| {
        let args = env.digital_args(&ACK);
        let tty = pty::open();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(&args)
            .env(CHILD_ENV, "1")
            .env("PVAULT_CONFIG_DIR", env.root().join("settings"))
            .env_remove("PVAULT_FAILPOINT")
            .env_remove("PVAULT_TEST_NO_TERMINAL")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        pty::make_controlling(&mut cmd, &tty.slave);
        let child = cmd.spawn().unwrap();
        let screen = pty::Screen::start(&tty.master);
        let mut before = before;
        let mut seen = 0;
        for (prompt, reply) in [
            ("Enter the new passphrase: ", pw),
            ("Enter it again: ", pw),
            ("Type your passphrase from memory: ", pw),
            ("Type CHECK after re-inserting", check),
        ] {
            let deadline = Instant::now() + Duration::from_secs(180);
            while !screen.text().contains(prompt) {
                assert!(
                    Instant::now() < deadline,
                    "no prompt {prompt:?}: {}",
                    screen.text()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            seen += 1;
            if seen == 4
                && let Some(f) = before.take()
            {
                f();
            }
            (&tty.master)
                .write_all(format!("{reply}\n").as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        drop(tty);
        Out {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    };
    // Enter: skipped.
    let env = Env::new();
    let out = run(&env, "", None);
    out.expect(0, "skipped");
    assert!(
        out.says("Vault created") && out.says("The vault has already been created"),
        "{}",
        out.stderr
    );
    assert!(out.says("Card check skipped"), "{}", out.stderr);
    // Ejected and re-inserted, then CHECK: passes.
    let env = Env::new();
    let a = env.root().join("a");
    let out = run(
        &env,
        "CHECK",
        Some(Box::new(move || {
            let saved: Vec<_> = std::fs::read_dir(&a)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.clone(), std::fs::read(&p).unwrap())
                })
                .collect();
            std::fs::remove_dir_all(&a).unwrap();
            std::fs::create_dir(&a).unwrap();
            for (p, b) in saved {
                std::fs::write(p, b).unwrap();
            }
        })),
    );
    out.expect(0, "check passed");
    assert!(out.says("Card check passed"), "{}", out.stderr);
    // A changed card file: exit 1, nothing rolled back or deleted.
    let env = Env::new();
    let b = env.root().join("b");
    let out = run(
        &env,
        "CHECK",
        Some(Box::new(move || {
            let p = std::fs::read_dir(&b)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let mut bytes = std::fs::read(&p).unwrap();
            bytes.push(b'\n');
            std::fs::write(p, bytes).unwrap();
        })),
    );
    out.expect(1, "check failed");
    assert!(
        out.says("The vault was created, but the card check failed"),
        "{}",
        out.stderr
    );
    assert_eq!(env.digital_files().len(), 2, "no card file deleted");
    env.list().expect(0, "the vault stays");
}

/// SI-52 F98: a crash at every digital step, then `pvault init <vault>`:
/// the card files are never deleted after the restart; current cards are
/// released, others kept and named; `clean-partials` never deletes them.
fn digital_crash_at_each_step() {
    let committed = ["init.committed", "init.cards-released"];
    for fp in [
        "init.cards-created",
        "init.cards-registered",
        "init.cards-written",
        "init.rehearsed",
        "init.committing",
        "init.committed",
        "init.cards-released",
    ] {
        let env = Env::new();
        let out = env.run(&env.digital_args(&ACK), &[PW, PW, PW].concat(), Some(fp));
        assert!(out.crashed(), "{fp}: {:?} {}", out.code, out.stderr);
        let before = env.digital_files();
        assert_eq!(before.len(), 2, "{fp}");
        let resume = env.run(&[arg("init"), arg(&env.vault())], PW, None);
        resume.expect(0, fp);
        if committed.contains(&fp) {
            assert!(
                resume.says("Your recovery card files are"),
                "{fp}: {}",
                resume.stderr
            );
        } else if fp != "init.cards-created" {
            assert!(resume.says("probably invalid"), "{fp}: {}", resume.stderr);
        }
        assert_eq!(
            env.digital_files(),
            before,
            "{fp}: nothing deleted by the resume"
        );
        let clean = env.run(&[arg("clean-partials")], b"", None);
        if committed.contains(&fp) || fp == "init.cards-created" {
            clean.expect(0, fp);
        } else {
            clean.expect(4, fp);
            assert!(
                clean.says("pvault never deletes these"),
                "{fp}: {}",
                clean.stderr
            );
        }
        assert_eq!(
            env.digital_files(),
            before,
            "{fp}: nothing deleted by clean-partials"
        );
    }
}

/// F26 (`init`), F78: a crash at each step, then `pvault init` resumes.
fn init_crash_at_each_step() {
    let committed = ["init.committed", "init.cards-deleted"];
    // W3 to W7: entries exist until W8 (after W7 they name deleted files,
    // which the cleaner drops after confirmation).
    let tracked = [
        "init.cards-registered",
        "init.cards-written",
        "init.committing",
        "init.committed",
        "init.cards-deleted",
    ];
    for fp in [
        "init.prepared",
        "init.keytable-created",
        "init.keytable-written",
        "init.cards-created",
        "init.cards-registered",
        "init.cards-written",
        "init.committing",
        "init.committed",
        "init.cards-deleted",
    ] {
        let env = Env::new();
        let out = env.init(Some(fp));
        assert!(out.crashed(), "{fp}: {:?} {}", out.code, out.stderr);
        let resume = env.run(&[arg("init"), arg(&env.vault())], PW, None);
        resume.expect(0, fp);
        if committed.contains(&fp) {
            assert!(
                resume.says("The interrupted setup was finished"),
                "{fp}: {}",
                resume.stderr
            );
            env.list().expect(0, fp);
            assert!(!env.vault().join("vault.journal").exists());
        } else {
            assert!(
                resume.says("The interrupted setup was removed."),
                "{fp}: {}",
                resume.stderr
            );
            assert_eq!(env.vault_names(), LOCKS, "{fp}");
        }
        // Card files: tracked ones are listed (declined without a terminal);
        // untracked empty ones (W2 window) are not.
        let clean = env.run(&[arg("clean-partials")], b"", None);
        if tracked.contains(&fp) {
            clean.expect(4, fp);
            assert!(
                clean.says("Card A file") && clean.says("Card B file"),
                "{fp}"
            );
            let left = env.names(&env.cards()).len();
            assert_eq!(left, if fp == "init.cards-deleted" { 0 } else { 2 }, "{fp}");
        } else {
            clean.expect(0, fp);
        }
        if fp == "init.cards-created" {
            let files = env.names(&env.cards());
            assert_eq!(files.len(), 2, "{fp}");
            for f in files {
                assert_eq!(
                    std::fs::metadata(env.cards().join(f)).unwrap().len(),
                    0,
                    "no share bytes"
                );
            }
        }
    }
    // After a rollback, init runs again in the same folder.
    let env = Env::new();
    assert!(env.init(Some("init.keytable-written")).crashed());
    env.run(&[arg("init"), arg(&env.vault())], PW, None)
        .expect(0, "resume");
    env.init(None).expect(0, "init again");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    /// Old state, nothing pending.
    Old,
    /// New state, nothing pending.
    New,
    /// Old state; an unowned file blocks the next change (exit 4).
    OldBlocked,
    /// The restart itself is blocked by a residue journal temp (exit 4).
    RestartBlocked,
}

/// F26 and F89 (SI-40): the 9.6 table for one operation. `template` holds a vault with `a`.
fn update_crashes(
    op: &str,
    run: impl Fn(&Env, Option<&str>) -> Out,
    object: bool,
    old: &str,
    new: &str,
) {
    let template = Env::new();
    template.init(None).expect(0, "template init");
    template
        .add(&template.source("a", b"old a"), "a", &[], None)
        .expect(0, "template add");
    let mut cases = vec![
        ("update.prepared", After::Old),
        ("update.created", After::OldBlocked),
        ("journal.partial#1", After::OldBlocked),
        ("journal.tmp-complete#1", After::OldBlocked),
        ("journal.renamed#1", After::Old),
        ("update.staged", After::Old),
        ("update.keytable-written", After::Old),
        ("update.keytable-final", After::Old),
        ("journal.partial#2", After::OldBlocked),
        ("journal.tmp-complete#2", After::Old),
        ("update.committing", After::Old),
        ("header.tmp-written", After::Old),
        ("header.replaced", After::New),
        ("update.committed", After::New),
        ("update.objects-removed", After::New),
        ("journal.partial#3", After::RestartBlocked),
        ("journal.tmp-complete#3", After::New),
        ("update.cleaned", After::New),
        ("update.old-table-removed", After::New),
        ("journal.unlinked", After::New),
    ];
    if object {
        cases.push(("update.object-written", After::Old));
        cases.push(("update.object-final", After::Old));
    }
    for (fp, after) in cases {
        let env = Env::copy_vault_from(&template);
        let out = run(&env, Some(fp));
        assert!(out.crashed(), "{op} {fp}: {:?} {}", out.code, out.stderr);
        let restart = env.list();
        if after == After::RestartBlocked {
            restart.expect(4, &format!("{op} {fp}"));
            assert!(
                restart.says("vault.journal.tmp"),
                "{op} {fp}: {}",
                restart.stderr
            );
            assert!(env.vault().join("vault.journal").exists(), "journal kept");
            continue;
        }
        restart.expect(0, &format!("{op} {fp}"));
        let want = if after == After::New { new } else { old };
        assert_eq!(
            restart
                .stdout
                .lines()
                .map(|l| l.rsplit('\t').next().unwrap())
                .collect::<Vec<_>>()
                .join(","),
            want,
            "{op} {fp}: {}",
            restart.stderr
        );
        assert!(
            !env.vault().join("vault.journal").exists(),
            "{op} {fp}: journal resolved"
        );
        let names = env.vault_names();
        let tables = names.iter().filter(|n| n.starts_with("keytable.")).count();
        let next = env.add(&env.source("n", b"n"), "next", &[], None);
        match after {
            After::OldBlocked => {
                next.expect(4, &format!("{op} {fp} next change"));
                assert!(next.says("Files pvault cannot prove it created block this change"));
            }
            _ => {
                assert_eq!(tables, 1, "{op} {fp}: one key table: {names:?}");
                assert!(
                    !names.iter().any(|n| n.ends_with(".tmp")),
                    "{op} {fp}: {names:?}"
                );
                next.expect(0, &format!("{op} {fp} next change"));
            }
        }
    }
}

fn add_crash_at_each_step() {
    update_crashes(
        "add",
        |env, fp| env.add(&env.source("b", b"b"), "b", &[], fp),
        true,
        "a",
        "a,b",
    );
}

fn replace_crash_at_each_step() {
    update_crashes(
        "add --replace",
        |env, fp| env.add(&env.source("a2", b"new a"), "a", &["--replace"], fp),
        true,
        "a",
        "a",
    );
}

fn rm_crash_at_each_step() {
    update_crashes("rm", |env, fp| env.pv("rm", &["a"], fp), false, "a", "");
}

/// F33/F72 (`get` halves), F50, F51, F67, F70: a crash at each export step.
fn export_crash_at_each_step() {
    let template = Env::new();
    template.init(None).expect(0, "template init");
    let data = vec![9u8; 80_000];
    template
        .add(&template.source("a", &data), "a", &[], None)
        .expect(0, "template add");
    for fp in [
        "export.created",
        "export.registered",
        "export.written",
        "export.published",
    ] {
        let env = Env::copy_vault_from(&template);
        let dest = env.root().join("out.bin");
        let partial = env.root().join("out.bin.pvpartial");
        let out = env.pv("get", &["a", dest.to_str().unwrap()], Some(fp));
        assert!(out.crashed(), "{fp}: {:?} {}", out.code, out.stderr);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = if fp == "export.published" {
                &dest
            } else {
                &partial
            };
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{fp}: owner-only (F51)");
        }
        let clean = env.run(&[arg("clean-partials")], b"", None);
        match fp {
            "export.created" => {
                // E2 window: an empty, unrecorded partial (no plaintext).
                assert_eq!(std::fs::metadata(&partial).unwrap().len(), 0);
                clean.expect(0, fp);
                let again = env.pv("get", &["a", dest.to_str().unwrap()], None);
                again.expect(1, fp);
                assert!(
                    again.says(".pvpartial already exists; nothing was written."),
                    "{}",
                    again.stderr
                );
            }
            "export.published" => {
                assert_eq!(
                    std::fs::read(&dest).unwrap(),
                    data,
                    "published file complete"
                );
                assert!(!partial.exists());
                clean.expect(4, fp);
                assert!(clean.says("export:"));
                assert_eq!(std::fs::read(&dest).unwrap(), data, "never deleted");
            }
            _ => {
                assert!(!dest.exists(), "{fp}: nothing published");
                assert!(partial.exists());
                clean.expect(4, fp);
                // A new export to another name offers the stale one
                // (declined without a terminal) and continues.
                let other = env.root().join("other.bin");
                let again = env.pv("get", &["a", other.to_str().unwrap()], None);
                again.expect(0, fp);
                assert!(again.says("An interrupted export of this vault left these files"));
                assert_eq!(std::fs::read(&other).unwrap(), data);
            }
        }
    }
    // Name too long for the suffix (K7): refused before anything exists.
    let env = Env::copy_vault_from(&template);
    let long = env.root().join("n".repeat(250));
    let out = env.pv("get", &["a", long.to_str().unwrap()], None);
    out.expect(1, "long name");
    assert!(out.says(
        "The destination name is too long to add the .pvpartial suffix on this file system."
    ));
    assert!(!env.names(env.root()).iter().any(|n| n.starts_with("nnnn")));
}

/// CLI 1.2: native paths in messages are escaped.
fn native_paths_are_rendered_safely() {
    let env = Env::new();
    env.init(None).expect(0, "init");
    env.add(&env.source("a", b"x"), "a", &[], None)
        .expect(0, "add");
    #[cfg(unix)]
    let dest = env.root().join("slash\\x\u{9B}y\u{202E}z\u{2067}w\u{FEFF}");
    #[cfg(windows)]
    let dest = env.root().join("x\u{9B}y\u{202E}z\u{2067}w\u{FEFF}");
    let out = env.pv("get", &["a", dest.to_str().unwrap()], None);
    out.expect(0, "get");
    #[cfg(unix)]
    assert!(
        out.says("slash\\\\x\\u{009B}y\\u{202E}z\\u{2067}w\\u{FEFF}"),
        "{}",
        out.stderr
    );
    #[cfg(windows)]
    assert!(
        out.says("x\\u{009B}y\\u{202E}z\\u{2067}w\\u{FEFF}"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains('\u{9B}') && !out.stderr.contains('\u{202E}'));
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let dir = env.root().join(OsStr::from_bytes(b"bad\xffname"));
        std::fs::create_dir(&dir).unwrap();
        let mut args = vec![arg("get"), arg(&env.vault()), arg("a")];
        args.push(dir.join("out").into_os_string());
        let out = env.run(&args, PW, None);
        out.expect(0, "get into a non-UTF-8 folder");
        assert!(out.says("bad\\xFFname"), "{}", out.stderr);
        // A destination file name that is not UTF-8 (native names, 7.2):
        // exported; after a crash, recorded, listed and cleaned up by its
        // native bytes through the confirmed cleaner.
        let odd = env.root().join(OsStr::from_bytes(b"out\xff.bin"));
        let mut args = vec![arg("get"), arg(&env.vault()), arg("a")];
        args.push(odd.clone().into_os_string());
        let out = env.run(&args, PW, None);
        out.expect(0, "get to a non-UTF-8 file name");
        assert!(out.says("out\\xFF.bin"), "{}", out.stderr);
        assert_eq!(std::fs::read(&odd).unwrap(), b"x");
        let crash = env.root().join(OsStr::from_bytes(b"crash\xfe.bin"));
        let partial = env
            .root()
            .join(OsStr::from_bytes(b"crash\xfe.bin.pvpartial"));
        let mut args = vec![arg("get"), arg(&env.vault()), arg("a")];
        args.push(crash.into_os_string());
        let mut child = env.command(&args, Some("export.written")).spawn().unwrap();
        child.stdin.take().unwrap().write_all(PW).unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(partial.exists());
        let listed = env.run(&[arg("clean-partials")], b"", None);
        listed.expect(4, "stale non-UTF-8 export listed");
        assert!(listed.says("crash\\xFE.bin.pvpartial"), "{}", listed.stderr);
        let (out, _) = env.run_tty(
            &[arg("clean-partials")],
            b"",
            &[("DELETE 1 STALE FILES", "DELETE 1 STALE FILES")],
        );
        out.expect(0, "confirmed cleanup of a non-UTF-8 partial");
        if out.says("Deleted") {
            assert!(!partial.exists());
        } else {
            // No birth time on this file system: kept and reported.
            assert!(
                out.says("cannot prove") && partial.exists(),
                "{}",
                out.stderr
            );
        }
    }
    // A destination name with an unpaired surrogate (native UTF-16, 7.2):
    // exported, rendered, recorded after a crash and listed by the cleaner.
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let wide = |stem: &str, ext: &str| {
            let units: Vec<u16> = stem
                .encode_utf16()
                .chain([0xD800])
                .chain(ext.encode_utf16())
                .collect();
            std::ffi::OsString::from_wide(&units)
        };
        let odd = env.root().join(wide("out", ".bin"));
        let mut args = vec![arg("get"), arg(&env.vault()), arg("a")];
        args.push(odd.clone().into_os_string());
        let out = env.run(&args, PW, None);
        out.expect(0, "get to an unpaired-surrogate name");
        assert!(out.says("out\\u{D800}.bin"), "{}", out.stderr);
        assert_eq!(std::fs::read(&odd).unwrap(), b"x");
        let crash = env.root().join(wide("crash", ".bin"));
        let mut partial = crash.clone().into_os_string();
        partial.push(".pvpartial");
        let mut args = vec![arg("get"), arg(&env.vault()), arg("a")];
        args.push(crash.into_os_string());
        let mut child = env.command(&args, Some("export.written")).spawn().unwrap();
        child.stdin.take().unwrap().write_all(PW).unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(Path::new(&partial).exists());
        let listed = env.run(&[arg("clean-partials")], b"", None);
        listed.expect(4, "stale unpaired-surrogate export listed");
        assert!(
            listed.says("crash\\u{D800}.bin.pvpartial"),
            "{}",
            listed.stderr
        );
    }
}
