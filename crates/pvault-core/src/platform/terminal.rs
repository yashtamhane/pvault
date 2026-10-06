//! Terminal secret input with echo control (spec 7.6a; SI-51 section 4).
//!
//! - **Unix:** reads from `/dev/tty` with `ECHO` cleared (`ICANON` and `ISIG`
//!   kept, `ECHONL` set). The saved settings are restored on return, on
//!   errors and while unwinding. Signal handlers for SIGINT, SIGTERM, SIGHUP
//!   and SIGQUIT restore them too, using only async-signal-safe calls
//!   (`tcsetattr`, `sigemptyset`, `sigaction`, `raise`), and then re-raise
//!   the signal with its default action. SIGTSTP is ignored during the read.
//! - **Windows:** reads from `CONIN$` with `ENABLE_ECHO_INPUT` cleared. A
//!   console control handler, which Windows runs on its own thread, restores
//!   the mode on Ctrl-C, Ctrl-Break and close events.
//!
//! **Not recoverable:** SIGKILL, `TerminateProcess`, or a crash before the
//! guard runs. These can leave echo off; the remedy is `stty sane` or
//! `reset`, or closing the console window.
//!
//! **Pending input** (approved for Milestone 4, A1): before each prompt is
//! displayed and read, pending terminal input is discarded (Unix: the
//! `tcsetattr` call uses `TCSAFLUSH`; Windows: `FlushConsoleInputBuffer`).
//! pvault's own buffers belong to one prompt: the Unix reader takes one byte
//! at a time with no buffer, and the Windows console buffer is wiped when
//! the prompt ends. This reduces the chance that stray queued lines answer a
//! later prompt; it does not prove which prompt was visible when a line was
//! typed, and it cannot stop input that arrives after the flush.

use crate::input::{ByteSource, InputError, SecretLine, read_line};

/// Prompts on the terminal and reads one secret line with echo off.
pub fn read_secret(prompt: &str) -> Result<SecretLine, InputError> {
    read_hidden(prompt, |source| read_line(source))
}

/// Prompts on the terminal with echo off, then lets `read` take as many
/// lines as it needs from the same hidden session (for card text).
pub fn read_hidden<T>(
    prompt: &str,
    read: impl FnOnce(&mut dyn ByteSource) -> Result<T, InputError>,
) -> Result<T, InputError> {
    imp::read_hidden(prompt, read)
}

/// Prompts on the terminal and reads one visible line (confirmations,
/// acknowledgments, file paths). Never reads standard input.
pub fn read_visible(prompt: &str) -> Result<String, InputError> {
    let line = imp::read_visible(prompt)?;
    String::from_utf8(line.as_bytes().to_vec()).map_err(|_| InputError::InvalidUtf16)
}

/// Writes text for the owner's eyes only to the terminal device.
pub fn show(text: &str) -> Result<(), InputError> {
    imp::show(text)
}

/// Whether a terminal device can be opened.
pub fn has_terminal() -> bool {
    imp::has_terminal()
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod imp {
    use std::cell::UnsafeCell;
    use std::fs::File;
    use std::io::{self, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::SeqCst};

    use crate::input::{ByteSource, InputError, SecretLine, UnbufferedSource, read_line};

    /// Terminal settings saved before echo is turned off.
    struct Saved(UnsafeCell<MaybeUninit<libc::termios>>);

    // SAFETY: `SAVED` is written only in `EchoOff::engage`, after `ACTIVE`
    // grants exclusive use and before `FD` publishes it to the signal
    // handlers. After that it is only read, until `FD` is cleared again.
    unsafe impl Sync for Saved {}

    static SAVED: Saved = Saved(UnsafeCell::new(MaybeUninit::uninit()));
    static FD: AtomicI32 = AtomicI32::new(-1);
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    const RESTORE_ON: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

    /// Echo-off state. Dropping it restores the terminal and the previous
    /// signal dispositions.
    pub(crate) struct EchoOff {
        fd: RawFd,
        previous: [libc::sigaction; 5],
        installed: usize,
    }

    impl EchoOff {
        pub(crate) fn engage(fd: RawFd) -> io::Result<Self> {
            if ACTIVE.swap(true, SeqCst) {
                return Err(io::Error::other("secret input is already active"));
            }
            let mut current = MaybeUninit::<libc::termios>::uninit();
            // SAFETY: `fd` is an open descriptor, and on success `tcgetattr`
            // fully initializes `current`.
            if unsafe { libc::tcgetattr(fd, current.as_mut_ptr()) } != 0 {
                ACTIVE.store(false, SeqCst);
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `tcgetattr` succeeded, so `current` is initialized.
            let current = unsafe { current.assume_init() };
            // SAFETY: `ACTIVE` grants exclusive use, and no handler can read
            // `SAVED` yet because `FD` is still -1.
            unsafe { (*SAVED.0.get()).write(current) };
            FD.store(fd, SeqCst);

            let mut guard = Self {
                fd,
                // SAFETY: an all-zero `sigaction` is a valid value.
                previous: unsafe { core::mem::zeroed() },
                installed: 0,
            };
            for (slot, signal) in RESTORE_ON.iter().enumerate() {
                guard.install(slot, *signal, restore_and_reraise as *const () as usize)?;
            }
            guard.install(4, libc::SIGTSTP, libc::SIG_IGN)?;

            let mut quiet = current;
            quiet.c_lflag &= !libc::ECHO;
            quiet.c_lflag |= libc::ECHONL;
            // SAFETY: `quiet` is a valid `termios` derived from the current
            // settings of the open descriptor `fd`.
            // TCSAFLUSH also discards input received but not yet read, so
            // queued lines cannot answer this prompt (A1).
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
                return Err(io::Error::last_os_error()); // `guard` restores on drop
            }
            Ok(guard)
        }

        fn install(&mut self, slot: usize, signal: libc::c_int, handler: usize) -> io::Result<()> {
            // SAFETY: an all-zero `sigaction` is valid; the fields used are
            // set below.
            let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
            action.sa_sigaction = handler;
            // SAFETY: `action.sa_mask` is a valid, writable `sigset_t`.
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            // SAFETY: both pointers refer to valid `sigaction` values that
            // outlive the call.
            if unsafe { libc::sigaction(signal, &action, &mut self.previous[slot]) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.installed = slot + 1;
            Ok(())
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            // SAFETY: `SAVED` holds the settings written in `engage` for this
            // same descriptor.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, (*SAVED.0.get()).as_ptr()) };
            let signals = [
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGHUP,
                libc::SIGQUIT,
                libc::SIGTSTP,
            ];
            for (slot, signal) in signals.iter().enumerate().take(self.installed) {
                // SAFETY: `previous[slot]` was filled by a successful
                // `sigaction` call in `install`.
                unsafe { libc::sigaction(*signal, &self.previous[slot], core::ptr::null_mut()) };
            }
            FD.store(-1, SeqCst);
            ACTIVE.store(false, SeqCst);
        }
    }

    /// Signal handler: restores the terminal, then re-raises the signal with
    /// its default action. Uses only async-signal-safe operations.
    extern "C" fn restore_and_reraise(signal: libc::c_int) {
        let fd = FD.load(SeqCst);
        if fd >= 0 {
            // SAFETY: `FD` is set only while `SAVED` holds valid settings.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, (*SAVED.0.get()).as_ptr()) };
        }
        // SAFETY: a zeroed `sigaction` with `SIG_DFL` and an emptied mask is
        // valid. `sigemptyset`, `sigaction` and `raise` are async-signal-safe.
        unsafe {
            let mut default: libc::sigaction = core::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut default.sa_mask);
            libc::sigaction(signal, &default, core::ptr::null_mut());
            libc::raise(signal);
        }
    }

    fn open_tty() -> Result<File, InputError> {
        // SAFETY: the path is a valid NUL-terminated string. The flags do
        // not make the terminal a controlling terminal and close it on exec.
        let fd = unsafe {
            libc::open(
                c"/dev/tty".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(InputError::NoTerminal);
        }
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn has_terminal() -> bool {
        open_tty().is_ok()
    }

    pub(super) fn show(text: &str) -> Result<(), InputError> {
        let mut tty = open_tty()?;
        tty.write_all(text.as_bytes()).map_err(InputError::Io)?;
        tty.flush().map_err(InputError::Io)
    }

    pub(super) fn read_hidden<T>(
        prompt: &str,
        read: impl FnOnce(&mut dyn ByteSource) -> Result<T, InputError>,
    ) -> Result<T, InputError> {
        let tty = open_tty()?;
        read_hidden_from(&tty, prompt, read)
    }

    /// Reads one secret from an already open terminal.
    #[cfg(test)]
    pub(crate) fn read_secret_from(tty: &File, prompt: &str) -> Result<SecretLine, InputError> {
        read_hidden_from(tty, prompt, |source| read_line(source))
    }

    /// Discards pending input and turns echo off (EchoOff, TCSAFLUSH), then
    /// shows the prompt, then reads.
    pub(crate) fn read_hidden_from<T>(
        tty: &File,
        prompt: &str,
        read: impl FnOnce(&mut dyn ByteSource) -> Result<T, InputError>,
    ) -> Result<T, InputError> {
        let guard = EchoOff::engage(tty.as_raw_fd()).map_err(InputError::Io)?;
        let mut out = tty;
        out.write_all(prompt.as_bytes()).map_err(InputError::Io)?;
        out.flush().map_err(InputError::Io)?;
        let result = read(&mut UnbufferedSource(tty));
        drop(guard);
        result
    }

    pub(super) fn read_visible(prompt: &str) -> Result<SecretLine, InputError> {
        let tty = open_tty()?;
        read_visible_from(&tty, prompt)
    }

    /// Discards pending input (TCSAFLUSH with unchanged settings), then
    /// shows the prompt and reads one echoed line.
    pub(crate) fn read_visible_from(tty: &File, prompt: &str) -> Result<SecretLine, InputError> {
        let fd = tty.as_raw_fd();
        let mut current = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is open, and on success `tcgetattr` initializes
        // `current`.
        if unsafe { libc::tcgetattr(fd, current.as_mut_ptr()) } != 0 {
            return Err(InputError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `tcgetattr` succeeded; the settings are written back
        // unchanged, only discarding pending input.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, current.as_ptr()) } != 0 {
            return Err(InputError::Io(io::Error::last_os_error()));
        }
        let mut out = tty;
        out.write_all(prompt.as_bytes()).map_err(InputError::Io)?;
        out.flush().map_err(InputError::Io)?;
        read_line(&mut UnbufferedSource(tty))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::fs::File;
    use std::io::{self, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::SeqCst};

    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, FlushConsoleInputBuffer, GetConsoleMode, ReadConsoleW,
        SetConsoleCtrlHandler, SetConsoleMode,
    };
    use windows_sys::core::BOOL;
    use zeroize::Zeroizing;

    use crate::input::{ByteSource, InputError, MAX_LINE, SecretLine, Utf16Decoder, read_line};

    static CONIN: AtomicUsize = AtomicUsize::new(0);
    static SAVED_MODE: AtomicU32 = AtomicU32::new(0);
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Console control handler. Windows runs it on its own thread, so calling
    /// `SetConsoleMode` here is safe. Returning FALSE lets default handling
    /// (process exit) continue.
    unsafe extern "system" fn on_console_event(_event: u32) -> BOOL {
        let handle = CONIN.load(SeqCst);
        if handle != 0 {
            // SAFETY: `CONIN` holds an open console input handle while
            // non-zero.
            unsafe { SetConsoleMode(handle as HANDLE, SAVED_MODE.load(SeqCst)) };
        }
        0
    }

    fn open(name: &str) -> io::Result<OwnedHandle> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the
        // remaining arguments are plain values or null.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` was just opened and is owned by nothing else.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    struct EchoOff {
        handle: HANDLE,
        mode: u32,
    }

    impl EchoOff {
        fn engage(handle: HANDLE) -> io::Result<Self> {
            if ACTIVE.swap(true, SeqCst) {
                return Err(io::Error::other("secret input is already active"));
            }
            let mut mode = 0u32;
            // SAFETY: `handle` is an open console input handle, and `mode`
            // is writable.
            if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
                ACTIVE.store(false, SeqCst);
                return Err(io::Error::last_os_error());
            }
            SAVED_MODE.store(mode, SeqCst);
            CONIN.store(handle as usize, SeqCst);
            let guard = Self { handle, mode };
            // SAFETY: `on_console_event` matches the required signature.
            if unsafe { SetConsoleCtrlHandler(Some(on_console_event), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `handle` is an open console input handle.
            if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // Discards pending input, so queued lines cannot answer this
            // prompt (A1).
            // SAFETY: `handle` is an open console input handle.
            if unsafe { FlushConsoleInputBuffer(handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(guard)
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            // SAFETY: restores the saved mode on the same open handle, then
            // removes the handler that was added in `engage`.
            unsafe {
                SetConsoleMode(self.handle, self.mode);
                SetConsoleCtrlHandler(Some(on_console_event), 0);
            }
            CONIN.store(0, SeqCst);
            ACTIVE.store(false, SeqCst);
        }
    }

    struct ConsoleSource {
        handle: HANDLE,
        units: Zeroizing<[u16; MAX_LINE + 1]>,
        len: usize,
        pos: usize,
        decoder: Utf16Decoder,
    }

    impl ByteSource for ConsoleSource {
        fn next_byte(&mut self) -> io::Result<Option<u8>> {
            loop {
                if let Some(b) = self.decoder.next_byte() {
                    return Ok(Some(b));
                }
                if self.pos < self.len {
                    let unit = self.units[self.pos];
                    self.units[self.pos] = 0;
                    self.pos += 1;
                    self.decoder
                        .push(unit)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                    continue;
                }
                let mut read = 0u32;
                // SAFETY: the buffer is valid for `units.len()` UTF-16 units
                // and `read` is writable.
                let ok = unsafe {
                    ReadConsoleW(
                        self.handle,
                        self.units.as_mut_ptr().cast(),
                        self.units.len() as u32,
                        &mut read,
                        core::ptr::null(),
                    )
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                if read == 0 {
                    return Ok(None);
                }
                self.len = read as usize;
                self.pos = 0;
            }
        }
    }

    fn source(handle: HANDLE) -> ConsoleSource {
        ConsoleSource {
            handle,
            units: Zeroizing::new([0u16; MAX_LINE + 1]),
            len: 0,
            pos: 0,
            decoder: Utf16Decoder::default(),
        }
    }

    pub(super) fn has_terminal() -> bool {
        open("CONIN$").is_ok() && open("CONOUT$").is_ok()
    }

    pub(super) fn show(text: &str) -> Result<(), InputError> {
        let conout = open("CONOUT$").map_err(|_| InputError::NoTerminal)?;
        File::from(conout)
            .write_all(text.as_bytes())
            .map_err(InputError::Io)
    }

    /// Echo off and pending input discarded (EchoOff), then the prompt, then
    /// the read. The console buffer belongs to this prompt and is wiped when
    /// it is dropped.
    pub(super) fn read_hidden<T>(
        prompt: &str,
        read: impl FnOnce(&mut dyn ByteSource) -> Result<T, InputError>,
    ) -> Result<T, InputError> {
        let conout = open("CONOUT$").map_err(|_| InputError::NoTerminal)?;
        let conin = open("CONIN$").map_err(|_| InputError::NoTerminal)?;
        let mut out = File::from(conout);
        let handle = conin.as_raw_handle() as HANDLE;
        let guard = EchoOff::engage(handle).map_err(InputError::Io)?;
        out.write_all(prompt.as_bytes()).map_err(InputError::Io)?;
        let mut source = source(handle);
        let result = read(&mut source);
        drop(guard);
        drop(source);
        let _ = out.write_all(b"\r\n");
        result
    }

    pub(super) fn read_visible(prompt: &str) -> Result<SecretLine, InputError> {
        let conout = open("CONOUT$").map_err(|_| InputError::NoTerminal)?;
        let conin = open("CONIN$").map_err(|_| InputError::NoTerminal)?;
        let handle = conin.as_raw_handle() as HANDLE;
        // SAFETY: `handle` is an open console input handle.
        if unsafe { FlushConsoleInputBuffer(handle) } == 0 {
            return Err(InputError::Io(io::Error::last_os_error()));
        }
        File::from(conout)
            .write_all(prompt.as_bytes())
            .map_err(InputError::Io)?;
        let mut source = source(handle);
        read_line(&mut source)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use crate::input::{ByteSource, InputError, SecretLine};

    pub(super) fn read_hidden<T>(
        _prompt: &str,
        _read: impl FnOnce(&mut dyn ByteSource) -> Result<T, InputError>,
    ) -> Result<T, InputError> {
        Err(InputError::NoTerminal)
    }

    pub(super) fn read_visible(_prompt: &str) -> Result<SecretLine, InputError> {
        Err(InputError::NoTerminal)
    }

    pub(super) fn show(_text: &str) -> Result<(), InputError> {
        Err(InputError::NoTerminal)
    }

    pub(super) fn has_terminal() -> bool {
        false
    }
}

#[cfg(all(test, unix))]
#[allow(unsafe_code)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::Command;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::imp::{read_hidden_from, read_secret_from};
    use crate::card::{CardTextError, CardTextProgress, CardTextReader, PAYLOAD_LEN};
    use crate::input::{InputError, read_line};
    use crate::secrets::SecretBytes;

    /// The echo-off state is process-wide, so tests that use it run one at
    /// a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Pty {
        master: File,
        slave: File,
    }

    fn pty() -> Pty {
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
        // SAFETY: `openpty` returned two new descriptors, owned by nothing else.
        unsafe {
            Pty {
                master: File::from_raw_fd(master),
                slave: File::from_raw_fd(slave),
            }
        }
    }

    fn echo_on(file: &File) -> bool {
        let mut t = core::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `file` is an open terminal descriptor, and `t` is writable.
        let rc = unsafe { libc::tcgetattr(file.as_raw_fd(), t.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SAFETY: `tcgetattr` succeeded.
        unsafe { t.assume_init() }.c_lflag & libc::ECHO != 0
    }

    fn wait_for_echo(file: &File, on: bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while echo_on(file) != on {
            assert!(Instant::now() < deadline, "echo never became {on}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn read_card_from(
        tty: &File,
    ) -> Result<Result<SecretBytes<PAYLOAD_LEN>, CardTextError>, InputError> {
        read_hidden_from(tty, "Card: ", |source| {
            let mut reader = CardTextReader::new();
            loop {
                let line = match read_line(source) {
                    Ok(line) => line,
                    Err(InputError::Cancelled) => return Ok(Err(reader.ended())),
                    Err(error) => return Err(error),
                };
                match reader.push_line(&line) {
                    Ok(CardTextProgress::Complete) => return Ok(reader.payload()),
                    Ok(CardTextProgress::NeedMore) => {}
                    Err(error) => return Ok(Err(error)),
                }
            }
        })
    }

    fn card_input(input: Vec<u8>) -> Result<SecretBytes<PAYLOAD_LEN>, CardTextError> {
        let Pty { master, slave } = pty();
        let watcher = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_card_from(&slave));
        wait_for_echo(&watcher, false);
        (&master).write_all(&input).unwrap();
        reader.join().unwrap().unwrap()
    }

    fn drain_master(master: &File) -> Vec<u8> {
        // SAFETY: plain flag changes on an open descriptor.
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let mut reader = master;
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn echo_is_off_during_input_and_restored_after() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let Pty { master, slave } = pty();
        assert!(echo_on(&slave));
        let watcher = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&slave, "Passphrase: "));
        wait_for_echo(&watcher, false);
        (&master).write_all(b"hunter2 with spaces  \n").unwrap();
        let line = reader.join().unwrap().unwrap();
        assert_eq!(line.as_bytes(), b"hunter2 with spaces  ");
        assert!(echo_on(&watcher), "restored after a normal read");
        let shown = drain_master(&master);
        assert!(shown.starts_with(b"Passphrase: "));
        assert!(
            !shown.windows(7).any(|w| w == b"hunter2"),
            "the secret was not echoed"
        );
    }

    /// CLI 2: the hidden terminal session accepts a printed seven-line card,
    /// stops exactly after line seven, and applies every multiline boundary
    /// to whole lines.
    #[test]
    fn hidden_multiline_card_boundaries() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let card = crate::card::tests::fixed_card(1, 0x5a);
        let text = String::from_utf8(card.base32().expose_secret().to_vec()).unwrap();
        let printed = card.base32_lines().join("\n");

        let Pty { master, slave } = pty();
        let watcher = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_card_from(&slave));
        wait_for_echo(&watcher, false);
        (&master)
            .write_all(format!("{printed}\nEXTRA LINE\n").as_bytes())
            .unwrap();
        let payload = reader.join().unwrap().unwrap().unwrap();
        assert_eq!(payload.expose_secret(), card.payload());
        // The callback returned after line seven; it did not consume line 8.
        let mut extra = [0u8; 11];
        (&watcher).read_exact(&mut extra).unwrap();
        assert_eq!(&extra, b"EXTRA LINE\n");

        assert_eq!(
            card_input(format!("{}Z\n", &text[..216]).into_bytes()).unwrap_err(),
            CardTextError::TooMany
        );
        assert_eq!(
            card_input(format!("{}\n\n", &text[..215]).into_bytes()).unwrap_err(),
            CardTextError::TooFew(215)
        );
        let nine: String = text
            .as_bytes()
            .chunks(24)
            .map(|chunk| format!("{}\n", std::str::from_utf8(chunk).unwrap()))
            .collect();
        assert_eq!(
            card_input(nine.into_bytes()).unwrap_err(),
            CardTextError::TooManyLines
        );
    }

    /// A line queued before the hidden prompt is discarded by TCSAFLUSH and
    /// cannot become this prompt's card input (A1).
    #[test]
    fn queued_card_input_is_discarded_before_prompt() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let card = crate::card::tests::fixed_card(1, 0x5a);
        let text = card.base32();
        let Pty { master, slave } = pty();
        (&master).write_all(&[b'X'; 216]).unwrap();
        (&master).write_all(b"\n").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let _ = drain_master(&master); // discard the stale line's echo
        let reader = std::thread::spawn(move || read_card_from(&slave));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut shown = Vec::new();
        while !shown.windows(6).any(|w| w == b"Card: ") {
            shown.extend_from_slice(&drain_master(&master));
            assert!(Instant::now() < deadline, "card prompt was not shown");
            std::thread::sleep(Duration::from_millis(5));
        }
        (&master).write_all(text.expose_secret()).unwrap();
        (&master).write_all(b"\n").unwrap();
        let payload = reader.join().unwrap().unwrap().unwrap();
        assert_eq!(payload.expose_secret(), card.payload());
    }

    #[test]
    fn restored_after_cancellation() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let Pty { master, slave } = pty();
        let watcher = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&slave, ""));
        wait_for_echo(&watcher, false);
        (&master).write_all(&[0x04]).unwrap(); // VEOF (Ctrl-D) at the start of a line
        assert!(matches!(reader.join().unwrap(), Err(InputError::Cancelled)));
        assert!(echo_on(&watcher), "restored after cancellation");
    }

    /// Linux's canonical line limit (4,095) exceeds pvault's 1,024, so an
    /// over-long line reaches the reader there. macOS truncates canonical
    /// lines at 1,024 bytes, so this case is covered by the `input` tests.
    #[cfg(target_os = "linux")]
    #[test]
    fn restored_after_an_error() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let Pty { master, slave } = pty();
        let watcher = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&slave, ""));
        wait_for_echo(&watcher, false);
        let mut long = vec![b'x'; 1100];
        long.push(b'\n');
        (&master).write_all(&long).unwrap();
        assert!(matches!(reader.join().unwrap(), Err(InputError::TooLong)));
        assert!(echo_on(&watcher), "restored after an error");
    }

    /// Portable error path: a write-only descriptor lets the prompt and the
    /// echo change succeed, then the read itself fails.
    #[test]
    fn restored_after_a_read_error() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let Pty { master, slave } = pty();
        let write_only = std::fs::OpenOptions::new()
            .write(true)
            .open(slave_path(&slave))
            .unwrap();
        let result = read_secret_from(&write_only, "Passphrase: ");
        match result {
            Err(InputError::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EBADF)),
            other => panic!("expected a read error, got {other:?}"),
        }
        assert!(echo_on(&slave), "restored after a read error");
        drop(master);
    }

    fn slave_path(slave: &File) -> String {
        let mut buf = [0 as libc::c_char; 256];
        // SAFETY: `buf` is writable for its full length.
        let rc = unsafe { libc::ttyname_r(slave.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
        assert_eq!(rc, 0);
        // SAFETY: `ttyname_r` wrote a NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    fn signal_restores(signal: libc::c_int) {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let Pty { master, slave } = pty();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::terminal::tests::signal_helper_reads_from_pty",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PVAULT_TEST_PTY", slave_path(&slave))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        wait_for_echo(&slave, false);
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // SAFETY: sending a signal to our own child process.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        let status = child.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(signal),
            "the child died from the re-raised signal"
        );
        assert!(echo_on(&slave), "terminal restored by the signal handler");
        drop(master);
    }

    #[test]
    fn restored_after_sigint() {
        signal_restores(libc::SIGINT);
    }

    #[test]
    fn restored_after_sigterm() {
        signal_restores(libc::SIGTERM);
    }

    #[test]
    fn restored_after_sighup() {
        signal_restores(libc::SIGHUP);
    }

    #[test]
    fn restored_after_sigquit() {
        signal_restores(libc::SIGQUIT);
    }

    /// Run only as a subprocess by `signal_restores`.
    #[test]
    #[ignore = "helper process for the signal-restoration tests"]
    fn signal_helper_reads_from_pty() {
        let path = std::env::var("PVAULT_TEST_PTY").expect("run by signal_restores");
        // SIGQUIT's default action dumps core; this process must not.
        crate::platform::disable_core_dumps().unwrap();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let _ = read_secret_from(&tty, "");
        unreachable!("the parent sends a signal before any input");
    }
}
