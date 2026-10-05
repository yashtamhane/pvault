//! `--secrets-stdin` input (SI-19, SI-51 section 4), through real standard
//! input. Each case runs this test binary again as a helper process whose
//! stdin is a pipe or a terminal.

use std::io::Write;
use std::process::{Command, Stdio};

use pvault_core::input::{InputError, StdinSecrets};

const MARK: &str = "RESULT:";

/// Run only as a subprocess: reports what `StdinSecrets` read.
#[test]
#[ignore = "helper process for the stdin tests"]
fn stdin_helper() {
    let mut out = String::from(MARK);
    match StdinSecrets::open() {
        Err(InputError::StdinIsTerminal) => out.push_str("terminal"),
        Err(e) => out.push_str(&format!("open error {e:?}")),
        Ok(mut secrets) => loop {
            match secrets.next_secret() {
                Ok(line) => out.push_str(&format!("{},", line.len())),
                Err(InputError::TooLong) => {
                    out.push_str("too-long");
                    break;
                }
                Err(InputError::Cancelled) => {
                    out.push_str("end");
                    break;
                }
                Err(e) => {
                    out.push_str(&format!("error {e:?}"));
                    break;
                }
            }
        },
    }
    println!("{out}");
}

fn helper(stdin: Stdio) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "stdin_helper",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn result(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|l| l.split_once(MARK).map(|(_, r)| r.to_owned()))
        .expect("the helper reported a result")
}

fn with_piped_input(input: &[u8]) -> String {
    let mut child = helper(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    result(&child.wait_with_output().unwrap().stdout)
}

#[test]
fn reads_one_secret_per_line_from_a_pipe() {
    // CRLF is a line ending; a final line without LF still counts.
    assert_eq!(with_piped_input(b"one\r\ntwo  \nlast"), "3,5,4,end");
}

#[test]
fn eof_before_any_input_is_a_cancellation() {
    assert_eq!(with_piped_input(b""), "end");
}

#[test]
fn an_over_long_line_stops_reading() {
    let mut input = b"ok\n".to_vec();
    input.extend(vec![b'x'; 1025]);
    input.extend(b"\nnever read\n");
    assert_eq!(with_piped_input(&input), "2,too-long");
    let mut exact = vec![b'y'; 1024];
    exact.push(b'\n');
    assert_eq!(with_piped_input(&exact), "1024,end");
}

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn refused_when_stdin_is_a_terminal() {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid; the optional arguments are null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: `openpty` returned two new descriptors, owned by nothing else.
    let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    let output = helper(Stdio::from(slave)).output().unwrap();
    assert_eq!(result(&output.stdout), "terminal");
    drop(master);
}
