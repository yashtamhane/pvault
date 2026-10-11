# pvault command-line interface

**Status:** approved by the author for Milestone 4 (2026-10-05; A1). This
defines the Milestone 4 command surface (spec 14, SI-47, SI-19, SI-41). Later milestones add commands and options; anything not listed
here does not exist in Milestone 4. Conflicts with the governing spec are
listed in section 9.

## 1. Conventions

```text
pvault [GLOBAL OPTIONS] <command> <vault-dir> [ARGUMENTS] [OPTIONS]
```

- The vault directory is the first argument of every vault command.
- **Output streams.** Requested data (the `list` output, `status` report)
  goes to standard output. Messages, progress and warnings go to standard
  error. Prompts and anything shown for the owner's eyes only (the generated
  passphrase) go to the **terminal device** (`/dev/tty`, Windows
  `CONIN$`/`CONOUT$`), never to standard output or standard error.
- Messages are fixed English text without color.
- Sizes are bytes. Times are UTC, `YYYY-MM-DDTHH:MM:SSZ`.

### 1.1 What output may contain

| Content | Where it may appear |
| --- | --- |
| Passphrases, card text, shares, keys | Never on standard output or standard error. The generated passphrase only on the terminal device (section 2) |
| Stored vault paths (from the key table) | Only in `list` output, which is what the owner asked for. No message names a stored path |
| A vault path the owner typed in this command | In that command's messages, in its normalized (NFC) form: `add` ("Added …", "Stored as: …"), `get` ("Exported … to …"), `rm` errors, path-rule errors |
| Other entries' paths | Never in messages. A collision says that an existing entry differs only by case or Unicode form, without naming it; `list` shows it |
| Native file-system paths (vault folder, source, destination, card folder, settings folder, recorded export and card paths) | In messages, rendered by section 1.2 |
| Counts and sizes | Anywhere ("Removed 12 entries.") |

### 1.2 Safe rendering

Every path or file name that pvault prints, on any stream, goes through one
rendering function, so no output can carry terminal control sequences or
reorder text:

- The text is decoded as UTF-8 (Unix bytes) or UTF-16 (Windows units).
  Invalid bytes are written `\xHH`; unpaired surrogates `\u{D800}` style.
- These characters are written as `\u{XXXX}` (uppercase hex, no padding
  beyond 4 digits): C0 controls U+0000–U+001F, DEL U+007F, C1 controls
  U+0080–U+009F, U+2028, U+2029, the bidirectional controls U+061C,
  U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+FEFF, and every code point
  that is unassigned in Unicode 17.0.0 or is a noncharacter.
- A backslash is written `\\`. The escaping is therefore unambiguous and
  reversible.
- `list` uses the same rendering for stored paths. Stored paths can contain
  C1 and bidirectional controls (7.8 rejects only C0 and DEL), so this is
  required, not cosmetic. To address such an entry, the owner types the
  actual characters; the escaped form is display only.

### 1.3 Where plaintext and card files may be written (O3)

Exported files and card files are written only to a folder whose file system
pvault identifies as local and enforcing owner-only access in its own kernel
driver (decided 2026-10-06, fail closed). A successful permission-setting call
is never taken as proof.

| Platform | Supported destination types | Why |
| --- | --- | --- |
| Linux | `ext4`, `xfs`, `btrfs`, `tmpfs` | Local kernel file systems that store and enforce POSIX owner and mode bits (`tmpfs` in memory) |
| macOS | `apfs`, `hfs` | Local file systems that store and enforce owner and mode bits |
| Windows | `NTFS`, `ReFS` on a local volume (8.5 Q1 to Q4) | Store and enforce the owner-only DACL pvault sets |

On macOS the volume must also be mounted with ownership enforced: a volume
with "Ignore ownership on this volume" turned on (the `noowners` mount option,
common for external drives) reports `apfs` or `hfs` but enforces nothing, so it
is refused like an unsupported type (decided 2026-10-06, G1). To use such a
drive, turn the setting off in Finder (Get Info, Sharing & Permissions).

Refused: FAT and exFAT (no owner or permission storage; the mount or nothing
decides), FUSE (`fuseblk`, `fuse.*`: a user-space server decides), network
file systems (`nfs`, `cifs`, `smbfs`, `afpfs`, `webdav`, Windows shares: the
server decides), any other or unknown type (for example `zfs`, `overlay`,
`9p`), and any folder whose file system cannot be identified. The refusal is
exit 6 and comes before any secret is read and before any destination file
or record entry exists.

### 1.4 Vaults on unsupported file systems (O4)

A vault on a file system that pvault does not support for changes (8.5) can
still be read (`list`, `get` to a supported destination, `status`) **only if**
the stable file identity that the locking protocol needs is available
(Unix: device, inode and birth time; Windows: `FILE_ID_INFO`; spec 8.1, 8.4).
The identity and locking rules are not relaxed for reading (decided
2026-10-06, O4).

| File system holding the vault | Read-only commands | Changes |
| --- | --- | --- |
| macOS FAT/exFAT; Linux in-kernel `vfat`/`exfat` (birth time available) | Work | Refused (exit 6) |
| Windows FAT/exFAT (no `FILE_ID_INFO`); FUSE such as `fuseblk` (no birth time) | Refused (exit 6), nothing changed | Refused (exit 6) |

The refusal reads "This file system cannot safely store vault changes (no
stable file identity). Copy the vault to a supported drive to change it."
**Workaround:** copy the entire vault folder (every file, including `objects/`) to a supported local file system, then open that copy. The original folder is left unchanged.

## 2. Secrets, confirmations and the terminal

**TPM stack output:** the CLI turns the TPM software stack's own logging off
at startup (`TSS2_LOG`, overridden; Milestone 5), because at debug level it
logs session keys and parameters before encryption, and its error lines would
add detail to `Unlock failed.` (spec 5.6; `docs/M5_READINESS.md` 15).

**Secrets** are the passphrase (typed, confirmed or typed back), recovery
card text (Base32) and the TPM owner authorization (`--tpm-owner-auth`). They are **never** accepted as command-line arguments or
from environment variables, and no option or variable for them exists (F79).

| Source | When | Rules |
| --- | --- | --- |
| Terminal, hidden | Default | Echo off; restored on normal return, error, Ctrl-C, Ctrl-Break, SIGINT, SIGTERM, SIGHUP, SIGQUIT and window close. At most 1,024 raw bytes per line; a line ends at the first LF, and one CR before it is removed (SI-51 section 3) |
| Standard input | Only with the global `--secrets-stdin` | Standard input must not be a terminal (refused if it is). Secrets are read **one complete line each** (terminator required), in the order listed for each command in section 6. A card's text is one line holding exactly 216 symbols (separators allowed), validated as a whole line; more or fewer symbols reject it. pvault reads exactly the lines it needs and nothing more |
| Standard input without `--secrets-stdin` | Never | A secret prompt on a non-terminal standard input is refused, **also when a terminal device exists** (the terminal is used only when standard input is the terminal too). Commands that read secrets (`init`, `add`, `list`, `get`, `rm`, `duress`) refuse before anything is read or created: "Standard input is redirected. pvault reads secrets from it only with --secrets-stdin; otherwise run it with standard input on the terminal." (exit 6). Enforced from 2026-10-11 after Windows checklist step 9 found it missing (it was missing on every platform); message approved by the author (2026-10-11) |

**Card text typed at the terminal.** A printed card shows its text on 7
lines, so the hidden card prompt accepts one or more lines. Input is read and
validated **whole lines at a time**:

1. pvault reads one complete line, including its terminator (LF, with an
   optional CR before it), at most 1,024 bytes. A line is never split or
   partly used.
2. The whole line is validated: every character must be a Crockford symbol
   (7.4a input normalization: `I`/`L` read as `1`, `O` as `0`, any case) or a
   separator (space or hyphen). One invalid character rejects the attempt.
3. The line's symbols are added to the count. If the count now **exceeds**
   216, the attempt is rejected ("The card text has more than 216 symbols."),
   including when the excess is on the line that crossed 216.
4. If the count is **exactly** 216, the attempt is complete, and only now is
   the card text accepted for comparison. No further line is read for it.
5. Otherwise the next line is read. An empty line before 216, a ninth line,
   or end of input (no terminator after the last symbols) rejects the attempt.

A rejected attempt consumes nothing beyond the line that caused it; the
remaining type-ahead is discarded as described next. Nothing is echoed.

**Pending input is discarded before each hidden prompt.** Pasting can queue
more lines than a prompt uses (for example a card followed by a stray line).
Before each hidden prompt is displayed and read, pvault discards all pending
terminal input: on Unix the echo-off `tcsetattr` uses `TCSAFLUSH` (input
received but not yet read is discarded), and on Windows
`FlushConsoleInputBuffer` runs on the console input handle after
`SetConsoleMode`; only then is the prompt shown. pvault also clears and wipes
its own buffered input: the console reader's buffer belongs to one prompt and
is wiped when that prompt ends, and the Unix reader takes one byte at a time
with no buffer. This reduces the chance that stray queued lines answer a
later prompt. It does **not** prove which prompt was visible when a line was
typed, and it cannot stop input that arrives after the flush (for example
the tail of a slow paste); such input is read as the answer to the prompt
on screen. Type-ahead before a prompt is lost by design. Under
`--secrets-stdin` lines are consumed strictly in the documented order and
unread lines stay unread.

**Acknowledgments** ("Press Enter after printing") are read from the terminal
device when one exists, also under `--secrets-stdin`. Without a terminal they
are skipped; they are never read from standard input.

**Risk acknowledgments** (digital recovery cards, SI-52; 6.1) are consent, not
secrets. Each is given by `--accept-risk <token>` (accepted with or without a
terminal) or by its typed phrase (`STORE CARDS DIGITALLY`, `SAME DRIVE`) on
the terminal device. No environment variable gives one. Unlike the printing
acknowledgment, a missing risk acknowledgment is never skipped: without the
option and without a terminal, `init` stops (exit 4) before any secret is read
or anything is created.

**Confirmations** (typed phrases such as `ACCEPT MEDIUM PASSPHRASE` or
`DELETE INIT LEFTOVERS 1a2b3c4d`) are not secrets, but they authorize risky
actions. They are read **only from the terminal device**, never from standard
input, and their input is echoed. Without a terminal, every confirmation is
treated as declined (8.3: "non-interactive operation … leaves … blocked").

**Shown secrets.** The generated passphrase is displayed only on the terminal
device. Without a terminal, generated mode is refused (use `--custom` with
`--secrets-stdin`). The shown secret (a generated passphrase, or generated
duress words) stays on screen until the owner presses Enter on an **empty
line** at a labelled, hidden prompt (approved 2026-10-11): "Press Enter when
you have written it down (nothing needs to be typed): ". Echo is off; any
other input (typed text, a partial or over-long line) is discarded unseen,
nothing is cleared, and "Nothing needs to be typed here; that input was
discarded. Press Enter when you have written it down: " is shown before the
next read. End of input cancels (exit 7). Only after the empty line does
pvault clear the screen, on a best-effort basis; terminal scrollback, logs
and recordings may still hold it (7.4b remnants). Both messages are
approved (2026-10-11). On Windows the classic console (`conhost`) prints
control sequences literally unless virtual-terminal processing is on, so
pvault turns it on for the clearing sequences and restores the previous
mode; where it cannot, it blanks the whole console screen buffer through the
console API. Raw control sequences are never printed (fixed 2026-10-11 after
the Windows checklist showed `←[2J←[3J←[H`). On Windows, everything the
terminal module writes to the console (shown secrets, prompts) is written as
UTF-16 through `WriteConsoleW`, so it displays correctly whatever the
console's output code page (7.6a, amended 2026-10-11). The console's
previous output mode is restored after the clearing sequences. **Clearing
failures** (approved 2026-10-11): if pvault cannot clear the screen (no
terminal, a failed write or console call), the screen is left as it is,
standard error shows "Warning: pvault could not clear the displayed
passphrase. It may remain visible in the console or scrollback.", and the
command continues. If the console output mode changed for the clearing
(Windows) cannot be restored, standard error shows a separate warning,
"Warning: pvault could not restore the console output mode.
Escape-sequence processing may remain enabled."; when both fail, both are
shown, the clearing warning first. No warning does **not** mean the secret
was erased: a terminal may ignore the clearing sequences or keep its
scrollback, and pvault cannot tell; logs, recordings and other copies are
never reached. **Recovery-card text is never displayed** (decided
2026-10-05); cards exist only as files. Card Base32 may be **typed** back,
hidden, for verification.

## 3. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | The operation failed. Includes `Unlock failed.`, damaged data and I/O errors |
| 2 | Usage error (unknown command or option, bad argument) |
| 3 | The vault is in use by another pvault process |
| 4 | Blocked until the owner acts: a pending journal, unowned leftovers, a stale export, a declined confirmation, a missing risk acknowledgment (6.1), a `discard-card` without a terminal, a TPM owner authorization that is needed but was not declared with `--tpm-owner-auth` under `--secrets-stdin`, `duress set` while duress is configured |
| 5 | The outcome is uncertain: for a vault, run `fsck` (outcome unknown, durability unknown, indeterminate state, unresolved cleanup); for an export, the file was published but its durability is unconfirmed; a TPM index definition whose outcome is unknown (the journal is kept, 6.1) |
| 6 | Refused by the environment: unsupported file system (for a vault change, or an export or card destination without owner-only permissions), memory policy or resource limit, no terminal for a required prompt, unusable settings folder; bound mode on a platform without TPM support; a TPM that cannot be reached, whose identity cannot be measured (N2), whose storage hierarchy is disabled, that is in dictionary-attack lockout or that has no free NV handle; a TPM session that cannot be established securely; duress unavailable on this TPM |
| 7 | Cancelled by the owner inside pvault: declining at a prompt that cancels (for example `ACCEPT MEDIUM PASSPHRASE`), or end of input at a hidden terminal prompt (Unix: Ctrl-D on an empty line). The Windows console delivers Ctrl-Z as the character U+001A, which is input (refused as a control character), not cancellation |

**Native termination is not cancellation** (decided 2026-10-06, O2). Ctrl-C,
Ctrl-Break, SIGINT, SIGTERM, SIGHUP, SIGQUIT and closing the console window
end pvault through the system's default action after the terminal is
restored (7.6a). No pvault exit code is returned: on Unix the process is
ended by the signal (shells report 128 + the signal number, for example 130
for SIGINT); on Windows Ctrl-C and Ctrl-Break end it with
`STATUS_CONTROL_C_EXIT` (0xC000013A; `%ERRORLEVEL%` -1073741510). Crash
safety covers such an ending as it covers any process crash.

Every failure that depends on a secret (wrong passphrase, MAC failure, a
duress match) is `Unlock failed.` with code 1, so the code never reveals more
than the message.

## 4. Global options

| Option | Meaning |
| --- | --- |
| `--secrets-stdin` | Read secrets from standard input, one per line, in the documented order (section 2) |
| `--tpm <device\|swtpm:PORT>` | The TPM used by bound vaults (decided 2026-10-06, D9). `device` (the default) is `/dev/tpmrm0`. `swtpm:PORT` is a local emulator on `127.0.0.1`, commands on `PORT` and control on `PORT + 1` (tests and development). Not a secret; there is no environment variable for it. Ignored for portable vaults |
| `--tpm-owner-auth` | Declares that the TPM's owner authorization will be supplied: with `--secrets-stdin`, as one line at the position given for each command (6.1); otherwise as a hidden terminal prompt ("TPM owner authorization:"). The value is a secret: it never appears in arguments, the environment, messages or logs, and it is never stored. Without this flag, an interactive command asks for it (hidden) only when the TPM reports that owner authorization is set; a `--secrets-stdin` command then refuses (exit 4) before anything is written |
| `--help`, `-h` | Help |
| `--version`, `-V` | Version |

## 5. Command summary (Milestone 4)

| Command | Authentication (5.7) | Duress check | Vault lock (8.4) |
| --- | --- | --- | --- |
| `init` (new) | none | n/a | exclusive |
| `init` (resume, header present) | Path A | no | exclusive |
| `init` (resume, no header) | init-journal MAC | no | exclusive |
| `add`, `rm` | ordinary unlock | yes | exclusive |
| `list`, `get` | ordinary unlock | yes | exclusive for the unlock, then shared |
| `status` | none | no | shared |
| `clean-partials` | none | no | none (7.9) |
| `discard-card` | none; unlocks nothing (6.8) | no | shared, only with `--vault` |

**Card files never unlock a vault in Milestone 4** (decided 2026-10-06, SI-52
L1). `list`, `get`, `add` and `rm` need the passphrase as above and have no
card-file options (`--card-a-file` and similar are usage errors, exit 2).
Card files are read only by digital `init` (delivery and rehearsal) and by
`discard-card` (public fields only). Passphrase-free recovery is the
Milestone 6 `recover` command; `verify-card`, `recover` and `convert` accept
card files from Milestone 6 (`docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.2, 6.3).

Milestone 5 adds bound vaults (Linux, 6.1), `duress set` and `duress disable`
(6.9; inactive until Milestone 9), and the TPM lines of `status` (6.6). Bound
vaults use the same authentication as portable ones (spec 5.7): the ordinary
unlock reads S2 from the TPM.

Not available yet (spec 5.7 commands of later milestones, which the parser
does not accept): `recover`, `verify-card`, `convert`, `fsck`, `mount`, owner
Revoke, Erase, K2.

## 6. Commands

### 6.1 `pvault init`

```text
pvault init <vault-dir> --mode portable --cards paper --cards-dir <dir>
            [--card-a-png <file>] [--card-b-png <file>]
            [--words <10-16> | --custom]
            [--kdf-memory <MiB>] [--kdf-iterations <n>] [--kdf-parallelism <n>]

pvault init <vault-dir> --mode portable --cards digital
            --card-a-dir <dir> --card-b-dir <dir>
            [--accept-risk digital-cards] [--accept-risk same-volume]
            [--words <10-16> | --custom]
            [--kdf-memory <MiB>] [--kdf-iterations <n>] [--kdf-parallelism <n>]

pvault init <vault-dir> --mode bound --cards paper --cards-dir <dir>
            [--card-png <file>] [--words <10-16> | --custom] [kdf options]
            [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]

pvault init <vault-dir> --mode bound --cards digital --card-dir <dir>
            [--accept-risk digital-cards] [--words <10-16> | --custom] [kdf options]
            [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]

pvault init <vault-dir>          (resume; no other options except --tpm and --tpm-owner-auth)
```

| Argument or option | Meaning |
| --- | --- |
| `<vault-dir>` | The vault folder. Created if absent (8.3 bootstrap); if it exists it must be empty apart from zero-length `vault.gate` / `vault.lock` |
| `--mode portable\|bound` | Required; no default (decided 2026-10-06, D9; section 9, K1). `bound` needs Linux with TPM support (D10); elsewhere: "Bound mode needs a Linux computer with a TPM in this version." (exit 6), before anything is created |
| `--card-dir <dir>` | Bound and digital only, required there: the folder for the single bound card file (D8). Same rules as `--card-a-dir`; there is no second card, so no same-volume acknowledgment |
| `--card-png <file>` | Bound and paper only: verify the printed bound card from a PNG photo (the rules of `--card-a-png`) |
| `--cards paper\|digital` | Required for a new vault (decided 2026-10-06, SI-52 R1); no default. Missing: "--cards paper or --cards digital is required." (exit 2). **Paper:** printed cards; the card files are temporary and deleted after the commit. **Digital:** the card files are the recovery cards and are kept (below) |
| `--cards-dir <dir>` | Paper only, required there. An existing folder **outside** the vault for the two card files (7.4b). No default. It must be on a supported destination file system (1.3); otherwise `init` refuses (exit 6) before anything is created, the vault folder included, and before any secret is read (O3) |
| `--words <n>` | Generated passphrase of `n` words, 10 to 16. Default 12 |
| `--custom` | The owner writes the passphrase (estimated at creation only, SI-51) |
| `--kdf-memory <MiB>` | Argon2id memory, 256 to 4096; default 1024. Must also pass this computer's policy (≤ 50 % of RAM) and resource checks (4.3). Below 1024 prints "Lower memory makes passphrase guessing cheaper." |
| `--kdf-iterations <n>` | Argon2id `t`, 3 to 16; default 4 |
| `--kdf-parallelism <n>` | Argon2id `p`, 1 to 8; default 4 |
| `--card-a-dir <dir>`, `--card-b-dir <dir>` | Digital only, both required. Existing folders outside the vault, not links, on supported destination file systems (1.3, O3, G1; exit 6 otherwise, before anything is created and before any secret is read), and not the same folder ("Card A and Card B cannot be saved in the same folder.", exit 2). Card A is saved in the first, Card B in the second |
| `--accept-risk <token>` | Digital only; repeatable. `digital-cards` acknowledges the risks of digital cards; `same-volume` acknowledges both folders on one volume. Either may instead be typed on the terminal (`STORE CARDS DIGITALLY`, `SAME DRIVE`) when the option is absent. Not a secret (section 2) |
| `--card-a-png <file>`, `--card-b-png <file>` | Paper only. Verify a printed card from a PNG photo instead of typing its text. File paths are not secrets. **Needs the terminal device, also with `--secrets-stdin`** (decided 2026-10-06, O1): the photo is opened only after the printing acknowledgment on the terminal. Without a terminal: "Verifying a card from a PNG photo needs a terminal for the printing acknowledgment, also with --secrets-stdin. Nothing was written." (exit 6), before anything is created |

**Flow (new vault):**
1. Bootstrap and preflight (8.3 steps 1 to 7): open the parent, create the folder if absent, identify the file system, create the lock files, take the lock, re-check emptiness, run the preflight. Refusals use the 8.5 and 8.4 messages. The settings folder must allow durable registration (`docs/M4_READINESS.md` 7.1); otherwise `init` refuses here, before writing anything.
2. Passphrase:
   - **Generated** (needs the terminal device): the words, the entropy (`n × log2(7776)` bits) and the rating are shown on the terminal. "Write this passphrase down. Press Enter when done." Then the labelled, hidden wait that only an empty line ends (section 2, "Shown secrets"); the screen is cleared after it.
   - **Custom:** "Enter the new passphrase:" then "Enter it again:" (a mismatch: "The passphrases do not match.", and the pair is asked again; three mismatches end the command, exit 1, nothing written). Refusals and warnings follow SI-51 section 3, the NFC notice when applicable, then the estimate: weak is refused; medium needs the confirmation `ACCEPT MEDIUM PASSPHRASE`; strong continues. Estimator failure refuses the passphrase.
3. "Deriving keys…" (Argon2id), then the init journal and key table (8.3).
4. Card files are written to `--cards-dir` (`docs/M4_READINESS.md` 11): `pvault-<vault-id-8hex>-<set-id-8hex>-card-a.svg` and `…-card-b.svg`. Standard error: "Card files written: <path A>, <path B>. Print both, then keep the printed cards in two different places."
5. Printing acknowledgment on the terminal: "Press Enter after printing." (with `--card-*-png`: "Print both cards and save the PNG photos at the paths you gave, then press Enter."). It is read from the terminal device also under `--secrets-stdin`; without a terminal it is skipped, which is why `--card-*-png` needs one.
6. Delivery verification (6.4), Card A then Card B. Per card, the method is:
   - `--card-a-png` / `--card-b-png` given: that file is opened **now**, after the acknowledgment of step 5 (it did not exist when the command started) and decoded;
   - otherwise, with a terminal and no `--secrets-stdin`: "Card A: enter the path of a PNG photo of the printed card, or press Enter to type its text:", then the photo path or the hidden card prompt (section 2);
   - otherwise (`--secrets-stdin`): the next standard-input line is the card text.

   A mismatch gives "Card A does not match what was printed." Interactive verification allows **three** attempts per card (each attempt asks for the method again). Under `--secrets-stdin`, and for a `--card-*-png` file, there is exactly **one** attempt: a mismatch ends the setup, because a retry would desynchronize the input. Ending the setup rolls it back; the cards are invalid.
6a. Recovery rehearsal (both modes, SI-52 Q1): the two delivered cards (the
   photos or typed text of step 6; digital: the saved files) are combined
   through the recovery path, and the header and key table about to be
   committed must authenticate and decrypt under the recovered keys. The
   in-memory originals are not used. A failure: "Recovering this vault from
   the delivered cards failed, so the setup was rolled back; the cards are
   invalid." (exit 1). Nothing is read for it.
7. Type-back: "Type your passphrase from memory:" (hidden). Interactive: three attempts. Under `--secrets-stdin`: one line, one attempt; a mismatch rolls the setup back.
8. Commit (8.3), then the card files are deleted through the handles kept open since they were created (`docs/M4_READINESS.md` 11), then the journal is removed.
9. "Vault created: <vault-dir> (portable, vault ID <32 hex>). Keep Card A and Card B apart; together they can recover the vault without the passphrase."

**Mixing mode options** (`--cards-dir` or `--card-*-png` with `--cards
digital`; `--card-*-dir` or `--accept-risk` with `--cards paper`; card options on
a resume) is a usage error (exit 2) before anything is read or created.

**Digital flow** (decided 2026-10-06, SI-52; `docs/RECOVERY_DELIVERY_PROPOSAL.md`).
Before bootstrap and before any secret is read:
1. Both folders are checked (above). The risk text is printed to standard
   error ("Digital recovery cards: Card A and Card B together open this vault
   without the passphrase. …"), in every case.
2. `digital-cards`: from `--accept-risk digital-cards`, or, with a terminal,
   the typed phrase `STORE CARDS DIGITALLY`. Otherwise: "Digital recovery
   cards need your acknowledgment: give --accept-risk digital-cards, or type
   STORE CARDS DIGITALLY on a terminal. Nothing was written." (exit 4).
3. Both folders on one volume: "Card A and Card B are on the same volume
   (<type>). … Different volumes are not proof of different devices either:
   keep the cards on separate drives in separate places." Then
   `same-volume`: `--accept-risk same-volume` or the typed phrase `SAME
   DRIVE`; otherwise "Both cards on one volume need your acknowledgment: give
   --accept-risk same-volume, or type SAME DRIVE on a terminal. Nothing was
   written." (exit 4).
4. Warnings without an acknowledgment: "Warning: Card A is on the same drive
   as the vault."; for a folder under a well-known sync root (iCloud Drive,
   `~/Library/CloudStorage`, `~/Dropbox`, the OneDrive folders): "Warning:
   Card A's folder is inside <root>, which is usually synced to a cloud
   account: … pvault cannot detect every synced or backed-up folder, so no
   warning does not mean not synced."

Then steps 1 to 3 of the flow below. Step 4 saves Card A in `--card-a-dir` and
Card B in `--card-b-dir` (same file names): "Card files saved: <path A> (Card
A), <path B> (Card B). Checking them now." There is **no printing
acknowledgment** (step 5). Step 6 (delivery) reopens each saved file by name
without following links, requires the file pvault created, and reads it
through the card-file reader ("This is not an unmodified pvault card file
(format 1)."; a changed file: "The saved Card A file changed after it was
written; the setup was rolled back."). The recovery rehearsal and the type-back
follow as in steps 6a and 7. After the commit (step 8) the files are **kept**
and their records released: "Your recovery card files: <path A> (Card A) and
<path B> (Card B). Keep them on different drives in different places; pvault
will not delete them."

**Optional card check after the commit** (decided 2026-10-06, SI-52 R5;
proposal 6.5). Only for an **interactive** digital `init` (a terminal and no
`--secrets-stdin`; a non-interactive `init` omits it), after "Vault created:
…" is printed and every card-file handle, the card-operation lock and the
vault lock are released:

1. "The vault has already been created. Optional check: pvault has closed
   the card files, so you can now eject the drives that hold them, insert
   them again, and let pvault check that both cards read back and recover
   the vault. A failed check changes nothing: the vault stays, and no card
   file is deleted."
2. On the terminal device: "Type CHECK after re-inserting the drives to
   check the card files, or press Enter to skip:". Anything but `CHECK`:
   "Card check skipped." (exit 0).
3. With `CHECK`, each saved path is opened again without following links and
   read through the card-file reader, and the two cards go through the
   recovery rehearsal against the stored header and key table (shared vault
   lock). Passed: "Card check passed: <path A> (Card A) and <path B> (Card B)
   read back and recover this vault." (exit 0). Failed: "The vault was
   created, but the card check failed: <reason> The vault is unchanged and no
   card file was deleted. Check the drives and the card files before relying
   on them." (**exit 1, although the vault was created**). Nothing is rolled
   back, deleted or unregistered.

A digital setup that fails **before** the commit starts is rolled back and
both files are deleted through their handles: "The setup was rolled back;
the card files were deleted. If you copied them anywhere, delete those
copies: they are invalid." A failure **after** the commit started keeps both
files: "The setup was rolled back. The card files <paths> were kept; they are
probably invalid. pvault does not delete them now; check them with pvault
discard-card." After a restart no command deletes a digital card file (resume
below, 6.7, 6.8).

**Bound flow** (Milestone 5, decided 2026-10-06; spec 7.4d, 8.3, 9.1 to 9.3).
Before the bootstrap and before any secret is read, pvault connects to the TPM
(`--tpm`) and checks it:

1. The TPM identity must be measurable (H-2 EK, spec 8.1; C4). Otherwise:
   "This computer's TPM identity cannot be established, so a bound vault
   cannot be created here. You can create a portable vault instead." (exit 6,
   N2).
2. The storage hierarchy must be enabled (C2) and the TPM must not be in
   lockout (C3); otherwise the matching message (section 7), exit 6.
3. If owner authorization is set (C1) and none can be supplied (no terminal
   and no `--tpm-owner-auth`): exit 4.

Then the portable flow's steps 1 to 3 (bootstrap, passphrase, key
derivation), followed by, if needed, "TPM owner authorization:" (hidden;
under `--secrets-stdin` the line after the two passphrase lines). The
`prepared` journal records the chosen handle, both precomputed Names, the
policy nonce and the encrypted identity token; only then is the index
defined, S2 written and both Names confirmed. One card is written (paper
`…-bound.svg` in `--cards-dir`, or digital in `--card-dir`); delivery and the
rehearsal combine S1 from the passphrase with S3 from the delivered card.
After the type-back, an interactive `init` offers the duress step (6.9): "Type
SET DURESS to create a duress passphrase now, or press Enter to skip:". The
optional card check after the commit (R5) asks for the passphrase again,
because the bound card alone recovers nothing.

A failure before the `committing` record removes the index it defined
(under 9.2b, with the owner authorization if set) and rolls the setup back. An
index definition whose outcome is unknown keeps the journal: "The TPM index
definition did not complete; its outcome is unknown. The setup journal was
kept; run pvault init on the folder again." (exit 5).

**Non-interactive `init`** (`--secrets-stdin`; custom passphrases only). Every
branch, with the exact lines consumed:

| Point | Behavior | Lines read |
| --- | --- | --- |
| Start | Generated mode (no `--custom`) without a terminal device: refused, exit 6. `--card-a-png` or `--card-b-png` without a terminal device: refused, exit 6, before anything is created (O1) | 0 |
| Passphrase | Line 1: the passphrase. Line 2: the same again. A mismatch ends the command (exit 1, nothing written; no retry) | 2 |
| Estimate | Strong continues. Medium needs a confirmation: from the terminal device if one exists, otherwise refused (exit 6). Weak or estimator failure: refused (exit 1). Nothing written | 0 |
| Printing | Acknowledgment from the terminal device if one exists (always, with `--card-*-png`), otherwise skipped. Never read from standard input | 0 |
| Card A | `--card-a-png`: the file is read after the acknowledgment, no line. Otherwise the next line is Card A's text. One attempt | 0 or 1 |
| Card B | As Card A | 0 or 1 |
| Type-back | The next line. One attempt | 1 |
| End | Nothing more is read; remaining input is left unread | |

Total: 3 to 5 lines (paper). **Digital: exactly 3 lines** (passphrase, again,
type-back); no card line is ever read, and there is no printing
acknowledgment. **Bound** (Milestone 5): passphrase, again, then the owner
authorization line **only with `--tpm-owner-auth`**, then (paper) one card
line or none with `--card-png`, then the type-back: 3 to 5 lines; digital
bound: 3 or 4. The duress step is never offered without an interactive
terminal. Paper card lines **cannot be prepared in advance**: the cards
are generated during the run. The supplier of standard input must wait for
the "Card files written" line on standard error (or for the files), read the
card text from the SVG files or the printouts, and only then write lines 3
and 4. The test harness does exactly that. End of input before a needed line:
"Input ended before all secrets were read." (exit 1), and the setup is rolled
back if it had started.

**Resume** (`pvault init <vault-dir>` on a folder with an init journal or a
committed header, 8.3 restart table):
- With a header that matches the journal: "This vault's setup was interrupted after it was saved. Enter the passphrase to finish:" (Path A; no duress check). Then the post-commit completion.
- Without a header: "This folder holds an interrupted setup. Enter the passphrase used for it:" (the journal's `passphrase_kind` selects the handling). Authenticated artifacts are removed, and the setup is rolled back: "The interrupted setup was removed. Run pvault init again." Unowned candidates are listed with name, file identity and size; removing them needs the terminal confirmation `DELETE INIT LEFTOVERS <first 8 hex of setup_id>`.
- **Digital card files after a restart are never deleted.** On resume, records whose card set is the vault's current card set (authenticated header) are released: "Your recovery card files are: <paths>. Keep them on different drives in different places." Others are kept and named: "Card files of the interrupted setup (card set <16 hex>) were kept: <paths>. They are probably invalid, but pvault does not delete them after a restart; check them with pvault discard-card."
- **Bound setup without a header** (8.3 restart table): after the journal authenticates, the journaled index is resolved on the present TPM. The encrypted identity token must match the live TPM; then an absent index, or an index whose Name is neither journaled Name, is left alone and reported ("not ours"), and an index with a journaled Name and the exact public area is removed (owner authorization if set). On another TPM, or when the identity cannot be measured: "This setup's TPM index is on another TPM or cannot be checked here (handle 0x<8 hex>). Nothing was deleted; run pvault init on the computer that created it." (exit 4).
- **Bound setup with a header:** Path A reads S2 from the TPM (no duress check); the index is kept.
- `--secrets-stdin` on resume: exactly one line, the passphrase; a bound setup without a header adds the owner authorization line when `--tpm-owner-auth` is given. Confirmations (residue removal, stale card files) come only from the terminal device; without one they are declined and the command reports what blocks it (exit 4).

### 6.2 `pvault add`

```text
pvault add <vault-dir> <source-file> <vault-path> [--replace]
```

- `<source-file>`: a regular file. Rules in `docs/M4_READINESS.md` section 10 (no symlink or reparse point as the final component, no special files, change detection).
- `<vault-path>`: normalized to NFC; code points unassigned in Unicode 17.0.0 are refused; the 7.8 rules apply; it must not collide (canonical caseless match) with an existing entry unless `--replace` names exactly that entry's stored path. Missing parent folders are created. If normalization changed the text: "Stored as: <path>". All paths are printed with section 1.2.
- `--replace`: replaces exactly that file entry with a new object, ID and keys (7.7). Replacing a folder with a file is refused.
- Secrets: the passphrase (one line with `--secrets-stdin`).
- Success: "Added <vault-path> (<size> bytes)." Created parents: "Created <n> folders." (their paths are prefixes of the typed path).
- Pending leftovers and journals: section 7 of this document and `docs/M4_READINESS.md` section 9.

### 6.3 `pvault list`

```text
pvault list <vault-dir> [<vault-path>]
```

Lists every entry, or the entry and descendants of `<vault-path>`, in key-table
order. One line per entry on standard output, tab-separated:

```text
<kind>\t<size>\t<modified>\t<path>
file	1048576	2026-10-05T12:00:00Z	docs/report.pdf
dir	-	2026-10-05T12:00:00Z	docs
```

Paths cannot contain tabs or line breaks (7.8), so the format is unambiguous.
Secrets: the passphrase.

### 6.4 `pvault get`

```text
pvault get <vault-dir> <vault-path> <destination> [--force]
```

- Exports one file entry to `<destination>`, which must not exist. The destination folder must be on a supported destination file system (1.3); otherwise `get` refuses (exit 6) **before the passphrase is read** and before any file or record is created (O3). Exporting **from** a vault on another file system to a supported destination works.
- Writes `<destination>.pvpartial` first (7.9), verifies every chunk, then renames without replacing. The suffix `.pvpartial` is 10 ASCII characters: 10 bytes in UTF-8 and 10 UTF-16 code units. Whether the suffixed name fits is decided by the destination's own file system, in its own units (bytes on ext4, XFS, Btrfs and APFS; UTF-16 units on NTFS, ReFS, FAT, exFAT and HFS+). pvault does not guess a limit: if exclusive creation fails because the name is too long (`ENAMETOOLONG`; Windows `STATUS_OBJECT_NAME_INVALID` or `ERROR_FILENAME_EXCED_RANGE`), `get` refuses before writing anything: "The destination name is too long to add the .pvpartial suffix on this file system." The same rule applies to card file names.
- `--force` gives "The --force option is not available in this version; nothing was written." (exit 2) (SI-11; refused throughout Milestone 4).
- Before exporting, stale exports of this vault are offered for removal (7.9): "An interrupted export of this vault left these files: <list>. Delete them? Type DELETE STALE EXPORTS to confirm:". Declining leaves them and continues. A file is deleted only if its recorded identity, including a recorded birth time, still matches (`docs/M4_READINESS.md` 7.2); otherwise pvault deletes nothing and names it so the owner can check it ("pvault cannot prove that <path> is the file it created; delete it yourself if it is. It may contain exported plaintext."). The settings folder must allow durable registration (`docs/M4_READINESS.md` 7.1); otherwise `get` refuses before creating anything (exit 6).
- Secrets: the passphrase.
- **Publication.** The export is *published* when the no-replace rename makes `<destination>` visible.
  - A failure **before** publication (decryption, verification, writing, flushing the partial, or a rename that verifiably did not happen): the partial is deleted through its open handle, nothing exists at `<destination>`, exit 1.
  - A failure **after** publication (the parent folder's flush, or the record update that follows): the exported file is **kept**: "Exported <vault-path> to <destination>, but the export could not be confirmed as durable." (exit 5). pvault never deletes a published file.
  - A rename that reports failure is classified by looking at the names: if `<destination>` is the file pvault holds open, it was published; if the partial name still is, it was not; anything else is reported as "The export's outcome could not be determined; check <destination>." (exit 5), and nothing is deleted.
- Success: "Exported <vault-path> to <destination> (<size> bytes)."

### 6.5 `pvault rm`

```text
pvault rm <vault-dir> <vault-path> [--recursive]
```

Removes a file entry, or an empty folder entry. A non-empty folder needs
`--recursive`. Secrets: the passphrase. Success: "Removed <n> entries."

### 6.6 `pvault status`

```text
pvault status <vault-dir>
```

No passphrase, shared lock only, never writes to the vault. Reports public
state only (5.8):

```text
Vault ID:            <32 hex>
Mode:                portable
Generation:          <n>   (key table <n>)
Argon2id:            <m> MiB, t=<t>, p=<p>   (this computer: OK | needs more memory)
Passphrase kind:     generated | custom
Duress:              off | configured (inactive: no duress action in this version)
Card set:            <16 hex>
Pending operation:   none | <op> <phase> (not verified)
File system:         <type>, supported | <type>, read-only for pvault
Rollback record:     highest generation seen here <n> | none | unavailable
Protection:          core dumps <off | best effort>, memory locking <available | limited>
```

- A header that does not parse: "The header does not parse." (exit 1). Allowed for `status` by 5.8.
- An exclusive holder: "The vault is in use by another pvault process." (exit 3).
- A lower generation than recorded: the 9.7 warning.
- Duress is configured with `duress set` (6.9) but is **inactive** until the duress action exists (Milestone 9, decided 2026-10-06, D6): a match is `Unlock failed.` and changes nothing, and `status` says so.
- **Bound vaults** add, after `Mode:` (Milestone 5; D4):

  ```text
  TPM:                 <device | swtpm:PORT>, reachable | unavailable (<reason>)
  Owner authorization: set | not set
  Storage hierarchy:   enabled | disabled
  Lockout:             no | yes   (failed authorizations <n> of <max>)
  TPM identity:        measurable | not measurable
  ```

  and when C1 to C4 fail the duress line reads `configured (inactive …); unavailable on this TPM: <reasons>`, or `off (unavailable on this TPM: <reasons>)` (F81). Unavailable duress is reported **only** here, never during an unlock. A reachable TPM is queried with public commands only (`GetCapability`, `NV_ReadPublic` and an EK `CreatePrimary` with empty authorization); nothing is defined or deleted.

### 6.7 `pvault clean-partials`

```text
pvault clean-partials
```

Takes no vault lock (7.9). Lists stale export records (their transfer lock is
free) and, once SI-10 is approved, stale card-file records. Entries whose
operation is still running are skipped entirely. Deletion needs the terminal
confirmation `DELETE <n> STALE FILES`; each file is reopened without following
links and deleted only if its recorded identity matches, including a recorded
birth time. Entries without a recorded birth time are never deleted: they are
reported for the owner to handle, and dropped from the record only after
confirmation. Without a terminal it only lists (exit 4 if anything is stale).

**Digital card records** (SI-52 L2) are listed separately and their files are
**never deleted**: "Digital recovery card files of interrupted setups (pvault
never deletes these; they may be valid current cards):", one line per file
with its role, path, card set and vault folder, then "Compare the card set with
pvault status for that vault, or run pvault init on the vault folder.
Forgetting the records keeps every file." The terminal confirmation `FORGET <n>
CARD RECORDS` removes only the records. To delete a file, use `discard-card`
(6.8).

### 6.8 `pvault discard-card`

```text
pvault discard-card <card-file> [--vault <vault-dir>]
```

Deletes one recovery card file that the owner names (SI-52 8.3). pvault never
chooses the file and unlocks nothing.

1. The file is opened without following links and read through the card-file
   reader (format 1, at most 64 KiB). Anything else is refused and nothing is
   deleted: "This is not an unmodified pvault card file (format 1)." (exit 1).
2. "<path> is Card A of vault <32 hex>, card set <16 hex>."
3. With `--vault`: the vault's **public** header is read under a shared lock,
   without any secret, and compared. The result is always labeled as not
   verified: "Not verified: the header of <vault-dir> names this card's set as
   its current card set." (or "names a different card set as current (this
   card may be old)", or "names a different vault"), followed by "These header
   fields were read without any secret; anyone who can write that folder could
   have changed them." An unreadable header: "The header of <vault-dir> could
   not be read; nothing is known about this card's status."
4. Always: "pvault cannot verify whether this is a current card. Destroying a
   current card leaves the vault recoverable only with the passphrase or with
   another copy of this card."
5. Confirmation on the terminal device only: `DISCARD RECOVERY CARD <first 8
   hex of the card set>`. No option replaces it. Without a terminal: "Discarding
   a card file needs the typed confirmation on a terminal. Nothing was
   deleted." (exit 4); declined: "Not confirmed. Nothing was deleted." (exit 4).
6. The file opened in step 1 is deleted through that handle; if the path now
   names another file: "The file changed after it was read; nothing was
   deleted." Any matching `cards.cbor` record is removed.
7. "Deleted. Deleting a card file does not erase it from flash storage,
   snapshots, backups, cloud history or thumbnail caches; destroy a drive that
   held it, or replace the card set."

Verified current membership needs both cards and Path B (`verify-card`,
Milestone 6); `discard-card` does not attempt it.

### 6.9 `pvault duress set` and `pvault duress disable`

```text
pvault duress set <vault-dir>
pvault duress disable <vault-dir>
```

Approved for Milestone 5 (2026-10-06, D5 to D7; spec 6.10). Both commit
through the `update` journal (a new key table generation and header, spec
8.3); the vault's data is unchanged.

- **`duress set`:** the ordinary unlock (with the duress check); refused while
  a tag is configured ("Duress is already configured. Run pvault duress
  disable first.", exit 4); needs the terminal device (the duress passphrase
  is generated and shown only there; exit 6 without one); bound vaults need
  C1 to C4 (otherwise "Duress is unavailable on this TPM: <reasons>.", exit 6).
  A 12-word duress passphrase is shown once, must differ from the main
  passphrase, and is typed back ("Type the duress passphrase from memory:",
  hidden; three attempts interactively, one under `--secrets-stdin`). When
  the main passphrase is custom and generated-word handling refuses it, the
  N3 timing notice is printed (section 7). Success: "Duress passphrase set. It
  is inactive in this version: entering it fails like a wrong passphrase and
  changes nothing."
- **`duress disable`:** the ordinary unlock, then the terminal confirmation
  `DISABLE DURESS`; the tag is removed. Without a terminal or when declined:
  exit 4, nothing changed.
- `--secrets-stdin` lines: `set`: the passphrase, then the duress type-back
  line; `disable`: the passphrase.
- The tag's presence is visible to anyone who can read the header (spec 9.6).

## 7. Messages

Existing, unchanged: every message of spec 4.3, 5.8, 7.3, 7.8, 8.4, 8.5 and the
Milestone 3 messages (SPEC_ISSUES 10.11, decided 2026-10-05):

| Condition | Message |
| --- | --- |
| Any secret-dependent unlock failure | `Unlock failed.` |
| Unknown word | `Word N is not in the word list.` |
| Policy limit | `This vault needs <m> MiB of memory, more than this computer can provide.` |
| Resource limit | `Not enough free memory to open this vault right now (needs <m> MiB).` |
| Lock | `The vault is in use by another pvault process.` |
| File system | `This file system cannot safely store vault changes (<type>). Copy the vault to a supported drive to change it.` |
| Entry limit | `This vault can hold at most 65,536 files and folders.` |
| Outcome unknown | `The header replacement outcome could not be determined. Run fsck before making further changes.` |
| Generation changed | `The vault changed during this operation. The header was not committed.` |
| Indeterminate | `The vault state could not be determined safely. No cleanup was performed. Run fsck.` |
| Durability unknown | `The new header is visible, but commit durability could not be confirmed; run fsck.` |
| Missing tracking header temp | (Milestone 3 text; recovery only) |

New in Milestone 4 (wording for approval):

| Condition | Message |
| --- | --- |
| Pending journal of another kind | `This vault has an unfinished <operation>. Run fsck to finish it.` |
| Unresolved `update` cleanup | `This vault's last change was saved, but its cleanup could not be finished because a file it needs is missing. Nothing was deleted. Run fsck.` (followed by the files not referenced by the current key table) / `Type CLOSE UNFINISHED CLEANUP <8 hex> to stop tracking it (no file is deleted):` |
| Unowned leftovers block | `Files pvault cannot prove it created block this change: <names>. Nothing was deleted.` |
| Card structure | `This is not a pvault recovery card.` / `This card belongs to another vault.` / `This is an old card.` / `This card is for a vault of the other mode.` / `These two cards are both Card A.` / `These two cards are both Card B.` / `These two cards belong to different vaults.` / `These two cards are from different card sets.` / `This is Card B, not Card A.` / `This is Card A, not Card B.` / `The card text must have 216 characters; <n> were entered.` / `The card text contains an invalid character at position <n>.` |
| PNG | `The image is not a PNG file.` / `The image is too large.` / `Animated PNG images are not supported.` / `No QR code was found in the image.` / `More than one QR code was found in the image.` |
| Card destination | `Card files cannot be written inside the vault folder.` / `A file named <name> already exists in <dir>; nothing was written.` |
| Private destinations (O3) | `pvault writes exported files and recovery cards only where it can confirm that the file system keeps them private to you (owner-only access). This destination is on <type>, which it cannot confirm. Nothing was written. Choose a folder on <suggestion>.` (exit 6; `<type>` is the reported type, or "unidentified or network file system"; the suggestion names the supported local types of 1.3) |
| Digital cards (SI-52) | `--cards paper or --cards digital is required.` (exit 2) / `Card A and Card B cannot be saved in the same folder.` (exit 2) / `This is not an unmodified pvault card file (format 1).` / `This file is too large to be a pvault card file.` / `The saved <Card A\|Card B> file changed after it was written; the setup was rolled back.` / `Recovering this vault from the delivered cards failed, so the setup was rolled back; the cards are invalid.` / the acknowledgment, warning, rollback, resume, card check, `clean-partials` and `discard-card` texts of 6.1, 6.7 and 6.8 |
| Card photos (O1) | `Verifying a card from a PNG photo needs a terminal for the printing acknowledgment, also with --secrets-stdin. Nothing was written.` (exit 6) |
| Path input (`<path>` is the owner's typed path, normalized) | `<path> already exists in the vault. Use --replace to replace it.` / `<path> collides with an existing entry that differs only by letter case or Unicode form. Use pvault list to see it.` / `--replace must name the stored path exactly. Use pvault list to see it.` / `This path is not allowed in a vault: <reason>.` / `<path> contains a character this version of pvault does not support.` |
| Source | `The source is not a regular file.` / `The source is a symbolic link or reparse point; give the file itself.` / `The source file changed while it was being added; the vault was not changed.` |
| Input | `The passphrases do not match.` / `Input ended before all secrets were read.` / `The card text has more than 216 symbols.` |
| Export | `Exported <vault-path> to <destination>, but the export could not be confirmed as durable.` / `The export's outcome could not be determined; check <destination>.` / `The destination name is too long to add the .pvpartial suffix on this file system.` / `<destination> already exists; nothing was written.` / `<destination>.pvpartial already exists; nothing was written.` / `The destination folder is a symbolic link or reparse point.` / `This file system cannot export without overwriting safely; nothing was written.` |
| Source in use (Windows) | `The source file is in use by another program.` |
| Settings folder and records | `The pvault settings folder <path> is not private to you.` / `Exports and card files need a settings folder on a supported local drive (<type>).` / `The export could not be registered durably; nothing was exported.` / `The card files could not be registered durably; no card was written.` / `The export record <path> is damaged; pvault will not change it. Move it aside to continue.` (moving it aside leaves any export it tracked untracked; the message's help text says so) / `Too many unfinished exports are recorded. Run pvault clean-partials.` / `Too many unfinished card files are recorded. Run pvault clean-partials.` / `Card files cannot be tracked on this file system.` / `This path is too long to track safely.` |
| Rollback record (9.7) | `This vault is older than a copy opened on this computer before (generation <g> < <r>). It may be an old copy.` (warning) / `Rollback detection is unavailable: <reason>.` (warning) / `The rollback record is full; this vault is not tracked.` (warning) |
| Leftover confirmation | `Type DELETE VAULT LEFTOVERS <8 hex> to delete exactly these files:` |
| Unprovable stale file | `pvault cannot prove that <path> is the file it created; delete it yourself if it is.` (exports add `It may contain exported plaintext.`; card files add `It may hold a recovery card.`) |
| Duress (Milestone 5) | `Duress passphrase set. It is inactive in this version: entering it fails like a wrong passphrase and changes nothing.` / `Duress is already configured. Run pvault duress disable first.` / `Duress is unavailable on this TPM: <reasons>.` / `Duress disabled.` / N3: `Your custom passphrase is one that generated-word handling refuses. With a duress passphrase set, unlocking with it takes about one Argon2id run less than other inputs, so someone timing unlock attempts can tell. Choosing a passphrase that generated-word handling accepts avoids this.` A duress match is `Unlock failed.` and changes nothing |
| TPM (Milestone 5) | `Bound mode needs a Linux computer with a TPM in this version.` / `The TPM could not be reached (<target>).` / `This computer's TPM identity cannot be established, so a bound vault cannot be created here. You can create a portable vault instead.` / `The TPM's storage hierarchy is disabled, so its NV indices cannot be used.` / `The TPM is in dictionary-attack lockout. Try again after it recovers.` / `No free TPM NV handle was found.` / `A secure TPM session could not be established; nothing was done.` / `The TPM owner authorization was not accepted.` / `The TPM requires owner authorization; give --tpm-owner-auth to supply it.` / `The TPM index definition did not complete; its outcome is unknown. The setup journal was kept; run pvault init on the folder again.` / `TPM cleanup capacity is full; resolve a recorded index on its original TPM.` / `This setup's TPM index is on another TPM or cannot be checked here (handle 0x<8 hex>). Nothing was deleted; run pvault init on the computer that created it.` (exit 4) / `Removed this setup's TPM index (handle 0x<8 hex>).` / `TPM handle 0x<8 hex> now holds an index that is not this setup's; it was left alone.` / `The TPM index of this setup could not be removed now. The setup journal was kept; run pvault init on the folder again to finish removing it.` |
| Bound card (Milestone 5) | `Card file written: <path>. Print it, then keep the printed card away from this computer.` / `Card file saved: <path> (Bound card). Checking it now.` / `Your recovery card file: <path> (Bound card). Keep it on a drive in a different place; pvault will not delete it.` / the bound risk text (`Digital recovery card: this card file together with your passphrase opens this vault without the TPM. …`) / R5: `Enter the passphrase to check the card:`, `Card check passed: <path> (Bound card) reads back and, with your passphrase, recovers this vault.` |

## 8. Locking and journals in commands

- Lock order and protocols: spec 8.4 (G + L). Every attempt is non-blocking.
- `add`, `rm`, `list` and `get` check for a pending journal after the duress check (5.7). An authenticated `update` journal (if approved; `docs/M4_READINESS.md` section 9) is resolved under the exclusive lock before the command continues; `list` and `get` resolve it before they downgrade. Any other journal stops the command with exit 4.

## 9. Conflicts with the governing spec

| # | Spec | Conflict | Proposal |
| --- | --- | --- | --- |
| K1 | 1 ("Bound mode (default)") | A bound default would fail on every platform without TPM support, and the wizard default is undecided (spec 16 item 3) | Decided 2026-10-06 (D9): `--mode` stays required in the CLI for v1 development; bound mode exists on Linux from Milestone 5 (D10) |
| K2 | 10.6, 7.3 | The spec does not say where a generated passphrase is shown when there is no terminal | Shown only on the terminal device; generated mode needs a terminal |
| K3 | 7.3 (medium band), 10.6 | `ACCEPT MEDIUM PASSPHRASE` is a confirmation; confirmations come only from the terminal | Non-interactive custom passphrases must estimate strong |
| K4 | 8.4 ("must stop and direct the owner to fsck") | Resolving an `update` journal inside `add`/`rm`/`list`/`get` is a new exception | Part of the SI-40 decision (`docs/M4_READINESS.md` section 9) |
| K5 | 10.2 (`status` shows the protection state) | `status` cannot know the memory-locking result of another process | `status` reports this computer's capability (a test lock) and the core-dump state |
| K6 | 8.3 ("optional duress"), 9.6 (duress action) | Duress setup exists from Milestone 5, but the duress action is a Milestone 9 feature behind the Milestone 8 gate | Decided 2026-10-06 (D5, D6): `duress set`/`disable` and the `init` step are built; a configured duress passphrase is inactive (a match is `Unlock failed.` and changes nothing) and `status` says so |
| K7 | 7.9 (`.pvpartial` beside the destination) | Some destination names leave no room for the 10-character suffix; the limit and its units depend on the destination file system | Refused when exclusive creation reports the name as too long (6.4); no limit is guessed |
| K9 | 10.6 (secrets one per line) | Card text on a printed card spans 7 lines, and a non-interactive `init` cannot know card text before the cards exist | Terminal card entry may span lines (section 2); under `--secrets-stdin` a card is one line, supplied after the cards are written (6.1) |
| K10 | 7.4b, 7.9 (no display of secrets; terminal output) | Stored paths may contain C1 and bidirectional controls, which a terminal would interpret | Safe rendering of every printed path (1.2) |
| K8 | none | Exit codes are not in the spec | Section 3 |
| K11 | 7.4c, 6.4 | A photo of a newly printed card cannot exist before the cards are written; without an acknowledgment pause a non-interactive run would read it too early | Decided 2026-10-06 (O1): `--card-*-png` needs the terminal device; the photo is read after the terminal acknowledgment (6.1) |
| K13 | 7.9, 7.4b (owner-only files) | Owner-only access can be relied on only where the local kernel enforces it; FAT/exFAT have none, FUSE and network servers decide for themselves, and an unidentified file system proves nothing | Decided 2026-10-06 (O3, fail closed): only the types of 1.3 are export and card destinations; everything else is refused (exit 6) before any secret, file or record; vaults elsewhere stay readable |
| K14 | 7.4b (card files are temporary print artifacts) | Owners without a printer need the card files as the deliverable | Decided 2026-10-06 (SI-52, revision 4): `--cards paper\|digital` (6.1, 6.7, 6.8; spec 7.4d) |
| K12 | 7.6a (restore on signals) | Ctrl-C was listed under exit 7, but the accepted handlers restore the terminal and then end the process natively | Decided 2026-10-06 (O2): handlers unchanged; section 3 separates native termination from cancellation (exit 7) |
