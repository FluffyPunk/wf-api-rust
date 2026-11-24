use std::io::Write;
use std::process::ExitCode;

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

mod process;
use process::ProcessHandle;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

static KEY: [u8; 16] = [76, 69, 79, 45, 65, 76, 69, 67, 9, 69, 79, 45, 65, 76, 69, 67];
static IV: [u8; 16] = [49, 50, 70, 71, 66, 51, 54, 45, 76, 69, 51, 45, 113, 61, 57, 0];

const PATTERN: &[u8; 11] = b"?accountId=";
const ACCOUNT_ID_LEN: usize = 24;
const NONCE_PREFIX: &[u8; 7] = b"&nonce=";
// Warframe account IDs are 24-character lowercase-hex ObjectIds. The literal
// pattern also matches a URL-template string baked into the game binary
// (used to build requests with extra parameters), which has unrelated text
// instead of a real ID and no nonce digits. Validating the shape rejects
// that false positive, so the first valid occurrence is accepted.

/// Bytes scanned per read. Bounds peak memory use regardless of how large
/// the target's regions are, and lets one unreadable chunk be skipped without
/// losing the rest of its region.
const CHUNK_SIZE: usize = 4 << 20;
/// Nonces are u64s (at most 20 digits); leave headroom anyway.
const MAX_NONCE_DIGITS: usize = 32;
/// Bytes needed from the start of a match to parse it completely. Consecutive
/// chunks overlap by this much so matches straddling a boundary aren't lost.
const MATCH_SPAN: usize = PATTERN.len() + ACCOUNT_ID_LEN + NONCE_PREFIX.len() + MAX_NONCE_DIGITS;

fn is_plausible_account_id(bytes: &[u8]) -> bool {
    bytes.len() == ACCOUNT_ID_LEN && bytes.iter().all(u8::is_ascii_hexdigit)
}

/// Parses `?accountId=<24 hex chars><7 bytes><digits>` from the start of
/// `bytes` (the caller has already matched `PATTERN`), returning the account
/// ID and nonce digits.
fn parse_authz(bytes: &[u8]) -> Option<(&str, &str)> {
    let id = bytes.get(PATTERN.len()..PATTERN.len() + ACCOUNT_ID_LEN)?;
    if !is_plausible_account_id(id) {
        return None;
    }
    let nonce = bytes.get(PATTERN.len() + ACCOUNT_ID_LEN + NONCE_PREFIX.len()..)?;
    let digits = nonce.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    // Both slices are ASCII (validated above), so these can't fail.
    Some((
        std::str::from_utf8(id).ok()?,
        std::str::from_utf8(&nonce[..digits]).ok()?,
    ))
}

#[allow(non_snake_case)]
fn gruzzleAuthz(mod_: &ProcessHandle) -> Option<String> {
    print!("Gruzzling");
    let _ = std::io::stdout().flush();

    let regions = mod_.regions();
    let mut chunks_read = 0u32;
    let mut matches_found = 0u32;
    // Reused across all chunks so only one allocation of this size is made.
    let mut buf = Vec::new();
    for region in &regions {
        let end = region.base.saturating_add(region.size);
        let mut pos = region.base;
        while pos < end {
            let scan_len = CHUNK_SIZE.min(end - pos);
            let read_len = (scan_len + MATCH_SPAN).min(end - pos);
            let chunk_base = pos;
            pos += scan_len;

            buf.resize(read_len, 0);
            if mod_.read(chunk_base, &mut buf).is_err() {
                continue;
            }
            chunks_read += 1;

            // Unlike upstream's `externalScan` (first hit per region only), we
            // check every occurrence: a false positive earlier in the same
            // region (e.g. a URL-template string) could otherwise hide a
            // genuine, later one.
            for offset in memchr::memmem::find_iter(&buf, PATTERN) {
                // Matches in the overlap tail belong to the next chunk.
                if offset >= scan_len {
                    break;
                }
                matches_found += 1;

                // Parse straight from the buffer. Only a match right at the
                // end of a region needs another read, which may extend into
                // the adjacent mapping.
                let in_buf = &buf[offset..];
                let extra;
                let bytes = if in_buf.len() >= MATCH_SPAN {
                    in_buf
                } else {
                    extra = mod_.read_vec(chunk_base + offset, MATCH_SPAN);
                    extra.as_deref().unwrap_or(in_buf)
                };
                let Some((account_id, nonce)) = parse_authz(bytes) else {
                    continue;
                };
                let authz = format!("?accountId={account_id}&nonce={nonce}");

                eprintln!(
                    "\n[debug] match #{matches_found} @ {:#x} (region {:#x}+{:#x}): {authz}",
                    chunk_base + offset,
                    region.base,
                    region.size
                );
                println!(" The crumbs have been gruzzled.");
                return Some(authz);
            }
        }
    }
    eprintln!(
        "[debug] {} regions total, {chunks_read} chunks read successfully, {matches_found} pattern matches",
        regions.len()
    );
    println!(" Failed to gruzzle the crumbs.");
    None
}

fn pause() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "pause > nul"])
            .status();
    }
}

/// Prints guidance for a memory-access failure, calling out the common Linux
/// `ptrace_scope` cause specifically when the OS reports permission denied.
fn report_access_error(context: &str, e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        println!("{context} ({e}).");
        #[cfg(unix)]
        println!(
            "On Linux this is usually the kernel's Yama ptrace_scope policy blocking \
             cross-process memory access. Fix it by doing one of:\n  \
             - sudo setcap cap_sys_ptrace+ep <path to this binary>\n  \
             - running this tool with sudo\n  \
             - sudo sysctl kernel.yama.ptrace_scope=0 (weakens system security until reboot)"
        );
    } else {
        println!("{context} ({e}).");
    }
}

fn main() -> ExitCode {
    let Some(pid) = process::find_pid(&["Warframe.x64.exe", "Warframe.x64.ex"]) else {
        println!("Process not found.");
        pause();
        return ExitCode::from(1);
    };

    let mod_ = match ProcessHandle::open(pid) {
        Ok(mod_) => mod_,
        Err(e) => {
            report_access_error("Failed to open process", &e);
            pause();
            return ExitCode::from(2);
        }
    };

    if let Err(e) = mod_.probe_read() {
        report_access_error("Opened the process, but reading its memory was denied", &e);
        pause();
        return ExitCode::from(4);
    }

    let Some(authz) = gruzzleAuthz(&mod_) else {
        pause();
        return ExitCode::from(3);
    };

    println!("{authz}");
    print!("Downloading inventory... ");
    let _ = std::io::stdout().flush();

    // Note: Could also use api.warframe.com
    let url = format!("https://mobile.warframe.com/api/inventory.php{authz}");
    let Ok(response) = reqwest::blocking::get(&url) else {
        println!("Request failed.");
        pause();
        return ExitCode::from(5);
    };
    let Ok(inventory) = response.text() else {
        println!("Request failed.");
        pause();
        return ExitCode::from(5);
    };

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&inventory) else {
        println!("Received an invalid response.");
        pause();
        return ExitCode::from(6);
    };

    let _ = std::fs::write(
        "inventory.json",
        serde_json::to_string_pretty(&parsed).unwrap(),
    );

    let ciphertext =
        Aes128CbcEnc::new(&KEY.into(), &IV.into()).encrypt_padded_vec::<Pkcs7>(inventory.as_bytes());
    let _ = std::fs::write("lastData.dat", ciphertext);

    println!("Saved to inventory.json & lastData.dat in working directory.");
    pause();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_account_id_accepts_24_hex_chars() {
        assert!(is_plausible_account_id(b"5a4766b43ade7f7aa7dfabc5"));
    }

    #[test]
    fn plausible_account_id_rejects_template_string_leftovers() {
        // What the static "&squadCount={...}&nonce=" format string in the
        // game binary looks like when misread as an account ID.
        assert!(!is_plausible_account_id(b"&squadCount={\"nonce\":\"%s"));
    }

    #[test]
    fn plausible_account_id_rejects_wrong_length() {
        assert!(!is_plausible_account_id(b"short"));
    }

    // `parse_authz` only skips `PATTERN`'s length, so these inputs use an
    // upper-case look-alike prefix. That keeps any complete authz string out
    // of the test binary's memory, which the self-scan test below would
    // otherwise find before its own fixture.
    #[test]
    fn parse_authz_extracts_id_and_nonce() {
        assert_eq!(
            parse_authz(b"?ACCOUNTID=fedcba9876543210fedcba98&nonce=42&x"),
            Some(("fedcba9876543210fedcba98", "42"))
        );
    }

    #[test]
    fn parse_authz_rejects_missing_nonce_and_truncation() {
        assert_eq!(
            parse_authz(b"?ACCOUNTID=fedcba9876543210fedcba98&nonce=&"),
            None
        );
        assert_eq!(
            parse_authz(b"?ACCOUNTID=fedcba9876543210fedcba98&non"),
            None
        );
        assert_eq!(parse_authz(b"?ACCOUNTID=fedcba9876"), None);
    }

    // Regression test: a single structurally-valid occurrence must be
    // enough to succeed, since the live buffer isn't guaranteed to be
    // duplicated three times in memory the way the original heuristic
    // assumed.
    #[test]
    fn gruzzle_authz_succeeds_on_a_single_valid_occurrence() {
        #[used]
        static FAKE_BUFFER: &[u8] =
            b"noise before ?accountId=0123456789abcdef01234567&nonce=123456789 trailing noise";

        let pid = std::process::id();
        let handle = ProcessHandle::open(pid).expect("should open own process");
        let authz = gruzzleAuthz(&handle).expect("should find the embedded candidate");
        assert_eq!(authz, "?accountId=0123456789abcdef01234567&nonce=123456789");
    }
}
