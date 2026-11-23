use std::collections::HashMap;
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
// that false positive without needing several identical occurrences, which
// isn't guaranteed to exist in memory at scan time.
const REQUIRED_CONFIRMATIONS: u32 = 1;

fn is_plausible_account_id(bytes: &[u8]) -> bool {
    bytes.len() == ACCOUNT_ID_LEN && bytes.iter().all(u8::is_ascii_hexdigit)
}

#[allow(non_snake_case)]
fn gruzzleAuthz(mod_: &mut ProcessHandle) -> Option<String> {
    print!("Gruzzling");
    let _ = std::io::stdout().flush();

    let mut candidates: HashMap<String, u32> = HashMap::new();
    let regions = mod_.regions();
    let mut regions_read = 0u32;
    let mut matches_found = 0u32;
    for region in &regions {
        let Some(data) = mod_.read_vec(region.base, region.size) else {
            continue;
        };
        regions_read += 1;

        // Unlike upstream's `externalScan` (first hit per region only), we
        // check every occurrence in the region: a false positive earlier in
        // the same region (e.g. a URL-template string) could otherwise hide
        // a genuine, later one.
        for match_offset in memchr::memmem::find_iter(&data, PATTERN) {
            matches_found += 1;

            let account_id_addr = region.base + match_offset + PATTERN.len();
            let Some(account_id_bytes) = mod_.read_vec(account_id_addr, ACCOUNT_ID_LEN) else {
                continue;
            };
            if !is_plausible_account_id(&account_id_bytes) {
                continue;
            }
            let account_id = String::from_utf8_lossy(&account_id_bytes);

            let mut authz = format!("?accountId={account_id}&nonce=");
            let mut addr = account_id_addr + ACCOUNT_ID_LEN + NONCE_PREFIX.len();
            let mut nonce_digits = 0u32;
            while let Some(c) = mod_.read_u8(addr) {
                addr += 1;
                if c.is_ascii_digit() {
                    authz.push(c as char);
                    nonce_digits += 1;
                } else {
                    break;
                }
            }
            if nonce_digits == 0 {
                continue;
            }

            eprintln!(
                "\n[debug] match #{matches_found} @ {account_id_addr:#x} (region {:#x}+{:#x}): {authz}",
                region.base, region.size
            );

            let count = candidates.entry(authz.clone()).or_insert(0);
            *count += 1;
            if *count == REQUIRED_CONFIRMATIONS {
                println!(" The crumbs have been gruzzled.");
                return Some(authz);
            }
        }
    }
    eprintln!(
        "[debug] {} regions total, {regions_read} read successfully, {matches_found} pattern matches",
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

    let mut mod_ = match ProcessHandle::open(pid) {
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

    let Some(authz) = gruzzleAuthz(&mut mod_) else {
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
        let mut handle = ProcessHandle::open(pid).expect("should open own process");
        let authz = gruzzleAuthz(&mut handle).expect("should find the embedded candidate");
        assert_eq!(authz, "?accountId=0123456789abcdef01234567&nonce=123456789");
    }
}
