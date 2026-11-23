//! Minimal cross-platform access to another process's memory: finding a
//! process by name, enumerating its readable memory regions, and reading
//! bytes from it. This covers the subset of functionality the original C++
//! tool used from the `soup` library's `Process`/`ProcessHandle` types.

use std::ffi::OsStr;

/// A contiguous, readable region of a target process's address space.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub base: usize,
    pub size: usize,
}

/// Looks up a running process by name, trying each candidate in order and
/// returning the first match's PID.
///
/// Linux truncates process names to 15 characters, which is why callers
/// typically pass both the full Windows name and a shortened fallback.
pub fn find_pid(candidates: &[&str]) -> Option<u32> {
    let mut system = sysinfo::System::new_all().ok()?;
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for name in candidates {
        if let Some(process) = system.processes_by_exact_name(OsStr::new(name)).next() {
            return Some(process.pid().as_u32());
        }
    }
    None
}

#[cfg(windows)]
mod imp {
    use super::Region;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    pub struct ProcessHandle(*mut c_void);

    // The handle is only ever passed by value into WinAPI calls, so moving
    // it across threads is sound.
    unsafe impl Send for ProcessHandle {}

    impl ProcessHandle {
        pub fn open(pid: u32) -> std::io::Result<Self> {
            let handle =
                unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
            if handle.is_null() {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }

        pub fn regions(&mut self) -> Vec<Region> {
            let mut regions = Vec::new();
            let mut address: usize = 0;
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                let written = unsafe {
                    VirtualQueryEx(
                        self.0,
                        address as *const c_void,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if written == 0 || mbi.RegionSize == 0 {
                    break;
                }
                // Mirrors upstream soup's `getAllocations`: every committed
                // region is included, regardless of protection. Pages that
                // truly can't be read (e.g. PAGE_NOACCESS) simply fail the
                // later `ReadProcessMemory` call and get skipped there.
                if mbi.State == MEM_COMMIT {
                    regions.push(Region {
                        base: mbi.BaseAddress as usize,
                        size: mbi.RegionSize,
                    });
                }
                match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
                    Some(next) if next > address => address = next,
                    _ => break,
                }
            }
            regions
        }

        pub fn read(&mut self, address: usize, buf: &mut [u8]) -> std::io::Result<()> {
            let mut bytes_read = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    self.0,
                    address as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    &mut bytes_read,
                ) != 0
                    && bytes_read == buf.len()
            };
            if ok {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Region;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};

    pub struct ProcessHandle {
        pid: u32,
        mem: File,
    }

    impl ProcessHandle {
        pub fn open(pid: u32) -> std::io::Result<Self> {
            let mem = OpenOptions::new().read(true).open(format!("/proc/{pid}/mem"))?;
            Ok(Self { pid, mem })
        }

        pub fn regions(&mut self) -> Vec<Region> {
            let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) else {
                return Vec::new();
            };
            maps.lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    let range = fields.next()?;
                    let perms = fields.next()?;
                    if !perms.starts_with('r') {
                        return None;
                    }
                    let (start, end) = range.split_once('-')?;
                    let start = usize::from_str_radix(start, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    Some(Region {
                        base: start,
                        size: end.saturating_sub(start),
                    })
                })
                .collect()
        }

        pub fn read(&mut self, address: usize, buf: &mut [u8]) -> std::io::Result<()> {
            self.mem.seek(SeekFrom::Start(address as u64))?;
            self.mem.read_exact(buf)
        }
    }
}

pub use imp::ProcessHandle;

impl ProcessHandle {
    /// Reads `len` bytes at `address`, returning `None` if the read fails
    /// (e.g. the region became inaccessible, which can happen when racing a
    /// live, running process).
    pub fn read_vec(&mut self, address: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read(address, &mut buf).ok().map(|()| buf)
    }

    pub fn read_u8(&mut self, address: usize) -> Option<u8> {
        let mut buf = [0u8; 1];
        self.read(address, &mut buf).ok().map(|()| buf[0])
    }

    /// Tries a handful of reads across different regions and returns the
    /// error if *all* of them failed with `PermissionDenied`. On Linux this
    /// reliably surfaces when the kernel's Yama `ptrace_scope` policy is
    /// blocking cross-process memory access (the common case when the
    /// target isn't a child process and the caller lacks `CAP_SYS_PTRACE`),
    /// without flagging a single unrelated unreadable page as the cause.
    pub fn probe_read(&mut self) -> Result<(), std::io::Error> {
        let mut saw_permission_denied = None;
        for region in self.regions().into_iter().take(50) {
            let mut buf = [0u8; 1];
            match self.read(region.base, &mut buf) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    saw_permission_denied = Some(e);
                }
                Err(_) => {}
            }
        }
        match saw_permission_denied {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the real OS-specific implementation end-to-end by having the
    // test process open and read its own memory.
    #[test]
    fn can_read_own_process_memory() {
        #[used]
        static MARKER: [u8; 16] = *b"PROCESS_RW_TEST\0";

        let pid = std::process::id();
        let mut handle = ProcessHandle::open(pid).expect("should open own process");

        let regions = handle.regions();
        assert!(!regions.is_empty(), "expected at least one readable region");

        let marker_addr = MARKER.as_ptr() as usize;
        let data = handle
            .read_vec(marker_addr, MARKER.len())
            .expect("should read own static data");
        assert_eq!(data, MARKER);
    }
}
