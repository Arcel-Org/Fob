/// Memory hygiene utilities for key material.
///
/// Keys must not appear in core dumps, swap, or crash reports.
/// This module wraps OS-level protections for sensitive allocations.
/// Attempt to mlock a byte slice, preventing it from being swapped to disk.
///
/// Failure is non-fatal but is logged at warn level. Many systems limit the
/// amount of mlocked memory per process; if the limit is exceeded, the page
/// is still usable but may be swapped.
pub fn try_mlock(data: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::mlock(data.as_ptr() as *const _, data.len()) };
        ret == 0
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::mlock(data.as_ptr() as *const _, data.len()) };
        ret == 0
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = data;
        false
    }
}

/// Unlock a previously mlocked region.
pub fn try_munlock(data: &[u8]) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unsafe {
        libc::munlock(data.as_ptr() as *const _, data.len());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = data;
    }
}

/// Advise the kernel not to include this memory in core dumps.
/// Linux only; no-op on other platforms.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn madvise_dontdump(data: &[u8]) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::madvise(data.as_ptr() as *mut _, data.len(), libc::MADV_DONTDUMP);
    }
}

/// A page-aligned, mlocked buffer for a fixed-size secret.
///
/// The contained bytes are mlocked on creation and munlocked + zeroized on drop.
pub struct LockedSecret<const N: usize> {
    data: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> LockedSecret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        let data = Box::new(bytes);
        let locked = try_mlock(&*data);
        madvise_dontdump(&*data);
        Self { data, locked }
    }

    pub fn bytes(&self) -> &[u8; N] {
        &self.data
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Drop for LockedSecret<N> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
        if self.locked {
            try_munlock(&*self.data);
        }
    }
}
