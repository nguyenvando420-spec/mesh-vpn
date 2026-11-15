//! iOS Jetsam memory headroom query (`os_proc_available_memory`, `US-092`, `BLK-MOB-G2-06`).

#[cfg(target_os = "ios")]
unsafe extern "C" {
    fn os_proc_available_memory() -> usize;
}

/// Returns remaining process memory budget reported by iOS Jetsam (`os_proc_available_memory()`),
/// or `usize::MAX` on non-iOS platforms.
#[must_use]
pub fn available_memory_bytes() -> usize {
    #[cfg(target_os = "ios")]
    {
        // SAFETY: `os_proc_available_memory` is a standard lock-free `libSystem` symbol on iOS 13+
        // that accepts no pointers or arguments.
        unsafe { os_proc_available_memory() }
    }
    #[cfg(not(target_os = "ios"))]
    {
        usize::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::available_memory_bytes;

    #[test]
    fn test_memory_ios_available_memory_returns_nonzero() {
        // Arrange & Act
        let avail = available_memory_bytes();

        // Assert
        assert!(avail > 0);
    }
}
