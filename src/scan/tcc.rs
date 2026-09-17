//! Full Disk Access detection. TCC denies `opendir` on a handful of user
//! folders (Safari, Mail, the TCC database itself) with EPERM unless the
//! process — the app bundle, for the GUI — has been granted Full Disk
//! Access in System Settings › Privacy & Security.

use std::io::ErrorKind;

/// Whether this process can read TCC-protected user data. Probes, in order,
/// `~/Library/Safari`, `~/Library/Application Support/com.apple.TCC`,
/// `~/Library/Mail`; the first that exists decides (readable → true,
/// EPERM/EACCES → false). If none exist there is nothing to protect → true.
pub fn full_disk_access(paths: &crate::config::Paths) -> bool {
    const PROBES: &[&str] = &[
        "Library/Safari",
        "Library/Application Support/com.apple.TCC",
        "Library/Mail",
    ];
    for probe in PROBES {
        let dir = paths.home.join(probe);
        match std::fs::read_dir(&dir) {
            Ok(_) => return true,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return false,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            // Some other error (e.g. not-a-directory) — don't nag over odd
            // errors, just try the next probe / fall through to "true".
            Err(_) => return true,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Restores a set of paths' permissions to `0o755` on drop, including on
    /// panic/unwind, so a failed assertion never leaves a chmod-000 directory
    /// behind for the rest of the test suite (or a later `tempdir` cleanup)
    /// to trip over.
    struct PermRestoreGuard(Vec<PathBuf>);
    impl Drop for PermRestoreGuard {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            }
        }
    }

    #[test]
    fn no_probe_dirs_means_nothing_to_protect() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        assert!(full_disk_access(&paths));
    }

    #[test]
    fn readable_safari_dir_means_access_granted() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join("Library/Safari")).unwrap();
        let paths = Paths::from_home(home.path());
        assert!(full_disk_access(&paths));
    }

    #[test]
    fn unreadable_safari_dir_means_access_denied() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything; the permission bits are moot.
        }
        let home = tempfile::tempdir().unwrap();
        let safari = home.path().join("Library/Safari");
        fs::create_dir_all(&safari).unwrap();
        fs::set_permissions(&safari, fs::Permissions::from_mode(0o000)).unwrap();
        let _guard = PermRestoreGuard(vec![safari.clone()]);

        let paths = Paths::from_home(home.path());
        assert!(!full_disk_access(&paths));
    }
}
