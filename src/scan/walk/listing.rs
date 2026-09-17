//! Directory listing: one fast macOS-native path, one portable fallback.
//!
//! The fast path is `getattrlistbulk(2)`, which returns name, type, device,
//! inode, mtime, link count and allocated size for *hundreds* of entries per
//! syscall. The `read_dir` + `lstat` shape costs one path lookup and one
//! syscall per file; on a home directory with a million files that difference
//! is most of the runtime.
//!
//! Not every volume implements the bulk call (network mounts, FAT, some FUSE
//! filesystems), so [`list`] degrades to [`list_stat`] — but only on the
//! errors that mean "unsupported". Anything else (`EPERM` from TCC, `ELOOP`
//! for a symlinked directory, `ENOENT`) propagates, because retrying those
//! with `read_dir` would either double the cost of every protected directory
//! or silently follow a symlink the bulk path refused.
//!
//! Record layout (verified empirically on macOS 26/27, arm64; see the note
//! above `decode_batch`): `[u32 len][attribute_set_t: 5×u32]` then the
//! attributes in ascending bit order within each group, common → dir → file.
//! `ATTR_CMN_ERROR` is the one exception: the kernel packs it *first*, right
//! after the returned-attrs header. Every multi-byte field is read with
//! `read_unaligned` because the header is 20 or 24 bytes depending on whether
//! the error word is present, which shifts the 8-byte fields off alignment.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// What a directory entry is, as far as accounting is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Dir,
    File,
    /// Symlink, socket, device… counted for its own size, never followed.
    Other,
}

/// One directory entry with everything needed to account for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: OsString,
    pub kind: Kind,
    pub dev: u64,
    pub ino: u64,
    pub nlink: u32,
    /// `st_blocks * 512`: the bytes the volume actually loses.
    pub alloc: u64,
    /// `st_size`: the logical length, which sparse files inflate.
    pub apparent: u64,
    /// Modification time, seconds since the epoch.
    pub mtime_secs: i64,
    /// True for a directory that is a mount point (another volume is mounted
    /// on it). Only ever set by the bulk path; the fallback reports `false`.
    pub mount_point: bool,
}

/// The listing of one directory.
#[derive(Debug, Default)]
pub struct Listing {
    pub entries: Vec<Entry>,
    /// Entries the kernel could not stat (reported via `ATTR_CMN_ERROR`).
    pub errors: u64,
    /// `(st_dev, st_ino)` of the listed directory itself, from `fstat` on the
    /// opened descriptor. This is the authoritative identity for a mount
    /// point: the *parent's* listing reports the covered vnode's device.
    pub dev: u64,
    pub ino: u64,
}

static FORCE_STAT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Force the portable path for every listing (benchmarks only).
pub fn force_stat(on: bool) {
    FORCE_STAT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// List `path`, preferring the bulk syscall and degrading to `read_dir` only
/// when the volume does not support it.
pub fn list(path: &Path) -> io::Result<Listing> {
    if FORCE_STAT.load(std::sync::atomic::Ordering::Relaxed) {
        return list_stat(path);
    }
    #[cfg(target_os = "macos")]
    {
        match bulk::list_bulk(path) {
            Err(e) if is_unsupported(&e) => list_stat(path),
            r => r,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        list_stat(path)
    }
}

#[cfg(target_os = "macos")]
fn is_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
    )
}

/// Portable fallback for volumes without `getattrlistbulk`.
///
/// `DirEntry::metadata` is an `lstat` on Unix, so symlinks stay unfollowed
/// here too. A symlinked directory is refused outright to match the bulk
/// path's `O_NOFOLLOW`.
pub fn list_stat(path: &Path) -> io::Result<Listing> {
    let own = fs::symlink_metadata(path)?;
    if own.file_type().is_symlink() {
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }
    let mut out = Listing {
        dev: own.dev(),
        ino: own.ino(),
        ..Listing::default()
    };
    for entry in fs::read_dir(path)? {
        let Ok(entry) = entry else {
            out.errors += 1;
            continue;
        };
        let Ok(md) = entry.metadata() else {
            out.errors += 1;
            continue;
        };
        let ft = md.file_type();
        out.entries.push(Entry {
            name: entry.file_name(),
            kind: if ft.is_dir() {
                Kind::Dir
            } else if ft.is_file() {
                Kind::File
            } else {
                Kind::Other
            },
            dev: md.dev(),
            ino: md.ino(),
            nlink: md.nlink() as u32,
            alloc: md.blocks() * 512,
            apparent: md.len(),
            mtime_secs: md.mtime(),
            mount_point: false,
        });
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
mod bulk {
    use super::{Entry, Kind, Listing};
    use std::cell::RefCell;
    use std::ffi::{CString, OsString};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    /// `ATTR_CMN_ERROR` is missing from the `libc` crate's constant set.
    const ATTR_CMN_ERROR: libc::attrgroup_t = 0x2000_0000;
    /// `vnode` types from `sys/vnode.h`; only these two are interesting.
    const VREG: u32 = 1;
    const VDIR: u32 = 2;
    /// 256 KiB, `u64`-aligned so the kernel's 8-byte fields land aligned
    /// whenever the header allows it.
    const BUF_WORDS: usize = 32 * 1024;

    thread_local! {
        // Rayon workers are long-lived; one buffer per thread avoids a
        // 256 KiB allocation per directory.
        static BUF: RefCell<Vec<u64>> = RefCell::new(vec![0; BUF_WORDS]);
    }

    /// The fast path: one syscall per batch of entries, no per-file `lstat`.
    pub fn list_bulk(path: &Path) -> io::Result<Listing> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // O_NOFOLLOW: a symlinked directory is never entered (ELOOP).
        let raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly opened descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = Listing {
            dev: st.st_dev as u64,
            ino: st.st_ino,
            ..Listing::default()
        };

        let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
        al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
        al.commonattr = libc::ATTR_CMN_RETURNED_ATTRS
            | ATTR_CMN_ERROR
            | libc::ATTR_CMN_NAME
            | libc::ATTR_CMN_DEVID
            | libc::ATTR_CMN_OBJTYPE
            | libc::ATTR_CMN_MODTIME
            | libc::ATTR_CMN_FILEID;
        al.dirattr = libc::ATTR_DIR_MOUNTSTATUS;
        al.fileattr =
            libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_TOTALSIZE | libc::ATTR_FILE_ALLOCSIZE;

        BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            loop {
                let n = unsafe {
                    libc::getattrlistbulk(
                        fd.as_raw_fd(),
                        std::ptr::addr_of_mut!(al).cast::<libc::c_void>(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len() * 8, // bytes, not words
                        u64::from(libc::FSOPT_NOFOLLOW),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                if n == 0 {
                    break;
                }
                // SAFETY: the kernel wrote `n` well-formed variable-length
                // records into `buf`; `decode_batch` walks them using the
                // lengths and returned-attribute bitmaps it reports.
                unsafe { decode_batch(buf.as_ptr().cast::<u8>(), n as usize, &mut out) };
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Read one `T` at `p` and advance `p` past it.
    ///
    /// # Safety
    /// `p` must point at least `size_of::<T>()` readable bytes.
    unsafe fn take<T: Copy>(p: &mut *const u8) -> T {
        let v = unsafe { p.cast::<T>().read_unaligned() };
        *p = unsafe { p.add(std::mem::size_of::<T>()) };
        v
    }

    /// Decode `count` `getattrlistbulk` records starting at `base`.
    ///
    /// Each record is `[u32 length][attribute_set_t][packed attributes…]`.
    /// Every field is read only if the record's `ATTR_CMN_RETURNED_ATTRS`
    /// header says it is present, which is what makes the cursor arithmetic
    /// safe: an attribute the kernel declined is skipped, never misread.
    ///
    /// Empirical layout notes (macOS 26.x/27.0, arm64, APFS):
    /// - with `ATTR_CMN_ERROR` requested the header is 4 + 20 + 4 = 28 bytes
    ///   when the error word is returned, 24 when it is not — hence
    ///   `read_unaligned` on every 8-byte field;
    /// - APFS does *not* return `ATTR_FILE_*` for directories (the returned
    ///   file bitmap is 0), so a directory's `nlink`/`alloc`/`apparent` here
    ///   are the blank defaults, unlike `lstat`'s. Callers gate accounting
    ///   on `kind` regardless;
    /// - `open(O_DIRECTORY | O_NOFOLLOW)` on a symlink fails with `ENOTDIR`,
    ///   not `ELOOP`;
    /// - `ATTR_CMN_DEVID` for a mount point is the covered vnode's device;
    ///   only `ATTR_DIR_MOUNTSTATUS` (and `fstat` after `open`) reveal it.
    ///
    /// # Safety
    /// `base` must point at `count` consecutive kernel-written records.
    unsafe fn decode_batch(base: *const u8, count: usize, out: &mut Listing) {
        let mut p = base;
        for _ in 0..count {
            let record = p;
            let len = unsafe { take::<u32>(&mut p) } as usize;
            // attribute_set_t: five bitmaps — common[0], vol[1], dir[2],
            // file[3], fork[4].
            let returned_common = unsafe { take::<u32>(&mut p) };
            let _returned_vol = unsafe { take::<u32>(&mut p) };
            let returned_dir = unsafe { take::<u32>(&mut p) };
            let returned_file = unsafe { take::<u32>(&mut p) };
            let _returned_fork = unsafe { take::<u32>(&mut p) };

            let mut e = Entry {
                name: OsString::new(),
                kind: Kind::Other,
                dev: 0,
                ino: 0,
                nlink: 1,
                alloc: 0,
                apparent: 0,
                mtime_secs: 0,
                mount_point: false,
            };
            let mut err = 0u32;
            if returned_common & ATTR_CMN_ERROR != 0 {
                err = unsafe { take::<u32>(&mut p) };
            }
            if returned_common & libc::ATTR_CMN_NAME != 0 {
                // attrreference_t: an offset relative to itself, plus a
                // length that includes the trailing NUL.
                let field = p;
                let off = unsafe { take::<i32>(&mut p) } as isize;
                let name_len = unsafe { take::<u32>(&mut p) } as usize;
                let bytes = unsafe {
                    std::slice::from_raw_parts(field.offset(off), name_len.saturating_sub(1))
                };
                e.name = OsString::from_vec(bytes.to_vec());
            }
            if returned_common & libc::ATTR_CMN_DEVID != 0 {
                e.dev = u64::from(unsafe { take::<u32>(&mut p) });
            }
            if returned_common & libc::ATTR_CMN_OBJTYPE != 0 {
                e.kind = match unsafe { take::<u32>(&mut p) } {
                    VREG => Kind::File,
                    VDIR => Kind::Dir,
                    _ => Kind::Other,
                };
            }
            if returned_common & libc::ATTR_CMN_MODTIME != 0 {
                // struct timespec { i64 tv_sec; i64 tv_nsec } on LP64.
                e.mtime_secs = unsafe { take::<i64>(&mut p) };
                let _nsec = unsafe { take::<i64>(&mut p) };
            }
            if returned_common & libc::ATTR_CMN_FILEID != 0 {
                e.ino = unsafe { take::<u64>(&mut p) };
            }
            if returned_dir & libc::ATTR_DIR_MOUNTSTATUS != 0 {
                let status = unsafe { take::<u32>(&mut p) };
                e.mount_point = status & libc::DIR_MNTSTATUS_MNTPOINT != 0;
            }
            if returned_file & libc::ATTR_FILE_LINKCOUNT != 0 {
                e.nlink = unsafe { take::<u32>(&mut p) };
            }
            if returned_file & libc::ATTR_FILE_TOTALSIZE != 0 {
                e.apparent = unsafe { take::<u64>(&mut p) };
            }
            if returned_file & libc::ATTR_FILE_ALLOCSIZE != 0 {
                e.alloc = unsafe { take::<u64>(&mut p) };
            }

            // An entry the kernel could not stat is counted, not guessed at.
            if err != 0 {
                out.errors += 1;
            } else if !e.name.is_empty() {
                out.entries.push(e);
            }
            p = unsafe { record.add(len.max(4)) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let mut f = File::create(p.join("eight-k.bin")).unwrap();
        f.write_all(&vec![0xA5u8; 8192]).unwrap();
        File::create(p.join("empty")).unwrap();
        fs::create_dir(p.join("sub")).unwrap();
        File::create(p.join("sub/inner")).unwrap();
        fs::hard_link(p.join("eight-k.bin"), p.join("eight-k.link")).unwrap();
        symlink(p.join("eight-k.bin"), p.join("file-link")).unwrap();
        symlink(p.join("sub"), p.join("dir-link")).unwrap();
        dir
    }

    /// Everything the walk accounts with. Directories carry no file
    /// attributes on the bulk path, so their size/link fields are excluded.
    fn key(e: &Entry) -> (OsString, Kind, u64, u32, u64, u64, i64) {
        let (nlink, alloc, apparent) = if e.kind == Kind::Dir {
            (0, 0, 0)
        } else {
            (e.nlink, e.alloc, e.apparent)
        };
        (
            e.name.clone(),
            e.kind,
            e.ino,
            nlink,
            alloc,
            apparent,
            e.mtime_secs,
        )
    }

    /// Both backends must agree about a directory they can both read: that
    /// equivalence is the only thing making the fallback safe.
    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_and_stat_agree() {
        let dir = fixture();
        let bulk = bulk::list_bulk(dir.path()).expect("bulk");
        let stat = list_stat(dir.path()).expect("stat");
        let mut b: Vec<_> = bulk.entries.iter().map(key).collect();
        let mut s: Vec<_> = stat.entries.iter().map(key).collect();
        b.sort();
        s.sort();
        assert_eq!(b, s);
        assert_eq!((bulk.dev, bulk.ino), (stat.dev, stat.ino));
        assert_eq!(bulk.errors, 0);
        // Symlinks are reported as themselves, never resolved.
        let link = bulk
            .entries
            .iter()
            .find(|e| e.name == "dir-link")
            .expect("dir symlink listed");
        assert_eq!(link.kind, Kind::Other);
        let hard = bulk
            .entries
            .iter()
            .find(|e| e.name == "eight-k.link")
            .unwrap();
        assert_eq!(hard.nlink, 2);
        assert_eq!(hard.apparent, 8192);
        assert!(hard.alloc >= 8192);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mount_point_flag_on_system_volumes() {
        // /System/Volumes/Data is a mount point on every macOS ≥ 10.15.
        let l = list(Path::new("/System/Volumes")).expect("list /System/Volumes");
        let data = l
            .entries
            .iter()
            .find(|e| e.name == "Data")
            .expect("Data volume listed");
        assert_eq!(data.kind, Kind::Dir);
        assert!(data.mount_point, "Data should be flagged as a mount point");
    }

    #[test]
    fn symlinked_dir_is_err_not_fallback() {
        let dir = fixture();
        let err = list(&dir.path().join("dir-link")).expect_err("must not follow");
        // O_DIRECTORY|O_NOFOLLOW yields ENOTDIR on macOS; the fallback path
        // reports ELOOP. Either way it is an error, never a listing.
        assert!(matches!(
            err.raw_os_error(),
            Some(libc::ENOTDIR) | Some(libc::ELOOP)
        ));
    }

    #[test]
    fn missing_directory_is_an_error() {
        assert!(list(Path::new("/nonexistent-macaudit-walk-test")).is_err());
    }

    #[test]
    fn permission_denied_is_err_not_fallback() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything
        }
        let dir = fixture();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let err = list(&locked).expect_err("unreadable dir");
        assert!(matches!(
            err.raw_os_error(),
            Some(libc::EACCES) | Some(libc::EPERM)
        ));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    }
}
