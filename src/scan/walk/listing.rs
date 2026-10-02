//! Directory listing: one fast macOS-native path, one portable fallback.
//!
//! The fast path is `getattrlistbulk(2)`, which returns name, type, device,
//! inode, mtime, link count and allocated size for *hundreds* of entries per
//! syscall. The `readdir` + `fstatat` shape costs one
//! syscall per file; on a home directory with a million files that difference
//! is most of the runtime.
//!
//! Not every volume implements the bulk call (network mounts, FAT, some FUSE
//! filesystems), so [`list`] degrades to [`list_stat`] — but only on the
//! errors that mean "unsupported". Anything else (`EPERM` from TCC, `ELOOP`
//! for a symlinked directory, `ENOENT`) propagates, because retrying those
//! with `readdir` would either double the cost of every protected directory
//! or silently follow a symlink the bulk path refused.
//!
//! Record layout (verified empirically on macOS 26/27, arm64; see the note
//! above `decode_batch`): `[u32 len][attribute_set_t: 5×u32]` then the
//! attributes in ascending bit order within each group, common → dir → file.
//! `ATTR_CMN_ERROR` is the one exception: the kernel packs it *first*, right
//! after the returned-attrs header. Every multi-byte field is read with
//! `read_unaligned` because the header is 20 or 24 bytes depending on whether
//! the error word is present, which shifts the 8-byte fields off alignment.

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::sync::Arc;

use crate::inventory::{MemoryBudget, Reservation};

const SF_DATALESS: u32 = 0x4000_0000;
const MAX_ENTRY_GROWTH: usize = 1024;

fn resource_error() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOMEM)
}

#[cfg(target_os = "macos")]
mod materialization {
    use std::io;
    use std::marker::PhantomData;
    use std::rc::Rc;

    const POLICY_TYPE: libc::c_int = 3;
    const THREAD_SCOPE: libc::c_int = 1;
    const POLICY_OFF: libc::c_int = 1;

    extern "C" {
        fn getiopolicy_np(policy_type: libc::c_int, scope: libc::c_int) -> libc::c_int;
        fn setiopolicy_np(
            policy_type: libc::c_int,
            scope: libc::c_int,
            policy: libc::c_int,
        ) -> libc::c_int;
    }

    pub(crate) struct Guard {
        previous: libc::c_int,
        _thread: PhantomData<Rc<()>>,
    }

    impl Guard {
        pub(crate) fn enter() -> io::Result<Self> {
            let previous = unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) };
            if previous < 0 || unsafe { setiopolicy_np(POLICY_TYPE, THREAD_SCOPE, POLICY_OFF) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                previous,
                _thread: PhantomData,
            })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { setiopolicy_np(POLICY_TYPE, THREAD_SCOPE, self.previous) };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn thread_policy_is_disabled_and_restored_across_nested_guards() {
            let previous = unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) };
            assert!(previous >= 0);
            {
                let _outer = Guard::enter().unwrap();
                assert_eq!(
                    unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                    POLICY_OFF
                );
                {
                    let _inner = Guard::enter().unwrap();
                }
                assert_eq!(
                    unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                    POLICY_OFF
                );
            }
            assert_eq!(
                unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                previous
            );
        }

        #[test]
        fn thread_policy_is_restored_after_listing_error() {
            let previous = unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) };
            assert!(super::super::list_stat(std::path::Path::new(
                "/nonexistent-macaudit-policy-test"
            ))
            .is_err());
            assert_eq!(
                unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                previous
            );
            assert!(super::super::bulk::list_bulk(std::path::Path::new(
                "/nonexistent-macaudit-policy-test"
            ))
            .is_err());
            assert_eq!(
                unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                previous
            );
        }

        #[test]
        fn visitor_reads_remain_guarded_on_walker_threads() {
            use crate::scan::walk::{walk, DirAction, DirNode, Entry, Flags, Visitor, WalkOptions};
            use std::path::Path;
            use std::sync::atomic::{AtomicUsize, Ordering};

            struct PolicyVisitor {
                callbacks: AtomicUsize,
            }

            impl Visitor for PolicyVisitor {
                fn on_child_dir(
                    &self,
                    _parent: &Path,
                    _child: &Entry,
                    _siblings: &[Entry],
                    flags: Flags,
                ) -> DirAction {
                    assert_eq!(
                        unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                        POLICY_OFF
                    );
                    self.callbacks.fetch_add(1, Ordering::Relaxed);
                    DirAction::Descend(flags)
                }

                fn on_dir_done(&self, _dir: &Path, _node: &DirNode, _flags: Flags) {
                    assert_eq!(
                        unsafe { getiopolicy_np(POLICY_TYPE, THREAD_SCOPE) },
                        POLICY_OFF
                    );
                    self.callbacks.fetch_add(1, Ordering::Relaxed);
                }
            }

            let root = tempfile::tempdir().unwrap();
            for index in 0..8 {
                std::fs::create_dir_all(root.path().join(format!("branch-{index}/nested")))
                    .unwrap();
            }
            let visitor = PolicyVisitor {
                callbacks: AtomicUsize::new(0),
            };
            let result = walk(root.path(), WalkOptions::default(), &visitor, None, &|| {
                false
            });
            assert!(result.complete);
            assert_eq!(visitor.callbacks.load(Ordering::Relaxed), 33);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use materialization::Guard as MaterializationGuard;

#[cfg(not(target_os = "macos"))]
pub(crate) struct MaterializationGuard;

#[cfg(not(target_os = "macos"))]
impl MaterializationGuard {
    pub(crate) fn enter() -> io::Result<Self> {
        Ok(Self)
    }
}

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
    pub dataless: bool,
}

/// The listing of one directory.
#[derive(Debug)]
pub struct Listing {
    pub entries: Vec<Entry>,
    /// Entries the kernel could not stat (reported via `ATTR_CMN_ERROR`).
    pub errors: u64,
    /// `(st_dev, st_ino)` of the listed directory itself, from `fstat` on the
    /// opened descriptor. This is the authoritative identity for a mount
    /// point: the *parent's* listing reports the covered vnode's device.
    pub dev: u64,
    pub ino: u64,
    pub(crate) _memory: ListingMemory,
}

#[derive(Debug)]
pub(crate) struct ListingMemory {
    budget: Arc<MemoryBudget>,
    entries: Reservation,
    names: Reservation,
}

impl Default for Listing {
    fn default() -> Self {
        Self::with_budget(MemoryBudget::shared()).expect("zero-byte listing reservation")
    }
}

impl Listing {
    fn with_budget(budget: Arc<MemoryBudget>) -> io::Result<Self> {
        let entries = budget.reserve(0).map_err(|_| resource_error())?;
        let names = budget.reserve(0).map_err(|_| resource_error())?;
        Ok(Self {
            entries: Vec::new(),
            errors: 0,
            dev: 0,
            ino: 0,
            _memory: ListingMemory {
                budget,
                entries,
                names,
            },
        })
    }

    fn push_entry(&mut self, mut entry: Entry, name: &[u8]) -> io::Result<()> {
        if self.entries.len() == self.entries.capacity() {
            let additional = self.entries.capacity().clamp(16, MAX_ENTRY_GROWTH);
            let capacity = self
                .entries
                .capacity()
                .checked_add(additional)
                .ok_or_else(resource_error)?;
            let bytes = capacity
                .checked_mul(std::mem::size_of::<Entry>())
                .ok_or_else(resource_error)?;
            let reservation = self
                ._memory
                .budget
                .reserve(bytes)
                .map_err(|_| resource_error())?;
            self.entries
                .try_reserve_exact(additional)
                .map_err(|_| resource_error())?;
            self._memory.entries = reservation;
        }
        self._memory
            .names
            .grow(name.len())
            .map_err(|_| resource_error())?;
        let mut raw_name = Vec::new();
        raw_name
            .try_reserve_exact(name.len())
            .map_err(|_| resource_error())?;
        raw_name.extend_from_slice(name);
        entry.name = OsString::from_vec(raw_name);
        self.entries.push(entry);
        Ok(())
    }
}

static FORCE_STAT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Force the portable path for every listing (benchmarks only).
pub fn force_stat(on: bool) {
    FORCE_STAT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// List `path`, preferring the bulk syscall and degrading to `readdir` only
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
/// Names are borrowed from `readdir` until budgeted storage is available;
/// `fstatat(AT_SYMLINK_NOFOLLOW)` keeps symlinks unfollowed.
pub fn list_stat(path: &Path) -> io::Result<Listing> {
    list_stat_with_budget(path, MemoryBudget::shared())
}

fn list_stat_with_budget(path: &Path, budget: Arc<MemoryBudget>) -> io::Result<Listing> {
    let _policy = MaterializationGuard::enter()?;
    let (fd, own) = open_directory(path, &budget)?;
    let mut out = Listing::with_budget(budget)?;
    out.dev = own.st_dev as u64;
    out.ino = inode_number(own.st_ino);
    let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _ = fd.into_raw_fd();
    let stream = DirectoryStream(stream);
    loop {
        unsafe { *errno_ptr() = 0 };
        let raw_entry = unsafe { libc::readdir(stream.0) };
        if raw_entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOMEM) {
                return Err(error);
            }
            if error.raw_os_error() != Some(0) {
                out.errors += 1;
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*raw_entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                libc::dirfd(stream.0),
                name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOMEM) {
                return Err(error);
            }
            out.errors += 1;
            continue;
        }
        out.push_entry(entry_from_stat(&metadata), name.to_bytes())?;
    }
    Ok(out)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

unsafe fn errno_ptr() -> *mut libc::c_int {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        unsafe { libc::__error() }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::__errno_location() }
    }
    #[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
    {
        unsafe { libc::__errno() }
    }
}

fn stat_flags(metadata: &libc::stat) -> u32 {
    #[cfg(target_os = "macos")]
    {
        metadata.st_flags
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = metadata;
        0
    }
}

fn inode_number(raw_inode: impl Into<u64>) -> u64 {
    raw_inode.into()
}

fn is_dataless(flags: u32) -> bool {
    flags & SF_DATALESS != 0
}

fn refuse_dataless_directory(metadata: &libc::stat) -> io::Result<()> {
    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR && is_dataless(stat_flags(metadata)) {
        return Err(io::Error::from_raw_os_error(libc::EDEADLK));
    }
    Ok(())
}

fn entry_from_stat(metadata: &libc::stat) -> Entry {
    Entry {
        name: OsString::new(),
        kind: match metadata.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Dir,
            libc::S_IFREG => Kind::File,
            _ => Kind::Other,
        },
        dev: metadata.st_dev as u64,
        ino: inode_number(metadata.st_ino),
        nlink: metadata.st_nlink as u32,
        alloc: (metadata.st_blocks as u64).saturating_mul(512),
        apparent: metadata.st_size as u64,
        mtime_secs: metadata.st_mtime,
        mount_point: false,
        dataless: is_dataless(stat_flags(metadata)),
    }
}

fn open_directory(path: &Path, budget: &Arc<MemoryBudget>) -> io::Result<(OwnedFd, libc::stat)> {
    let raw_path = path.as_os_str().as_bytes();
    if raw_path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let path_bytes = raw_path.len().checked_add(1).ok_or_else(resource_error)?;
    let _path_memory = budget.reserve(path_bytes).map_err(|_| resource_error())?;
    let mut terminated_path = Vec::new();
    terminated_path
        .try_reserve_exact(path_bytes)
        .map_err(|_| resource_error())?;
    terminated_path.extend_from_slice(raw_path);
    terminated_path.push(0);
    let cpath = CString::from_vec_with_nul(terminated_path)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(cpath.as_ptr(), &mut metadata) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }
    refuse_dataless_directory(&metadata)?;
    let raw_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } < 0 {
        return Err(io::Error::last_os_error());
    }
    refuse_dataless_directory(&metadata)?;
    Ok((fd, metadata))
}

#[cfg(target_os = "macos")]
mod bulk {
    use super::{
        is_dataless, open_directory, resource_error, Entry, Kind, Listing, MaterializationGuard,
    };
    use crate::inventory::{MemoryBudget, Reservation};
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::Arc;

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
        static BUF: RefCell<Option<BulkBuffer>> = const { RefCell::new(None) };
    }

    struct BulkBuffer {
        words: Vec<u64>,
        _memory: Reservation,
    }

    impl BulkBuffer {
        fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
            let memory = budget
                .reserve(BUF_WORDS * std::mem::size_of::<u64>())
                .map_err(|_| resource_error())?;
            let mut words = Vec::new();
            words
                .try_reserve_exact(BUF_WORDS)
                .map_err(|_| resource_error())?;
            words.resize(BUF_WORDS, 0);
            Ok(Self {
                words,
                _memory: memory,
            })
        }
    }

    /// The fast path: one syscall per batch of entries, no per-file `lstat`.
    pub fn list_bulk(path: &Path) -> io::Result<Listing> {
        let _policy = MaterializationGuard::enter()?;
        let budget = MemoryBudget::shared();
        let (fd, metadata) = open_directory(path, &budget)?;
        let mut out = Listing::with_budget(budget.clone())?;
        out.dev = metadata.st_dev as u64;
        out.ino = super::inode_number(metadata.st_ino);

        let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
        al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
        al.commonattr = libc::ATTR_CMN_RETURNED_ATTRS
            | ATTR_CMN_ERROR
            | libc::ATTR_CMN_NAME
            | libc::ATTR_CMN_DEVID
            | libc::ATTR_CMN_OBJTYPE
            | libc::ATTR_CMN_MODTIME
            | libc::ATTR_CMN_FLAGS
            | libc::ATTR_CMN_FILEID;
        al.dirattr = libc::ATTR_DIR_MOUNTSTATUS;
        al.fileattr =
            libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_TOTALSIZE | libc::ATTR_FILE_ALLOCSIZE;

        BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            if buf.is_none() {
                *buf = Some(BulkBuffer::new(&budget)?);
            }
            let buf = &mut buf.as_mut().unwrap().words;
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
                let bytes =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
                decode_batch(bytes, n as usize, &mut out)?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    fn malformed_record() -> io::Error {
        io::Error::from_raw_os_error(libc::EIO)
    }

    fn take<T: Copy>(record: &[u8], cursor: &mut usize) -> io::Result<T> {
        let end = cursor
            .checked_add(std::mem::size_of::<T>())
            .ok_or_else(malformed_record)?;
        let bytes = record.get(*cursor..end).ok_or_else(malformed_record)?;
        let value = unsafe { bytes.as_ptr().cast::<T>().read_unaligned() };
        *cursor = end;
        Ok(value)
    }

    /// Decode `count` bounded `getattrlistbulk` records.
    ///
    /// Each record is `[u32 length][attribute_set_t][packed attributes…]`.
    /// Every field is read only if the record's `ATTR_CMN_RETURNED_ATTRS`
    /// header says it is present. Record and name bounds are checked before
    /// reading; name storage is reserved before copying the raw bytes.
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
    fn decode_batch(mut buffer: &[u8], count: usize, out: &mut Listing) -> io::Result<()> {
        for _ in 0..count {
            let mut cursor = 0;
            let length = take::<u32>(buffer, &mut cursor)? as usize;
            if length < 24 {
                return Err(malformed_record());
            }
            let record = buffer.get(..length).ok_or_else(malformed_record)?;
            buffer = &buffer[length..];
            let returned_common = take::<u32>(record, &mut cursor)?;
            let _returned_vol = take::<u32>(record, &mut cursor)?;
            let returned_dir = take::<u32>(record, &mut cursor)?;
            let returned_file = take::<u32>(record, &mut cursor)?;
            let _returned_fork = take::<u32>(record, &mut cursor)?;

            if returned_common & ATTR_CMN_ERROR != 0 {
                let error = take::<u32>(record, &mut cursor)?;
                if error == libc::ENOMEM as u32 {
                    return Err(resource_error());
                }
                if error != 0 {
                    out.errors += 1;
                    continue;
                }
            }

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
                dataless: false,
            };
            let mut name = &[][..];
            if returned_common & libc::ATTR_CMN_NAME != 0 {
                let field = cursor;
                let offset = take::<i32>(record, &mut cursor)? as isize;
                let name_length = take::<u32>(record, &mut cursor)? as usize;
                let start = field
                    .checked_add_signed(offset)
                    .ok_or_else(malformed_record)?;
                let end = start
                    .checked_add(name_length)
                    .ok_or_else(malformed_record)?;
                name = record
                    .get(start..end)
                    .and_then(|bytes| bytes.strip_suffix(&[0]))
                    .ok_or_else(malformed_record)?;
            }
            if returned_common & libc::ATTR_CMN_DEVID != 0 {
                e.dev = u64::from(take::<u32>(record, &mut cursor)?);
            }
            if returned_common & libc::ATTR_CMN_OBJTYPE != 0 {
                e.kind = match take::<u32>(record, &mut cursor)? {
                    VREG => Kind::File,
                    VDIR => Kind::Dir,
                    _ => Kind::Other,
                };
            }
            if returned_common & libc::ATTR_CMN_MODTIME != 0 {
                e.mtime_secs = take::<i64>(record, &mut cursor)?;
                let _nsec = take::<i64>(record, &mut cursor)?;
            }
            if returned_common & libc::ATTR_CMN_FLAGS != 0 {
                e.dataless = is_dataless(take::<u32>(record, &mut cursor)?);
            }
            if returned_common & libc::ATTR_CMN_FILEID != 0 {
                e.ino = take::<u64>(record, &mut cursor)?;
            }
            if returned_dir & libc::ATTR_DIR_MOUNTSTATUS != 0 {
                let status = take::<u32>(record, &mut cursor)?;
                e.mount_point = status & libc::DIR_MNTSTATUS_MNTPOINT != 0;
            }
            if returned_file & libc::ATTR_FILE_LINKCOUNT != 0 {
                e.nlink = take::<u32>(record, &mut cursor)?;
            }
            if returned_file & libc::ATTR_FILE_TOTALSIZE != 0 {
                e.apparent = take::<u64>(record, &mut cursor)?;
            }
            if returned_file & libc::ATTR_FILE_ALLOCSIZE != 0 {
                e.alloc = take::<u64>(record, &mut cursor)?;
            }

            let required_common = libc::ATTR_CMN_NAME
                | libc::ATTR_CMN_DEVID
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_MODTIME
                | libc::ATTR_CMN_FLAGS
                | libc::ATTR_CMN_FILEID;
            let required_file =
                libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_TOTALSIZE | libc::ATTR_FILE_ALLOCSIZE;
            if name.is_empty()
                || returned_common & required_common != required_common
                || (e.kind != Kind::Dir && returned_file & required_file != required_file)
            {
                out.errors += 1;
            } else {
                out.push_entry(e, name)?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::super::{entry_from_stat, SF_DATALESS};
        use super::*;
        use std::os::unix::ffi::OsStringExt;

        fn record(flags: u32, kind: u32, name: &[u8]) -> Vec<u8> {
            let common = libc::ATTR_CMN_RETURNED_ATTRS
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_NAME
                | libc::ATTR_CMN_DEVID
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_MODTIME
                | libc::ATTR_CMN_FLAGS
                | libc::ATTR_CMN_FILEID;
            let directory = if kind == VDIR {
                libc::ATTR_DIR_MOUNTSTATUS
            } else {
                0
            };
            let file = if kind == VDIR {
                0
            } else {
                libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_TOTALSIZE | libc::ATTR_FILE_ALLOCSIZE
            };
            let mut record = Vec::new();
            for value in [0, common, 0, directory, file, 0, 0] {
                record.extend_from_slice(&value.to_ne_bytes());
            }
            let reference = record.len();
            record.extend_from_slice(&0i32.to_ne_bytes());
            record.extend_from_slice(&((name.len() + 1) as u32).to_ne_bytes());
            record.extend_from_slice(&23u32.to_ne_bytes());
            record.extend_from_slice(&kind.to_ne_bytes());
            record.extend_from_slice(&1234i64.to_ne_bytes());
            record.extend_from_slice(&0i64.to_ne_bytes());
            record.extend_from_slice(&flags.to_ne_bytes());
            record.extend_from_slice(&0x1234_5678_9abc_def0u64.to_ne_bytes());
            if kind == VDIR {
                record.extend_from_slice(&0u32.to_ne_bytes());
            } else {
                record.extend_from_slice(&2u32.to_ne_bytes());
                record.extend_from_slice(&4096u64.to_ne_bytes());
                record.extend_from_slice(&8192u64.to_ne_bytes());
            }
            let offset = (record.len() - reference) as i32;
            record[reference..reference + 4].copy_from_slice(&offset.to_ne_bytes());
            record.extend_from_slice(name);
            record.push(0);
            let length = record.len() as u32;
            record[..4].copy_from_slice(&length.to_ne_bytes());
            record
        }

        #[test]
        fn bulk_flags_precede_file_id_and_agree_with_stat() {
            for flags in [0, 0x40, SF_DATALESS, SF_DATALESS | 0x40] {
                let name = b"raw-\xff";
                let mut listing = Listing::default();
                decode_batch(&record(flags, VREG, name), 1, &mut listing).unwrap();
                let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
                metadata.st_mode = libc::S_IFREG;
                metadata.st_flags = flags;
                metadata.st_dev = 23;
                metadata.st_ino = 0x1234_5678_9abc_def0;
                metadata.st_nlink = 2;
                metadata.st_size = 4096;
                metadata.st_blocks = 16;
                metadata.st_mtime = 1234;
                let mut expected = entry_from_stat(&metadata);
                expected.name = OsString::from_vec(name.to_vec());
                assert_eq!(listing.entries, vec![expected]);
                assert_eq!(listing.errors, 0);
            }
        }

        #[test]
        fn bulk_decodes_dataless_directory_flag() {
            let mut listing = Listing::default();
            decode_batch(&record(SF_DATALESS, VDIR, b"placeholder"), 1, &mut listing).unwrap();
            assert_eq!(listing.entries.len(), 1);
            assert_eq!(listing.entries[0].kind, Kind::Dir);
            assert!(listing.entries[0].dataless);
            assert_eq!(listing.entries[0].ino, 0x1234_5678_9abc_def0);
        }

        #[test]
        fn bulk_errors_and_missing_attributes_are_not_exact_zero() {
            let mut bytes = Vec::new();
            for value in [
                28,
                libc::ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR,
                0,
                0,
                0,
                0,
                libc::EDEADLK as u32,
            ] {
                bytes.extend_from_slice(&value.to_ne_bytes());
            }
            for value in [24, libc::ATTR_CMN_RETURNED_ATTRS, 0, 0, 0, 0] {
                bytes.extend_from_slice(&value.to_ne_bytes());
            }
            bytes.extend_from_slice(&record(0, VREG, b"complete"));
            let mut listing = Listing::default();
            decode_batch(&bytes, 3, &mut listing).unwrap();
            assert_eq!(listing.errors, 2);
            assert_eq!(listing.entries.len(), 1);
            assert_eq!(listing.entries[0].name, "complete");
        }

        #[test]
        fn bulk_decoder_rejects_unbounded_name_before_allocating() {
            let mut bytes = record(0, VREG, b"name");
            bytes[32..36].copy_from_slice(&u32::MAX.to_ne_bytes());
            let budget = MemoryBudget::new(4096);
            let mut listing = Listing::with_budget(budget.clone()).unwrap();
            let error = decode_batch(&bytes, 1, &mut listing).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
            assert_eq!(listing.entries.capacity(), 0);
            assert_eq!(budget.used(), 0);
        }

        #[test]
        fn bulk_decoder_preserves_resource_error() {
            let budget = MemoryBudget::new(1);
            let mut listing = Listing::with_budget(budget.clone()).unwrap();
            let error = decode_batch(&record(0, VREG, b"name"), 1, &mut listing).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
            assert_eq!(budget.used(), 0);
        }

        #[test]
        fn bulk_buffer_reserves_before_allocation_and_retains_charge() {
            let bytes = BUF_WORDS * std::mem::size_of::<u64>();
            let insufficient = MemoryBudget::new(bytes - 1);
            assert_eq!(
                BulkBuffer::new(&insufficient).err().unwrap().raw_os_error(),
                Some(libc::ENOMEM)
            );
            assert_eq!(insufficient.used(), 0);
            assert_eq!(insufficient.peak(), 0);
            let budget = MemoryBudget::new(bytes);
            let buffer = BulkBuffer::new(&budget).unwrap();
            assert_eq!(buffer.words.len(), BUF_WORDS);
            assert_eq!(budget.used(), bytes);
            drop(buffer);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
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
    fn key(e: &Entry) -> (OsString, Kind, u64, u64, u32, u64, u64, i64, bool) {
        let (nlink, alloc, apparent) = if e.kind == Kind::Dir {
            (0, 0, 0)
        } else {
            (e.nlink, e.alloc, e.apparent)
        };
        (
            e.name.clone(),
            e.kind,
            e.dev,
            e.ino,
            nlink,
            alloc,
            apparent,
            e.mtime_secs,
            e.dataless,
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
        assert_eq!(stat.errors, 0);
        assert!(bulk.entries.iter().all(|entry| !entry.dataless));
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

    #[test]
    fn listing_reservation_outlives_moved_entries() {
        let budget = MemoryBudget::new(16 * std::mem::size_of::<Entry>() + 3);
        let mut listing = Listing::with_budget(budget.clone()).unwrap();
        let metadata: libc::stat = unsafe { std::mem::zeroed() };
        listing
            .push_entry(entry_from_stat(&metadata), b"raw")
            .unwrap();
        let bytes = listing.entries.capacity() * std::mem::size_of::<Entry>() + 3;
        assert_eq!(budget.used(), bytes);
        let Listing {
            entries,
            _memory: memory,
            ..
        } = listing;
        assert_eq!(entries[0].name.as_bytes(), b"raw");
        assert_eq!(budget.used(), bytes);
        drop(entries);
        assert_eq!(budget.used(), bytes);
        drop(memory);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn entry_vector_limit_fails_before_allocation() {
        let budget = MemoryBudget::new(16 * std::mem::size_of::<Entry>() - 1);
        let mut listing = Listing::with_budget(budget.clone()).unwrap();
        let metadata: libc::stat = unsafe { std::mem::zeroed() };
        let error = listing
            .push_entry(entry_from_stat(&metadata), b"name")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(listing.entries.capacity(), 0);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), 0);
    }

    #[test]
    fn raw_name_limit_fails_before_copying() {
        let budget = MemoryBudget::new(16 * std::mem::size_of::<Entry>() + 2);
        let mut listing = Listing::with_budget(budget.clone()).unwrap();
        let metadata: libc::stat = unsafe { std::mem::zeroed() };
        let error = listing
            .push_entry(entry_from_stat(&metadata), b"too-long")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert!(listing.entries.is_empty());
        assert_eq!(listing._memory.names.bytes(), 0);
        assert_eq!(budget.used(), 16 * std::mem::size_of::<Entry>());
        drop(listing);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn vector_growth_accounts_for_reallocation_peak() {
        let entry_bytes = std::mem::size_of::<Entry>();
        let budget = MemoryBudget::new(32 * entry_bytes);
        let mut listing = Listing::with_budget(budget.clone()).unwrap();
        let metadata: libc::stat = unsafe { std::mem::zeroed() };
        for _ in 0..16 {
            listing.push_entry(entry_from_stat(&metadata), b"").unwrap();
        }
        let error = listing
            .push_entry(entry_from_stat(&metadata), b"")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(listing.entries.capacity(), 16);
        assert_eq!(listing.entries.len(), 16);
        assert_eq!(budget.used(), 16 * entry_bytes);
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn stat_listing_returns_explicit_resource_error() {
        let dir = fixture();
        let budget = MemoryBudget::new(dir.path().as_os_str().as_bytes().len() + 1);
        let error = list_stat_with_budget(dir.path(), budget.clone()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(budget.used(), 0);
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn inode_numbers_preserve_both_platform_widths() {
        assert_eq!(inode_number(u32::MAX), u64::from(u32::MAX));
        assert_eq!(inode_number(u64::MAX), u64::MAX);
    }

    #[test]
    fn dataless_flag_is_not_confused_with_other_flags() {
        assert!(!is_dataless(0));
        assert!(!is_dataless(!SF_DATALESS));
        assert!(is_dataless(SF_DATALESS));
        assert!(is_dataless(SF_DATALESS | 0x40));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stat_dataless_directory_is_an_error_not_an_empty_listing() {
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        metadata.st_mode = libc::S_IFDIR;
        metadata.st_flags = SF_DATALESS;
        assert!(entry_from_stat(&metadata).dataless);
        let error = refuse_dataless_directory(&metadata).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EDEADLK));
        metadata.st_mode = libc::S_IFREG;
        assert!(entry_from_stat(&metadata).dataless);
        assert!(refuse_dataless_directory(&metadata).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_and_stat_preserve_unicode_names() {
        let dir = tempfile::tempdir().unwrap();
        let name = OsString::from("raw-☃");
        File::create(dir.path().join(&name)).unwrap();
        let bulk = bulk::list_bulk(dir.path()).unwrap();
        let stat = list_stat(dir.path()).unwrap();
        assert_eq!(bulk.entries.len(), 1);
        assert_eq!(stat.entries.len(), 1);
        assert_eq!(key(&bulk.entries[0]), key(&stat.entries[0]));
        assert_eq!(stat.entries[0].name, name);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resource_and_dataless_errors_never_trigger_fallback() {
        assert!(!is_unsupported(&resource_error()));
        assert!(!is_unsupported(&io::Error::from_raw_os_error(
            libc::EDEADLK
        )));
    }
}
