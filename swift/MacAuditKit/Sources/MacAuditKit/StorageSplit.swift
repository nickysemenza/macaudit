/// Splits a disk's used space into what macaudit's scanners can account for.
///
/// Pulled out of `StorageOverview` (the app target has no test bundle) so
/// the arithmetic — and its clamping — has unit coverage.
public enum StorageSplit {
    /// - Parameters:
    ///   - used: The volume's total used bytes (from the `system` section's
    ///     disk metric).
    ///   - rootAlloc: The allocated size of the walked Disk tree's root
    ///     (`Engine.dirRoot()?.alloc`), or `nil` before a Disk scan has ever
    ///     completed.
    ///   - categoryBytes: Sum of the disjoint category buckets already
    ///     measured — every fs-section `CategoryStat` plus Homebrew, but
    ///     *not* Simulators (its data lives under `~/Library/Developer`,
    ///     already inside the "Apple developer data" fs category, so
    ///     including it too would double-count when `rootAlloc` is known).
    /// - Returns: Either `(otherScanned, unscanned, nil)` when `rootAlloc`
    ///   is known, or `(nil, nil, other)` as a fallback before the first
    ///   Disk scan. Every value is clamped at 0 — a stale or racing read
    ///   must never go negative.
    public static func compute(used: UInt64, rootAlloc: UInt64?, categoryBytes: UInt64)
        -> (otherScanned: UInt64?, unscanned: UInt64?, other: UInt64?)
    {
        guard let rootAlloc else {
            let other = used > categoryBytes ? used - categoryBytes : 0
            return (nil, nil, other)
        }
        // Inside the walked `/` tree but not attributed to any category.
        let otherScanned = rootAlloc > categoryBytes ? rootAlloc - categoryBytes : 0
        // Outside the walked tree entirely: other APFS volumes, local
        // snapshots, folders only root can read.
        let unscanned = used > rootAlloc ? used - rootAlloc : 0
        return (otherScanned, unscanned, nil)
    }
}
