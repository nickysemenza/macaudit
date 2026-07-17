//! Artifact size cache (lane S) — persists `du_blocks` results keyed by path so
//! a rescan can skip re-measuring artifacts whose root mtime hasn't changed
//! since the last scan and whose cached size is still within the configured
//! TTL (spec `scan.size_cache_ttl_hours`, default 24).
//!
//! Own rusqlite db file, separate from `snapshot.rs`'s history db (frozen,
//! not touched here). Corrupted/unopenable db is never fatal to a scan: the
//! `fs.rs` integration treats an `open` failure as an empty cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// A previously computed artifact size, plus enough provenance to decide
/// whether it's still trustworthy on the next scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedSize {
    pub size: u64,
    /// Unix seconds when this size was measured.
    pub computed_at: i64,
    /// The artifact root's mtime (unix seconds) at measurement time — if the
    /// root's current mtime differs, the tree has changed and the entry is stale.
    pub root_mtime: i64,
}

pub struct SizeCache {
    conn: Connection,
}

impl SizeCache {
    /// Open (creating parent dirs + schema) the on-disk size cache database.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let cache = SizeCache { conn };
        cache.init_schema()?;
        Ok(cache)
    }

    /// In-memory cache for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let cache = SizeCache { conn };
        cache.init_schema()?;
        Ok(cache)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS size_cache (
                path        TEXT PRIMARY KEY,
                size        INTEGER NOT NULL,
                computed_at INTEGER NOT NULL,
                root_mtime  INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    /// Load every cached entry into memory, keyed by artifact path.
    pub fn load_all(&self) -> anyhow::Result<HashMap<PathBuf, CachedSize>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, size, computed_at, root_mtime FROM size_cache")?;
        let rows = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            Ok((
                PathBuf::from(path),
                CachedSize {
                    size: row.get::<_, i64>(1)? as u64,
                    computed_at: row.get(2)?,
                    root_mtime: row.get(3)?,
                },
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (path, cached) = row?;
            map.insert(path, cached);
        }
        Ok(map)
    }

    /// Upsert a batch of fresh entries in one transaction. A later entry for
    /// the same path overwrites an earlier one (last wins).
    pub fn upsert_batch(&mut self, entries: &[(PathBuf, CachedSize)]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO size_cache (path, size, computed_at, root_mtime)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET
                     size = excluded.size,
                     computed_at = excluded.computed_at,
                     root_mtime = excluded.root_mtime",
            )?;
            for (path, cached) in entries {
                stmt.execute(rusqlite::params![
                    path.to_string_lossy(),
                    cached.size as i64,
                    cached.computed_at,
                    cached.root_mtime,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

/// Path to the size cache database, derived from `Paths::state_dir` (which is
/// frozen — this stays a free function rather than a new `Paths` method).
pub fn db_path(paths: &crate::config::Paths) -> PathBuf {
    paths.state_dir.join("sizes.db")
}

/// Unix-seconds mtime of `path` itself (the measured tree's root), 0 on any
/// failure (missing path, permission error, platforms without mtime support).
pub fn root_mtime_secs(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Is a cached size still trustworthy: measured within the TTL window AND the
/// tree root's mtime hasn't moved since (a changed mtime means the tree was
/// touched, so the old size can no longer be trusted). Shared by FsScanner's
/// artifact sizing and GitScanner's repo sizing.
pub fn is_fresh(
    cached: &CachedSize,
    current_root_mtime: i64,
    now_secs: i64,
    ttl_hours: u64,
) -> bool {
    let ttl_secs = (ttl_hours as i64).saturating_mul(3600);
    let not_expired = cached.computed_at > now_secs.saturating_sub(ttl_secs);
    let mtime_matches = cached.root_mtime == current_root_mtime;
    not_expired && mtime_matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;

    fn sized(size: u64, computed_at: i64, root_mtime: i64) -> CachedSize {
        CachedSize {
            size,
            computed_at,
            root_mtime,
        }
    }

    #[test]
    fn in_memory_roundtrip() {
        let mut cache = SizeCache::open_in_memory().unwrap();
        let entries = vec![
            (PathBuf::from("/a/node_modules"), sized(100, 1000, 500)),
            (PathBuf::from("/b/target"), sized(200, 1001, 501)),
        ];
        cache.upsert_batch(&entries).unwrap();

        let loaded = cache.load_all().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.get(&PathBuf::from("/a/node_modules")),
            Some(&sized(100, 1000, 500))
        );
        assert_eq!(
            loaded.get(&PathBuf::from("/b/target")),
            Some(&sized(200, 1001, 501))
        );
    }

    #[test]
    fn batch_overwrite_last_wins() {
        let mut cache = SizeCache::open_in_memory().unwrap();
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(100, 1000, 500))])
            .unwrap();
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(999, 2000, 600))])
            .unwrap();

        let loaded = cache.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get(&PathBuf::from("/a")),
            Some(&sized(999, 2000, 600))
        );
    }

    #[test]
    fn batch_overwrite_within_same_call_last_wins() {
        let mut cache = SizeCache::open_in_memory().unwrap();
        cache
            .upsert_batch(&[
                (PathBuf::from("/a"), sized(100, 1000, 500)),
                (PathBuf::from("/a"), sized(999, 2000, 600)),
            ])
            .unwrap();

        let loaded = cache.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded.get(&PathBuf::from("/a")),
            Some(&sized(999, 2000, 600))
        );
    }

    #[test]
    fn db_path_shape() {
        let paths = Paths::from_home("/tmp/fixture-home");
        assert_eq!(
            db_path(&paths),
            PathBuf::from("/tmp/fixture-home/.local/state/macaudit/sizes.db")
        );
    }
}
