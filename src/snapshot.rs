//! Snapshot history: serialize a full scan's findings to SQLite so runs can be
//! diffed over time (spec §8). One row per finding keyed by stable `FindingId`,
//! plus a `snapshots` table with a timestamp and machine info.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::model::{Finding, FindingId, SnapshotPolicy};

/// Metadata about a stored snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotMeta {
    pub id: i64,
    pub created_at: i64,
    pub machine: String,
    pub finding_count: i64,
    pub total_bytes: i64,
}

/// Difference between two snapshots.
#[derive(Debug, Default)]
pub struct SnapshotDiff {
    /// Findings present in B but not A.
    pub added: Vec<Finding>,
    /// Findings present in A but not B.
    pub removed: Vec<Finding>,
    /// Findings in both whose size increased: (finding, old_bytes, new_bytes).
    pub grown: Vec<(Finding, u64, u64)>,
}

/// Best-effort machine name for snapshot provenance. Shared by the CLI and the
/// TUI's auto-save.
pub fn machine_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

pub struct SnapshotStore {
    conn: Connection,
}

impl SnapshotStore {
    /// Open (creating parent dirs + schema) the on-disk history database.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let store = SnapshotStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = SnapshotStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS snapshots (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                machine    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                finding_id  TEXT NOT NULL,
                kind        TEXT NOT NULL,
                title       TEXT NOT NULL,
                size_bytes  INTEGER,
                severity    TEXT NOT NULL,
                json        TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_snapshot ON findings(snapshot_id);
            "#,
        )?;
        Ok(())
    }

    /// Persist a scan's findings as a new snapshot; returns its row id.
    pub fn save(
        &mut self,
        machine: &str,
        findings: &BTreeMap<FindingId, Finding>,
    ) -> anyhow::Result<i64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO snapshots (created_at, machine) VALUES (?1, ?2)",
            rusqlite::params![now, machine],
        )?;
        let snap_id = tx.last_insert_rowid();
        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (snapshot_id, finding_id, kind, title, size_bytes, severity, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for f in findings
                .values()
                .filter(|f| f.snapshot_policy == SnapshotPolicy::Durable)
            {
                let json = serde_json::to_string(f)?;
                stmt.execute(rusqlite::params![
                    snap_id,
                    f.id.to_string(),
                    f.kind.tag(),
                    f.title,
                    f.size_bytes.map(|s| s as i64),
                    f.severity_label(),
                    json,
                ])?;
            }
        }
        tx.commit()?;
        Ok(snap_id)
    }

    /// All snapshots, newest first.
    pub fn list(&self) -> anyhow::Result<Vec<SnapshotMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.created_at, s.machine,
                    COUNT(f.finding_id),
                    COALESCE(SUM(f.size_bytes), 0)
             FROM snapshots s
             LEFT JOIN findings f ON f.snapshot_id = s.id
             GROUP BY s.id
             ORDER BY s.created_at DESC, s.id DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SnapshotMeta {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    machine: row.get(2)?,
                    finding_count: row.get(3)?,
                    total_bytes: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The most recent snapshot's id, if any.
    pub fn latest_id(&self) -> anyhow::Result<Option<i64>> {
        Ok(self.list()?.first().map(|m| m.id))
    }

    /// All findings from the most recent snapshot (for the TUI's Δ baseline).
    pub fn latest_findings(&self) -> anyhow::Result<Option<Vec<Finding>>> {
        match self.latest_id()? {
            Some(id) => Ok(Some(self.load_findings(id)?.into_values().collect())),
            None => Ok(None),
        }
    }

    fn load_findings(&self, snapshot_id: i64) -> anyhow::Result<BTreeMap<FindingId, Finding>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM findings WHERE snapshot_id = ?1")?;
        let rows = stmt
            .query_map([snapshot_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut map = BTreeMap::new();
        for json in rows {
            let f: Finding = serde_json::from_str(&json)?;
            map.insert(f.id, f);
        }
        Ok(map)
    }

    /// Diff snapshot `a` (baseline) against `b` (newer): added/removed/grown.
    pub fn diff(&self, a: i64, b: i64) -> anyhow::Result<SnapshotDiff> {
        let old = self.load_findings(a)?;
        let new = self.load_findings(b)?;
        let mut diff = SnapshotDiff::default();
        for (id, f) in &new {
            match old.get(id) {
                None => diff.added.push(f.clone()),
                Some(prev) => {
                    if let (Some(o), Some(n)) = (prev.size_bytes, f.size_bytes) {
                        if n > o {
                            diff.grown.push((f.clone(), o, n));
                        }
                    }
                }
            }
        }
        for (id, f) in &old {
            if !new.contains_key(id) {
                diff.removed.push(f.clone());
            }
        }
        Ok(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingKind, Severity};

    fn f(key: &str, title: &str, size: Option<u64>) -> Finding {
        let mut f =
            Finding::new(FindingKind::BuildArtifact, key, title).severity(Severity::Reclaimable);
        f.size_bytes = size;
        f
    }

    fn map_of(items: Vec<Finding>) -> BTreeMap<FindingId, Finding> {
        items.into_iter().map(|f| (f.id, f)).collect()
    }

    #[test]
    fn ephemeral_findings_are_not_saved() {
        let mut store = SnapshotStore::open_in_memory().unwrap();
        let durable = f("/p/durable", "durable", Some(10));
        let ephemeral = Finding::new(FindingKind::SystemMetric, "load", "CPU load").ephemeral();
        store
            .save("mac", &map_of(vec![durable, ephemeral]))
            .unwrap();
        let saved = store.latest_findings().unwrap().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].title, "durable");
    }

    #[test]
    fn save_list_diff_roundtrip() {
        let mut store = SnapshotStore::open_in_memory().unwrap();
        let a = store
            .save(
                "mac",
                &map_of(vec![
                    f("/p/nm", "nm", Some(100)),
                    f("/p/old", "old", Some(5)),
                ]),
            )
            .unwrap();
        let b = store
            .save(
                "mac",
                &map_of(vec![
                    f("/p/nm", "nm", Some(250)),
                    f("/p/new", "new", Some(9)),
                ]),
            )
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);

        let d = store.diff(a, b).unwrap();
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].title, "new");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].title, "old");
        assert_eq!(d.grown.len(), 1);
        assert_eq!(d.grown[0].1, 100);
        assert_eq!(d.grown[0].2, 250);
    }
}
