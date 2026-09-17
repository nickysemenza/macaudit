//! Turns a resolve pass's `Claim`s into a `FootprintSet`: group by canonical
//! path, resolve multi-owner nesting deepest-first, then derive each owner's
//! exclusive/shared/reach/baseline-share numbers (§3).
//!
//! Pure — no I/O beyond `paths::Sizer` (tree lookups + the occasional
//! `lstat` for a file claim, both already memoised).
//!
//! **Nesting, precisely.** `FootprintEntry::bytes` is defined so that it
//! "sums correctly with siblings" (its own doc comment): summing every
//! entry's `bytes` under a claimed subtree reproduces that subtree's own
//! `raw_bytes` exactly, with nothing double-counted and nothing dropped.
//! That only holds if an ancestor subtracts each nearest descendant's own
//! `raw_bytes` (which already covers everything *below* that descendant,
//! claimed or not) — subtracting the descendant's post-subtraction `bytes`
//! instead would leave whatever that descendant already carved out for its
//! own nested claims double-counted in the ancestor. Concretely, for
//! `A(raw=300) ⊃ B(raw=150) ⊃ C(raw=50)` with three different owners:
//! `C.bytes = 50`, `B.bytes = 150 − 50 = 100`, `A.bytes = 300 − 150 = 50 +
//! 100 + 150 = 300`... i.e. `A.bytes = 300 − raw(B) = 150`, and
//! `50 + 100 + 150 = 300 = raw(A)`. Had `A` instead subtracted `B.bytes`
//! (100), the sum would be `50 + 100 + 200 = 350` — `C`'s 50 bytes counted
//! once on their own and a second time still sitting inside `A`'s "own"
//! share. So the per-node subtraction below sums nearest children's
//! `raw_bytes`, not their `bytes`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use crate::model::{FindingId, FindingKind};

use super::model::{
    self, Axis, Claim, EntryKind, Footprint, FootprintEntry, FootprintGroup, FootprintSet, Owner,
    OwnerKind, ResolveEnv,
};
use super::paths;

/// Account for a resolve pass's claims, producing one `Footprint` per unique
/// owner plus the synthetic Baseline/Unattributed rows.
///
/// `owners` is the axis's full owner registry (every discovered project /
/// app / formula / tool): each gets a `Footprint` row even with zero claims
/// (an empty project is still a project), and supplies the row's
/// `name`/`kind`/`path`. A claim whose owner key isn't in the registry
/// (the Apple data table can name an app that isn't installed) still gets a
/// row, with metadata derived from the key alone (`owner_from_key`).
pub fn account(
    claims: Vec<Claim>,
    owners: &[Owner],
    env: &ResolveEnv<'_>,
    axis: Axis,
) -> FootprintSet {
    // Which owners claimed anything tagged with a given ecosystem — the
    // denominator for baseline shares (§3: "N_eco = number of owners whose
    // claims include any claim with that ecosystem tag").
    let mut ecosystem_owners: HashMap<&'static str, BTreeSet<String>> = HashMap::new();
    for claim in &claims {
        if claim.owner == model::BASELINE_OWNER {
            continue;
        }
        if let Some(eco) = claim.ecosystem {
            ecosystem_owners
                .entry(eco)
                .or_default()
                .insert(claim.owner.clone());
        }
    }

    let registry: HashMap<&str, &Owner> = owners.iter().map(|o| (o.key.as_str(), o)).collect();
    let all_owner_keys: BTreeSet<String> = claims
        .iter()
        .map(|c| c.owner.clone())
        .chain(owners.iter().map(|o| o.key.clone()))
        .filter(|o| o != model::UNATTRIBUTED_OWNER && o != model::BASELINE_OWNER)
        .collect();

    // 1. Group by canonical path.
    let mut by_path: BTreeMap<PathBuf, Vec<Claim>> = BTreeMap::new();
    for claim in claims {
        by_path
            .entry(paths::tree_path(&claim.path))
            .or_default()
            .push(claim);
    }

    let sizer = paths::Sizer::new(env.trees);
    let mut entries: Vec<(FootprintEntry, BTreeSet<&'static str>)> =
        Vec::with_capacity(by_path.len());
    for (path, path_claims) in by_path {
        let deduped = dedup_per_owner(path_claims);
        entries.push(build_entry(path, deduped, &sizer));
    }

    // 2. Nesting, deepest-first (see the module doc for why nearest
    // descendants contribute their *raw* bytes, not their adjusted ones).
    entries.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let n = entries.len();
    let mut parent: Vec<Option<usize>> = vec![None; n];
    {
        let mut stack: Vec<usize> = Vec::new();
        for i in 0..n {
            while let Some(&top) = stack.last() {
                if entries[i].0.path.starts_with(&entries[top].0.path)
                    && entries[i].0.path != entries[top].0.path
                {
                    break;
                }
                stack.pop();
            }
            parent[i] = stack.last().copied();
            stack.push(i);
        }
    }
    let mut children_raw: Vec<u64> = vec![0; n];
    for i in 0..n {
        if let Some(p) = parent[i] {
            children_raw[p] += entries[i].0.raw_bytes;
        }
    }
    // Saturating: an ancestor's raw bytes can legitimately trail its
    // children's when the two came from different measurements (a finding's
    // cached `size_bytes` override under a freshly walked child, or a walk
    // that raced a growing build dir) — the parent's own remainder is then
    // simply zero, never a panic.
    for i in 0..n {
        entries[i].0.bytes = entries[i].0.raw_bytes.saturating_sub(children_raw[i]);
    }

    // 3. Split into baseline / unattributed / owned, accumulating each
    // owner's numbers as we go.
    let mut accum: HashMap<String, OwnerAccum> = all_owner_keys
        .iter()
        .map(|k| (k.clone(), OwnerAccum::default()))
        .collect();
    let mut baseline: Vec<FootprintEntry> = Vec::new();
    let mut unattributed: Vec<FootprintEntry> = Vec::new();
    let mut attributed_total: u64 = 0;

    for (mut entry, ecosystems) in entries {
        if !entry.virtual_bytes {
            attributed_total += entry.bytes;
        }

        if entry.owners.len() == 1 && entry.owners[0] == model::UNATTRIBUTED_OWNER {
            entry.reason = Some(entry.evidence.clone());
            unattributed.push(entry);
            continue;
        }

        if entry.baseline {
            let owner_universe: BTreeSet<String> = ecosystems
                .iter()
                .flat_map(|eco| ecosystem_owners.get(eco).cloned().unwrap_or_default())
                .collect();
            let n_eco = owner_universe.len() as u64;
            // N_eco == 0: no owner is known to be in this ecosystem — the
            // entry stays whole in Baseline, uncounted toward anyone's share.
            if let Some(base) = entry.bytes.checked_div(n_eco) {
                let rem = entry.bytes % n_eco;
                let first = owner_universe.iter().next().cloned();
                for owner in &owner_universe {
                    let Some(a) = accum.get_mut(owner) else {
                        continue;
                    };
                    let share = if Some(owner) == first.as_ref() {
                        base + rem
                    } else {
                        base
                    };
                    a.baseline_share += share;
                    a.reach += entry.bytes;
                    a.clone_note |= entry.clone_of_store;
                }
            }
            baseline.push(entry);
            continue;
        }

        let n_owners = entry.owners.len() as u64;
        let first_owner = entry.owners.first().cloned();
        for owner in &entry.owners {
            let Some(a) = accum.get_mut(owner) else {
                continue;
            };
            a.reach += entry.bytes;
            a.clone_note |= entry.clone_of_store;

            let contribution = if entry.virtual_bytes {
                0
            } else if n_owners == 1 {
                if entry.clone_of_store {
                    0
                } else {
                    entry.bytes
                }
            } else {
                let base = entry.bytes / n_owners;
                let rem = entry.bytes % n_owners;
                if Some(owner) == first_owner.as_ref() {
                    base + rem
                } else {
                    base
                }
            };
            if n_owners == 1 {
                a.exclusive += contribution;
            } else {
                a.shared += contribution;
            }
            let group = a.groups.entry(entry.kind).or_default();
            group.0 += contribution;
            group.1.push(entry.clone());
        }
    }

    // 4. Assemble one Footprint per owner.
    let finding_kind = match axis {
        Axis::Projects => FindingKind::Project,
        Axis::AppStorage => FindingKind::AppOwner,
    };
    let mut footprints: Vec<Footprint> = all_owner_keys
        .into_iter()
        .map(|key| {
            let a = accum.remove(&key).unwrap_or_default();
            let mut groups: Vec<FootprintGroup> = a
                .groups
                .into_iter()
                .map(|(kind, (bytes, mut group_entries))| {
                    group_entries
                        .sort_by(|x, y| y.bytes.cmp(&x.bytes).then_with(|| x.path.cmp(&y.path)));
                    FootprintGroup {
                        kind,
                        bytes,
                        entries: group_entries,
                    }
                })
                .collect();
            groups.sort_by(|x, y| {
                y.bytes
                    .cmp(&x.bytes)
                    .then_with(|| kind_rank(x.kind).cmp(&kind_rank(y.kind)))
            });
            Footprint {
                finding: FindingId::new(finding_kind, &key),
                owner: registry
                    .get(key.as_str())
                    .map(|o| (*o).clone())
                    .unwrap_or_else(|| owner_from_key(axis, &key)),
                exclusive: a.exclusive,
                shared: a.shared,
                reach: a.reach,
                baseline_share: a.baseline_share,
                groups,
                worktrees: Vec::new(),
                processes: Vec::new(),
                ports: Vec::new(),
                clone_note: a.clone_note,
            }
        })
        .collect();
    footprints.sort_by(|a, b| {
        b.exclusive
            .cmp(&a.exclusive)
            .then_with(|| a.owner.key.cmp(&b.owner.key))
    });

    FootprintSet {
        axis,
        gen: 0,
        footprints,
        baseline,
        unattributed,
        disk_total: paths::disk_total(env.trees),
        attributed_total,
        missing_deps: Vec::new(),
    }
}

/// Running per-owner totals while entries are folded in.
#[derive(Default)]
struct OwnerAccum {
    exclusive: u64,
    shared: u64,
    reach: u64,
    baseline_share: u64,
    clone_note: bool,
    groups: HashMap<EntryKind, (u64, Vec<FootprintEntry>)>,
}

/// Collapse repeat claims from the same owner on the same path to the one
/// with the strongest evidence tier (ties keep whichever was seen first, for
/// determinism). What's left is at most one claim per owner — the set this
/// path's `FootprintEntry` is built from.
fn dedup_per_owner(claims: Vec<Claim>) -> Vec<Claim> {
    let mut best: BTreeMap<String, Claim> = BTreeMap::new();
    for claim in claims {
        match best.get(&claim.owner) {
            Some(existing) if existing.tier <= claim.tier => {}
            _ => {
                best.insert(claim.owner.clone(), claim);
            }
        }
    }
    best.into_values().collect()
}

/// Build one path's `FootprintEntry` (with `bytes` still equal to
/// `raw_bytes` — nesting adjusts it afterwards) from its deduped claims,
/// plus the ecosystem tags those claims carried (kept alongside rather than
/// on `FootprintEntry` itself, since it's only needed to compute baseline
/// shares and isn't part of the FFI-shaped entry type).
fn build_entry(
    path: PathBuf,
    claims: Vec<Claim>,
    sizer: &paths::Sizer<'_>,
) -> (FootprintEntry, BTreeSet<&'static str>) {
    // The ecosystem-pass sentinel never appears as an owner: an entry it
    // alone claimed has no owners and is baseline by construction.
    let mut owners: Vec<String> = claims
        .iter()
        .map(|c| c.owner.clone())
        .filter(|o| o != model::BASELINE_OWNER)
        .collect();
    owners.sort();
    owners.dedup();

    // The strongest-tier claim supplies kind/evidence/label/finding; ties
    // broken by owner so the pick is deterministic regardless of input order.
    let primary = claims
        .iter()
        .min_by(|a, b| a.tier.cmp(&b.tier).then_with(|| a.owner.cmp(&b.owner)))
        .expect("build_entry is only called with a non-empty claim group");

    let baseline = owners.is_empty() || claims.iter().any(|c| c.baseline);
    let clone_of_store = claims.iter().any(|c| c.clone_of_store);
    let virtual_bytes = claims.iter().any(|c| c.virtual_bytes);
    let stale = claims.iter().any(|c| c.stale);
    let raw_override = claims.iter().find_map(|c| c.raw_bytes_override);
    let ecosystems: BTreeSet<&'static str> = claims.iter().filter_map(|c| c.ecosystem).collect();

    let (raw_bytes, is_unsized) = match raw_override {
        Some(bytes) => (bytes, false),
        None => match sizer.bytes_of(&path) {
            paths::Sized::Dir(bytes) | paths::Sized::File(bytes) => (bytes, false),
            paths::Sized::Unsized => (0, true),
        },
    };

    let entry = FootprintEntry {
        path,
        kind: primary.kind,
        bytes: raw_bytes,
        raw_bytes,
        owners,
        tier: primary.tier,
        evidence: primary.evidence.clone(),
        label: primary.label.clone(),
        baseline,
        clone_of_store,
        virtual_bytes,
        r#unsized: is_unsized,
        stale,
        finding: primary.finding,
        reason: None,
    };
    (entry, ecosystems)
}

/// Best-effort owner identity from its key alone — see `account`'s doc
/// comment for why a fuller registry isn't available here. Project keys are
/// root paths; App Storage keys are bundle ids, or `formula:<name>` /
/// `tool:<name>` / `homebrew`.
fn owner_from_key(axis: Axis, key: &str) -> Owner {
    match axis {
        Axis::Projects => {
            let path = PathBuf::from(key);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| key.to_string());
            Owner {
                key: key.to_string(),
                kind: OwnerKind::Project,
                name,
                path: Some(path),
            }
        }
        Axis::AppStorage => {
            if let Some(name) = key.strip_prefix("formula:") {
                Owner {
                    key: key.to_string(),
                    kind: OwnerKind::Formula,
                    name: name.to_string(),
                    path: None,
                }
            } else if let Some(name) = key.strip_prefix("tool:") {
                Owner {
                    key: key.to_string(),
                    kind: OwnerKind::Tool,
                    name: name.to_string(),
                    path: None,
                }
            } else if key == "homebrew" {
                Owner {
                    key: key.to_string(),
                    kind: OwnerKind::Homebrew,
                    name: "Homebrew".to_string(),
                    path: None,
                }
            } else {
                let name = key.rsplit('.').next().unwrap_or(key).to_string();
                Owner {
                    key: key.to_string(),
                    kind: OwnerKind::App,
                    name,
                    path: None,
                }
            }
        }
    }
}

fn kind_rank(kind: EntryKind) -> usize {
    EntryKind::ALL
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};
    use crate::model::ScannerId;
    use crate::runner::MockCommandRunner;
    use crate::scan::walk::DirTree;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Arc;

    fn env<'a>(
        paths: &'a Paths,
        config: &'a Config,
        trees: &'a [Arc<DirTree>],
        snapshots: &'a StdHashMap<ScannerId, super::super::bus::Snapshot>,
        runner: &'a MockCommandRunner,
    ) -> ResolveEnv<'a> {
        ResolveEnv::new(paths, config, trees, snapshots, runner)
    }

    struct Fixture {
        paths: Paths,
        config: Config,
        trees: Vec<Arc<DirTree>>,
        snapshots: StdHashMap<ScannerId, super::super::bus::Snapshot>,
        runner: MockCommandRunner,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                paths: Paths::from_home("/tmp/macaudit-accounting-test-home"),
                config: Config::default(),
                trees: Vec::new(),
                snapshots: StdHashMap::new(),
                runner: MockCommandRunner::new(),
            }
        }

        fn env(&self) -> ResolveEnv<'_> {
            env(
                &self.paths,
                &self.config,
                &self.trees,
                &self.snapshots,
                &self.runner,
            )
        }
    }

    fn claim(path: &str, owner: &str, kind: EntryKind, raw_bytes: u64) -> Claim {
        Claim::new(
            path,
            owner,
            kind,
            super::super::model::EvidenceTier::Exact,
            "test",
        )
        .raw_bytes_override(raw_bytes)
    }

    fn find_entry(set: &FootprintSet, path: impl AsRef<std::path::Path>) -> &FootprintEntry {
        let path = path.as_ref();
        set.footprints
            .iter()
            .flat_map(|f| f.groups.iter())
            .flat_map(|g| g.entries.iter())
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("no entry for {path:?} in {set:#?}"))
    }

    fn footprint<'a>(set: &'a FootprintSet, owner_key: &str) -> &'a Footprint {
        set.footprints
            .iter()
            .find(|f| f.owner.key == owner_key)
            .unwrap_or_else(|| panic!("no footprint for {owner_key} in {set:#?}"))
    }

    #[test]
    fn nesting_three_distinct_owners_no_negative_no_double_subtraction() {
        let fixture = Fixture::new();
        let claims = vec![
            claim("/root/a", "proj-a", EntryKind::WorkingTree, 300),
            claim("/root/a/b", "proj-b", EntryKind::WorkingTree, 150),
            claim("/root/a/b/c", "proj-c", EntryKind::WorkingTree, 50),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(find_entry(&set, "/root/a").bytes, 150);
        assert_eq!(find_entry(&set, "/root/a/b").bytes, 100);
        assert_eq!(find_entry(&set, "/root/a/b/c").bytes, 50);
        assert_eq!(footprint(&set, "proj-a").exclusive, 150);
        assert_eq!(footprint(&set, "proj-b").exclusive, 100);
        assert_eq!(footprint(&set, "proj-c").exclusive, 50);
        assert_eq!(set.attributed_total, 300);
    }

    #[test]
    fn nesting_same_owner_at_top_and_bottom_of_a_different_middle_owner() {
        // A{p} ⊃ B{q} ⊃ C{p}: C's bytes go to p, B excludes C.
        let fixture = Fixture::new();
        let claims = vec![
            claim("/root/a", "p", EntryKind::WorkingTree, 300),
            claim("/root/a/b", "q", EntryKind::WorkingTree, 150),
            claim("/root/a/b/c", "p", EntryKind::WorkingTree, 50),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(find_entry(&set, "/root/a").bytes, 150);
        assert_eq!(find_entry(&set, "/root/a/b").bytes, 100);
        assert_eq!(find_entry(&set, "/root/a/b/c").bytes, 50);
        assert_eq!(
            find_entry(&set, "/root/a/b/c").owners,
            vec!["p".to_string()]
        );
        assert_eq!(find_entry(&set, "/root/a/b").owners, vec!["q".to_string()]);
        assert_eq!(footprint(&set, "p").exclusive, 150 + 50);
        assert_eq!(footprint(&set, "q").exclusive, 100);
    }

    #[test]
    fn same_owner_breakdown_keeps_both_entries_and_the_artifact_finding() {
        let fixture = Fixture::new();
        let claims = vec![
            claim("/root/proj", "p", EntryKind::WorkingTree, 1000),
            Claim::new(
                "/root/proj/node_modules",
                "p",
                EntryKind::Artifacts,
                super::super::model::EvidenceTier::Exact,
                "node_modules",
            )
            .raw_bytes_override(400)
            .finding(FindingId(42)),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(find_entry(&set, "/root/proj").bytes, 600);
        let artifacts = find_entry(&set, "/root/proj/node_modules");
        assert_eq!(artifacts.bytes, 400);
        assert_eq!(artifacts.finding, Some(FindingId(42)));
        let fp = footprint(&set, "p");
        assert_eq!(fp.exclusive, 1000);
        assert_eq!(fp.groups.len(), 2);
    }

    #[test]
    fn shared_remainder_goes_to_the_first_owner_so_shares_sum_exactly() {
        let fixture = Fixture::new();
        let claims = vec![
            claim("/root/shared", "p1", EntryKind::PackageCache, 10),
            claim("/root/shared", "p2", EntryKind::PackageCache, 10),
            claim("/root/shared", "p3", EntryKind::PackageCache, 10),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        let p1 = footprint(&set, "p1").shared;
        let p2 = footprint(&set, "p2").shared;
        let p3 = footprint(&set, "p3").shared;
        assert_eq!(p1 + p2 + p3, 10);
        assert_eq!(p1, 4); // 10 / 3 = 3 remainder 1, remainder to the first (sorted) owner
        assert_eq!(p2, 3);
        assert_eq!(p3, 3);
    }

    #[test]
    fn ecosystem_pass_baseline_claim_is_shared_by_tagged_owners_only() {
        use super::super::model::{EvidenceTier, BASELINE_OWNER};
        let fixture = Fixture::new();
        let rust_claim = |path: &str, owner: &str| {
            Claim::new(
                path,
                owner,
                EntryKind::PackageCache,
                EvidenceTier::Exact,
                "Cargo.lock",
            )
            .raw_bytes_override(1)
            .ecosystem("rust")
        };
        let claims = vec![
            rust_claim("/registry/serde", "proj-a"),
            rust_claim("/registry/tokio", "proj-b"),
            // A Node-only project: not in the rust ecosystem.
            Claim::new(
                "/root/c",
                "proj-c",
                EntryKind::WorkingTree,
                EvidenceTier::Exact,
                "root",
            )
            .raw_bytes_override(1),
            // Claimed once by the ecosystem pass, not per project.
            Claim::new(
                "/toolchains/stable",
                BASELINE_OWNER,
                EntryKind::Toolchain,
                EvidenceTier::EcosystemDefault,
                "default toolchain",
            )
            .raw_bytes_override(100)
            .baseline("rust"),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(footprint(&set, "proj-a").baseline_share, 50);
        assert_eq!(footprint(&set, "proj-b").baseline_share, 50);
        assert_eq!(footprint(&set, "proj-c").baseline_share, 0);
        assert!(set.footprints.iter().all(|f| f.owner.key != BASELINE_OWNER));
        assert_eq!(set.baseline.len(), 1);
        assert!(set.baseline[0].owners.is_empty());
    }

    #[test]
    fn baseline_share_divides_by_the_ecosystems_owner_count() {
        let fixture = Fixture::new();
        let claims = vec![
            Claim::new(
                "/root/a",
                "proj-a",
                EntryKind::WorkingTree,
                super::super::model::EvidenceTier::Exact,
                "root",
            )
            .raw_bytes_override(1),
            Claim::new(
                "/root/b",
                "proj-b",
                EntryKind::WorkingTree,
                super::super::model::EvidenceTier::Exact,
                "root",
            )
            .raw_bytes_override(1),
            Claim::new(
                "/toolchains/rust",
                "proj-a",
                EntryKind::Toolchain,
                super::super::model::EvidenceTier::EcosystemDefault,
                "default toolchain",
            )
            .raw_bytes_override(100)
            .baseline("rust"),
            Claim::new(
                "/toolchains/rust",
                "proj-b",
                EntryKind::Toolchain,
                super::super::model::EvidenceTier::EcosystemDefault,
                "default toolchain",
            )
            .raw_bytes_override(100)
            .baseline("rust"),
        ];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(footprint(&set, "proj-a").baseline_share, 50);
        assert_eq!(footprint(&set, "proj-b").baseline_share, 50);
        assert_eq!(footprint(&set, "proj-a").reach, 1 + 100);
        assert_eq!(set.baseline.len(), 1);
        assert_eq!(set.baseline[0].bytes, 100);
        // Never in anyone's exclusive/shared.
        assert_eq!(footprint(&set, "proj-a").exclusive, 1);
        assert_eq!(footprint(&set, "proj-a").shared, 0);
    }

    #[test]
    fn n_eco_zero_leaves_the_entry_whole_in_baseline() {
        let fixture = Fixture::new();
        // A baseline claim with no ecosystem tag at all (built via struct
        // literal, bypassing the `.baseline(eco)` builder, exactly the
        // "nobody is known to be in this ecosystem" case `N_eco == 0`
        // guards): the resource still belongs in Baseline, but there is no
        // owner set to divide it across.
        let mut untagged = Claim::new(
            "/toolchains/mystery",
            "proj-a",
            EntryKind::Toolchain,
            super::super::model::EvidenceTier::EcosystemDefault,
            "orphaned baseline tag",
        )
        .raw_bytes_override(64);
        untagged.baseline = true;
        untagged.ecosystem = None;

        let set = account(vec![untagged], &[], &fixture.env(), Axis::Projects);

        assert_eq!(set.baseline.len(), 1);
        assert_eq!(set.baseline[0].bytes, 64);
        // proj-a still gets a Footprint row (it did claim something), but
        // nothing was added to its baseline_share.
        assert_eq!(footprint(&set, "proj-a").baseline_share, 0);
    }

    #[test]
    fn clone_of_store_counts_in_reach_not_exclusive() {
        let fixture = Fixture::new();
        let claims = vec![Claim::new(
            "/root/proj/node_modules/.pnpm",
            "p",
            EntryKind::PackageCache,
            super::super::model::EvidenceTier::Exact,
            "pnpm clone",
        )
        .raw_bytes_override(500)
        .clone_of_store()];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        let fp = footprint(&set, "p");
        assert_eq!(fp.exclusive, 0);
        assert_eq!(fp.shared, 0);
        assert_eq!(fp.reach, 500);
        assert!(fp.clone_note);
    }

    #[test]
    fn virtual_bytes_are_not_in_attributed_total() {
        let fixture = Fixture::new();
        let claims = vec![Claim::new(
            "/docker/image",
            "p",
            EntryKind::Docker,
            super::super::model::EvidenceTier::Exact,
            "docker image",
        )
        .raw_bytes_override(1_000)
        .virtual_bytes()];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert_eq!(set.attributed_total, 0);
        let fp = footprint(&set, "p");
        assert_eq!(fp.exclusive, 0);
        assert_eq!(fp.reach, 1_000);
    }

    #[test]
    fn unattributed_claim_gets_a_reason_and_no_footprint() {
        let fixture = Fixture::new();
        let claims = vec![Claim::new(
            "/Library/Caches/orphan",
            model::UNATTRIBUTED_OWNER,
            EntryKind::Cache,
            super::super::model::EvidenceTier::Curated,
            "no owner matched `orphan`",
        )
        .raw_bytes_override(10)];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);

        assert!(set.footprints.is_empty());
        assert_eq!(set.unattributed.len(), 1);
        assert_eq!(
            set.unattributed[0].reason.as_deref(),
            Some("no owner matched `orphan`")
        );
    }

    #[test]
    fn file_claim_is_sized_via_lstat() {
        let fixture = Fixture::new();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![0u8; 20_000]).unwrap();
        let claims = vec![Claim::new(
            tmp.path(),
            "p",
            EntryKind::PackageCache,
            super::super::model::EvidenceTier::Exact,
            "a .crate file",
        )];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);
        let entry = find_entry(&set, paths::tree_path(tmp.path()));
        assert!(!entry.r#unsized);
        assert!(entry.bytes >= 20_000);
    }

    #[test]
    fn unsized_dir_is_flagged() {
        let fixture = Fixture::new();
        let tmp = tempfile::tempdir().unwrap();
        let claims = vec![Claim::new(
            tmp.path(),
            "p",
            EntryKind::Other,
            super::super::model::EvidenceTier::Observed,
            "a dir no tree reached",
        )];
        let set = account(claims, &[], &fixture.env(), Axis::Projects);
        let entry = find_entry(&set, paths::tree_path(tmp.path()));
        assert!(entry.r#unsized);
        assert_eq!(entry.bytes, 0);
    }

    #[test]
    fn empty_claims_yield_an_empty_set_for_the_requested_axis() {
        let fixture = Fixture::new();
        let set = account(Vec::new(), &[], &fixture.env(), Axis::AppStorage);
        assert_eq!(set.axis, Axis::AppStorage);
        assert!(set.footprints.is_empty());
        assert_eq!(set.disk_total, 0);
    }
}
