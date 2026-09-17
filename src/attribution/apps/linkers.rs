//! Candidate-to-owner tier resolution, first hit wins per candidate (ties
//! share): exact bundle id, exact group-container heuristic, name match
//! (`CFBundleName`/`CFBundleDisplayName`/`CFBundleExecutable`/vendor
//! component), observed (open files from the shared `lsof` pass), curated
//! (the ≤25-row last-resort table in `curated.rs`).
//!
//! `resolve_candidate` picks the tier (pure, unit-tested below on in-memory
//! owner/candidate lists); `link` is the only impure part — it runs the
//! `lsof`/`ps` pass for tier 4 and turns every candidate plus each owner's
//! own bundle/Cellar/install dir into `Claim`s.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::attribution::model::{self, Claim, EntryKind, EvidenceTier, ResolveEnv};
use crate::runner::CommandRunner;

use super::candidates::Candidate;
use super::curated::{self, CuratedTarget};
use super::owners::Owners;

/// One owner matching a candidate at some tier, with the human-readable
/// reason that becomes the claim's `evidence`.
struct OwnerHit {
    key: String,
    evidence: String,
}

/// Resolve every candidate to claims (owner claims for matches,
/// `UNATTRIBUTED_OWNER` claims for misses), plus each owner's own
/// bundle/Cellar/install dir and Homebrew's own top-level dirs, plus
/// dependency-sharing claims for formulae with installed dependents.
pub(crate) fn link(
    env: &ResolveEnv<'_>,
    owners: &Owners,
    candidates: &[Candidate],
    groups: &HashMap<PathBuf, (Vec<String>, bool)>,
) -> Vec<Claim> {
    let observed = observed_opens(env, owners, candidates);

    let mut claims = Vec::with_capacity(candidates.len() + owners.apps.len());
    let mut attributed: HashSet<&Path> = HashSet::new();
    let mut misses: Vec<&Candidate> = Vec::new();
    for candidate in candidates {
        let (hits, tier) = resolve_candidate(owners, groups, &observed, candidate);
        if hits.is_empty() {
            misses.push(candidate);
            continue;
        }
        attributed.insert(&candidate.path);
        for hit in hits {
            claims.push(
                Claim::new(
                    candidate.path.clone(),
                    hit.key,
                    candidate.parent_kind,
                    tier,
                    hit.evidence,
                )
                .label(candidate.name.clone()),
            );
        }
    }

    // A depth-2 candidate (`Application Support/Claude/vm_bundles`) that
    // matched nothing itself is just part of its matched parent — emitting
    // it as Unattributed would carve it *out* of the parent's bytes.
    for candidate in misses {
        let inside_attributed = candidate
            .path
            .parent()
            .is_some_and(|parent| attributed.contains(parent));
        if !inside_attributed {
            claims.push(unattributed_claim(candidate));
        }
    }

    claims.extend(owner_own_claims(env, owners));
    claims.extend(formula_sharing_claims(owners));
    claims
}

/// Which owner(s) claim one candidate, and at which tier — the pure core
/// the unit tests below exercise directly.
fn resolve_candidate(
    owners: &Owners,
    groups: &HashMap<PathBuf, (Vec<String>, bool)>,
    observed: &HashSet<(String, PathBuf)>,
    candidate: &Candidate,
) -> (Vec<OwnerHit>, EvidenceTier) {
    let hits = tier1_exact(owners, groups, candidate);
    if !hits.is_empty() {
        return (hits, EvidenceTier::Exact);
    }
    let hits = tier2_group_heuristic(owners, candidate);
    if !hits.is_empty() {
        return (hits, EvidenceTier::Exact);
    }
    let hits = tier3_name_match(owners, candidate);
    if !hits.is_empty() {
        return (hits, EvidenceTier::NameMatch);
    }
    let hits: Vec<OwnerHit> = observed
        .iter()
        .filter(|(_, path)| path == &candidate.path)
        .map(|(key, _)| OwnerHit {
            key: key.clone(),
            evidence: "a running process of this app has it open".to_string(),
        })
        .collect();
    if !hits.is_empty() {
        return (hits, EvidenceTier::Observed);
    }
    (tier5_curated(owners, candidate), EvidenceTier::Curated)
}

/// Tier 1: candidate name equals an owner's bundle id or alias
/// (case-insensitive — covers `<id>.plist`/`.binarycookies`/`.savedState`
/// stems too, since `candidates.rs` already strips those extensions into
/// `name`), or a Group Containers name equals one of the owner's entitled
/// app groups.
fn tier1_exact(
    owners: &Owners,
    groups: &HashMap<PathBuf, (Vec<String>, bool)>,
    candidate: &Candidate,
) -> Vec<OwnerHit> {
    let cand_lower = candidate.name.to_lowercase();
    let mut hits = Vec::new();
    for app in &owners.apps {
        let bid_lower = app.owner.key.to_lowercase();
        let alias_hit = app.aliases.iter().any(|a| a.to_lowercase() == cand_lower);
        if cand_lower == bid_lower || alias_hit {
            hits.push(OwnerHit {
                key: app.owner.key.clone(),
                evidence: format!("`{}` matches the bundle id", candidate.name),
            });
            continue;
        }
        if candidate.parent_kind == EntryKind::GroupContainer {
            if let Some(app_path) = &app.owner.path {
                if let Some((entitled_groups, _)) = groups.get(app_path) {
                    if entitled_groups
                        .iter()
                        .any(|g| g.to_lowercase() == cand_lower)
                    {
                        hits.push(OwnerHit {
                            key: app.owner.key.clone(),
                            evidence: format!("`{}` is an entitled app group", candidate.name),
                        });
                    }
                }
            }
        }
    }
    hits
}

/// Tier 2: a Group Containers name matches `group.<id>` or
/// `<TEAMID>.<id>`/`<TEAMID>.group.<id>` for an owner's bundle id (or its
/// last two components) — the fallback for when entitlements weren't
/// available to try tier 1's exact group match.
fn tier2_group_heuristic(owners: &Owners, candidate: &Candidate) -> Vec<OwnerHit> {
    if candidate.parent_kind != EntryKind::GroupContainer {
        return Vec::new();
    }
    let lower_name = candidate.name.to_lowercase();
    let mut hits = Vec::new();
    for app in &owners.apps {
        if group_heuristic_matches(&lower_name, &app.owner.key.to_lowercase()) {
            hits.push(OwnerHit {
                key: app.owner.key.clone(),
                evidence: format!(
                    "`{}` matches `{}` by group-id shape",
                    candidate.name, app.owner.key
                ),
            });
        }
    }
    hits
}

fn group_heuristic_matches(lower_name: &str, lower_bundle_id: &str) -> bool {
    let parts: Vec<&str> = lower_bundle_id.split('.').collect();
    let last_two = if parts.len() >= 2 {
        Some(parts[parts.len() - 2..].join("."))
    } else {
        None
    };
    let candidates_for_id = |id: &str| -> Vec<String> { vec![format!("group.{id}")] };

    let mut shapes = candidates_for_id(lower_bundle_id);
    if let Some(lt) = &last_two {
        shapes.extend(candidates_for_id(lt));
    }
    if shapes.iter().any(|s| s == lower_name) {
        return true;
    }
    // `<TEAMID>.<id>` / `<TEAMID>.group.<id>` — Apple team ids are exactly
    // 10 alphanumeric characters; we don't validate them further than that.
    if let Some((first, rest)) = lower_name.split_once('.') {
        if first.len() == 10 && first.chars().all(|c| c.is_ascii_alphanumeric()) {
            if rest == lower_bundle_id || Some(rest) == last_two.as_deref() {
                return true;
            }
            if shapes.iter().any(|s| s == rest) {
                return true;
            }
        }
    }
    false
}

/// Tier 3: normalised name match against an app's `CFBundleName`,
/// `CFBundleDisplayName`, `CFBundleExecutable`, its `.app` stem, or its
/// bundle id's last component (depth-2 candidates additionally require the
/// vendor component to match too); a formula/tool's own name or bin names.
fn tier3_name_match(owners: &Owners, candidate: &Candidate) -> Vec<OwnerHit> {
    let cand_norm = normalise(&candidate.name);
    // App hits carry a rank so that when several apps share a name the
    // one *called* that wins: `Claude.app` over a helper whose CFBundleName
    // happens to be "Claude". 0 = bundle file stem, 1 = everything else.
    let mut app_hits: Vec<(u8, OwnerHit)> = Vec::new();
    let mut cli_hits = Vec::new();

    for app in &owners.apps {
        let stem = app
            .owner
            .path
            .as_deref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned());
        let mut names: Vec<String> = Vec::new();
        names.extend(app.bundle_name.clone());
        names.extend(app.display_name.clone());
        names.extend(app.executable.clone());
        names.extend(stem.clone());
        // The bundle id's last component is only evidence when it is
        // recognisably the app's name (`VSCode` ~ `Code`, `claudefordesktop`
        // ~ `Claude`); an unrelated one (`com.openai.codex` on ChatGPT.app)
        // would otherwise capture a different product's `~/.codex`.
        let last = last_component(&app.owner.key).to_string();
        if names
            .iter()
            .any(|n| related(&normalise(n), &normalise(&last)))
        {
            names.push(last);
        }
        names.extend(app.cask_names.clone());

        let name_matches = names.iter().any(|n| normalise(n) == cand_norm);
        let matched = match &candidate.vendor {
            Some(vendor) => {
                let vendor_matches = vendor_component(&app.owner.key)
                    .map(|v| normalise(&v) == normalise(vendor))
                    .unwrap_or(false);
                vendor_matches && name_matches
            }
            None => name_matches,
        };
        if matched {
            let rank = if stem.as_deref().map(normalise) == Some(cand_norm.clone()) {
                0
            } else {
                1
            };
            app_hits.push((
                rank,
                OwnerHit {
                    key: app.owner.key.clone(),
                    evidence: format!("`{}` matches the app's name", candidate.name),
                },
            ));
        }
    }
    let best = app_hits.iter().map(|(rank, _)| *rank).min();
    let app_hits: Vec<OwnerHit> = app_hits
        .into_iter()
        .filter(|(rank, _)| Some(*rank) == best)
        .map(|(_, hit)| hit)
        .collect();

    for formula in &owners.formulae {
        let name_matches = normalise(&formula.owner.name) == cand_norm
            || formula.bin_names.iter().any(|b| normalise(b) == cand_norm);
        if name_matches {
            cli_hits.push(OwnerHit {
                key: formula.owner.key.clone(),
                evidence: format!("`{}` matches the formula name", candidate.name),
            });
        }
    }

    for tool in &owners.tools {
        if normalise(&tool.owner.name) == cand_norm {
            cli_hits.push(OwnerHit {
                key: tool.owner.key.clone(),
                evidence: format!("`{}` matches the tool name", candidate.name),
            });
        }
    }

    // A name shared by an app and a CLI tool (`Claude.app` and the `claude`
    // npm global) is disambiguated by where the candidate lives: GUI apps
    // write under `~/Library`, command-line tools under `~/.<name>`,
    // `~/.cache`, `~/.config`, `~/.local`. Only when one side matched
    // nothing does the other keep the whole candidate.
    match (app_hits.is_empty(), cli_hits.is_empty()) {
        (false, false) if is_unix_style(candidate) => cli_hits,
        (false, false) => app_hits,
        (true, _) => cli_hits,
        (_, true) => app_hits,
    }
}

/// Whether a candidate sits in a dotfile-style location (`~/.x`, `~/.cache/x`,
/// `~/.config/x`, `~/.local/share/x`) rather than under `~/Library`.
fn is_unix_style(candidate: &Candidate) -> bool {
    candidate
        .path
        .components()
        .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
}

/// Tier 5: the curated last-resort table (`curated::CURATED`), matched
/// against the candidate's vendor component when it has one, else its own
/// name. `CuratedTarget::Owner` only fires when that owner actually exists
/// this scan.
fn tier5_curated(owners: &Owners, candidate: &Candidate) -> Vec<OwnerHit> {
    let name = candidate
        .vendor
        .as_deref()
        .unwrap_or(candidate.name.as_str());
    let lower = name.to_lowercase();
    let mut hits = Vec::new();
    for row in curated::CURATED {
        if row.name.to_lowercase() != lower {
            continue;
        }
        match row.target {
            CuratedTarget::Owner(key) => {
                if owner_exists(owners, key) {
                    hits.push(OwnerHit {
                        key: key.to_string(),
                        evidence: format!("`{name}` — {}", row.reason),
                    });
                }
            }
            CuratedTarget::VendorPrefix(prefix) => {
                for app in &owners.apps {
                    if app.owner.key.starts_with(prefix) {
                        hits.push(OwnerHit {
                            key: app.owner.key.clone(),
                            evidence: format!("`{name}` — {}", row.reason),
                        });
                    }
                }
            }
        }
    }
    hits
}

fn owner_exists(owners: &Owners, key: &str) -> bool {
    owners.apps.iter().any(|a| a.owner.key == key)
        || owners.formulae.iter().any(|f| f.owner.key == key)
        || owners.tools.iter().any(|t| t.owner.key == key)
        || owners.homebrew.as_ref().is_some_and(|h| h.key == key)
}

fn unattributed_claim(candidate: &Candidate) -> Claim {
    let reason = if candidate.name.starts_with("com.apple.") {
        "macOS system component".to_string()
    } else {
        format!("no owner matched `{}`", candidate.name)
    };
    Claim::new(
        candidate.path.clone(),
        model::UNATTRIBUTED_OWNER,
        candidate.parent_kind,
        EvidenceTier::Curated,
        reason,
    )
    .label(candidate.name.clone())
}

/// Lowercase, with spaces/`-`/`_`/`.` stripped — the shape a bundle id
/// (`com.google.Chrome`), an Info.plist name (`Google Chrome`), and a
/// directory name (`Google Chrome` or `google-chrome`) all reduce to.
fn normalise(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_' | '.'))
        .collect()
}

/// `com.google.Chrome` → `Some("google")` — the vendor label a depth-2
/// `<Vendor>/<Name>` candidate's `Vendor` component is compared against.
/// Two normalised names are related when one contains the other and the
/// shorter is long enough not to be noise (`code` ⊂ `vscode`, but not
/// `tv` ⊂ `activitymonitor`).
fn related(a: &str, b: &str) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    short.len() >= 4 && long.contains(short)
}

fn vendor_component(bundle_id: &str) -> Option<String> {
    bundle_id.split('.').nth(1).map(|s| s.to_string())
}

fn last_component(bundle_id: &str) -> &str {
    bundle_id.rsplit('.').next().unwrap_or(bundle_id)
}

/// Every owner's own bundle/Cellar/install dir, plus Homebrew's own cache,
/// logs, and prefix top-level dirs (the Cellar/Caskroom dirs nested under
/// the prefix are separate owners, claimed above by their own formula, so
/// they're deliberately excluded here — accounting subtracts them from
/// Homebrew's own claim wherever they nest under it).
fn owner_own_claims(env: &ResolveEnv<'_>, owners: &Owners) -> Vec<Claim> {
    let mut claims = Vec::new();

    for app in &owners.apps {
        if let Some(path) = &app.owner.path {
            claims.push(
                Claim::new(
                    path.clone(),
                    app.owner.key.clone(),
                    EntryKind::AppBundle,
                    EvidenceTier::Exact,
                    "the app bundle",
                )
                .label(app.owner.name.clone()),
            );
        }
    }

    for formula in &owners.formulae {
        if let Some(path) = &formula.owner.path {
            claims.push(
                Claim::new(
                    path.clone(),
                    formula.owner.key.clone(),
                    EntryKind::AppBundle,
                    EvidenceTier::Exact,
                    "Cellar",
                )
                .label(formula.owner.name.clone()),
            );
        }
    }

    for tool in &owners.tools {
        if let Some(path) = &tool.owner.path {
            claims.push(
                Claim::new(
                    path.clone(),
                    tool.owner.key.clone(),
                    EntryKind::AppBundle,
                    EvidenceTier::Exact,
                    "install directory",
                )
                .label(tool.owner.name.clone()),
            );
        }
        for extra in &tool.extra_paths {
            claims.push(
                Claim::new(
                    extra.clone(),
                    tool.owner.key.clone(),
                    EntryKind::AppBundle,
                    EvidenceTier::Exact,
                    "shared store directory",
                )
                .label(tool.owner.name.clone()),
            );
        }
    }

    if let Some(homebrew) = &owners.homebrew {
        claims.push(
            Claim::new(
                env.paths.home.join("Library/Caches/Homebrew"),
                homebrew.key.clone(),
                EntryKind::Cache,
                EvidenceTier::Exact,
                "Homebrew's own cache",
            )
            .label("Homebrew".to_string()),
        );
        claims.push(
            Claim::new(
                env.paths.home.join("Library/Logs/Homebrew"),
                homebrew.key.clone(),
                EntryKind::Logs,
                EvidenceTier::Exact,
                "Homebrew's own logs",
            )
            .label("Homebrew".to_string()),
        );
        if let Some(prefix) = &homebrew.path {
            const PREFIX_DIRS: &[&str] = &[
                "bin",
                "lib",
                "share",
                "opt",
                "var",
                "etc",
                "Library",
                "Frameworks",
                "include",
                "sbin",
                "Homebrew",
            ];
            for dir in PREFIX_DIRS {
                claims.push(
                    Claim::new(
                        prefix.join(dir),
                        homebrew.key.clone(),
                        EntryKind::AppBundle,
                        EvidenceTier::Exact,
                        "Homebrew prefix",
                    )
                    .label("Homebrew".to_string()),
                );
            }
        }
    }

    claims
}

/// A formula that other installed formulae directly depend on
/// (`meta.dependents`) has its Cellar dir claimed again for each dependent,
/// on top of its own claim above — the path ends up with `1 +
/// dependents.len()` owners, so accounting shares it that many ways instead
/// of charging it wholly to the formula itself.
fn formula_sharing_claims(owners: &Owners) -> Vec<Claim> {
    let mut claims = Vec::new();
    for formula in &owners.formulae {
        let Some(path) = &formula.owner.path else {
            continue;
        };
        for dependent_name in &formula.dependents {
            let Some(dependent) = owners
                .formulae
                .iter()
                .find(|f| &f.owner.name == dependent_name)
            else {
                continue;
            };
            claims.push(
                Claim::new(
                    path.clone(),
                    dependent.owner.key.clone(),
                    EntryKind::AppBundle,
                    EvidenceTier::Exact,
                    format!("dependency of {dependent_name}"),
                )
                .label(formula.owner.name.clone()),
            );
        }
    }
    claims
}

/// One `lsof`/`ps` pass: which (owner key, candidate path) pairs a running
/// process of that owner's app has a file open under. Best-effort — `None`
/// from either command (no Tokio runtime, command missing, timeout) simply
/// yields no observed hits, same as any other degraded scanner input.
fn observed_opens(
    env: &ResolveEnv<'_>,
    owners: &Owners,
    candidates: &[Candidate],
) -> HashSet<(String, PathBuf)> {
    let mut result = HashSet::new();
    if owners.apps.is_empty() || candidates.is_empty() {
        return result;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return result;
    };
    let runner = env.runner;

    let (ps_out, lsof_out) = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let _guard = handle.enter();
                let ps = run_blocking(runner, "ps", &["-axo", "pid,comm"]);
                let user = std::env::var("USER").unwrap_or_default();
                let lsof = run_blocking(
                    runner,
                    "lsof",
                    &["-a", "-u", &user, "-d", "^txt,^mem", "-F", "pn"],
                );
                (ps, lsof)
            })
            .join()
            .unwrap_or((None, None))
    });
    let (Some(ps_out), Some(lsof_out)) = (ps_out, lsof_out) else {
        return result;
    };

    let procs = parse_ps_pid_comm(&ps_out);
    let opens = parse_lsof_pn(&lsof_out);

    let mut pid_owner: HashMap<u32, String> = HashMap::new();
    for (pid, comm) in &procs {
        for app in &owners.apps {
            if let Some(path) = &app.owner.path {
                if comm.starts_with(&*path.to_string_lossy()) {
                    pid_owner.insert(*pid, app.owner.key.clone());
                    break;
                }
            }
        }
    }
    if pid_owner.is_empty() {
        return result;
    }

    for (pid, opened_path) in &opens {
        let Some(owner_key) = pid_owner.get(pid) else {
            continue;
        };
        for candidate in candidates {
            if opened_path.starts_with(&candidate.path) {
                result.insert((owner_key.clone(), candidate.path.clone()));
            }
        }
    }

    result
}

fn run_blocking(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> Option<String> {
    let token = tokio_util::sync::CancellationToken::new();
    let result = tokio::runtime::Handle::current().block_on(tokio::time::timeout(
        Duration::from_secs(10),
        runner.run(program, args, &token),
    ));
    match result {
        Ok(Ok(out)) if out.success() => Some(out.stdout_str().into_owned()),
        _ => None,
    }
}

/// `ps -axo pid,comm`'s rows, skipping the header line. `comm` is the full
/// executable path on macOS, which may itself contain spaces (`Google
/// Chrome.app/...`), so only the leading whitespace-delimited pid is split
/// off.
fn parse_ps_pid_comm(output: &str) -> Vec<(u32, String)> {
    output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid_str, rest) = line.split_once(char::is_whitespace)?;
            let pid: u32 = pid_str.parse().ok()?;
            Some((pid, rest.trim().to_string()))
        })
        .collect()
}

/// `lsof -F pn`'s output: a `p<pid>` line starts a block, each following
/// `n<path>` line is one file that pid has open.
fn parse_lsof_pn(output: &str) -> Vec<(u32, PathBuf)> {
    let mut out = Vec::new();
    let mut current_pid: Option<u32> = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            current_pid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix('n') {
            if let Some(pid) = current_pid {
                out.push((pid, PathBuf::from(rest)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::apps::owners::{AppOwner, FormulaOwner};
    use crate::attribution::model::{Owner, OwnerKind};

    fn app_owner(key: &str, path: &str) -> AppOwner {
        AppOwner {
            owner: Owner {
                key: key.to_string(),
                kind: OwnerKind::App,
                name: key.to_string(),
                path: Some(PathBuf::from(path)),
            },
            aliases: Vec::new(),
            cask_names: Vec::new(),
            bundle_name: None,
            display_name: None,
            executable: None,
        }
    }

    fn candidate(name: &str, kind: EntryKind, vendor: Option<&str>) -> Candidate {
        Candidate {
            path: PathBuf::from(format!("/Users/dev/Library/x/{name}")),
            name: name.to_string(),
            parent_kind: kind,
            vendor: vendor.map(str::to_string),
            is_file: false,
        }
    }

    fn owners_with(apps: Vec<AppOwner>) -> Owners {
        Owners {
            apps,
            formulae: Vec::new(),
            tools: Vec::new(),
            homebrew: None,
        }
    }

    fn empty_groups() -> HashMap<PathBuf, (Vec<String>, bool)> {
        HashMap::new()
    }

    fn empty_observed() -> HashSet<(String, PathBuf)> {
        HashSet::new()
    }

    #[test]
    fn app_named_after_the_candidate_beats_a_helper_with_the_same_bundle_name() {
        let claude = app_owner("com.anthropic.claudefordesktop", "/Applications/Claude.app");
        let mut helper = app_owner(
            "com.anthropic.claude-code-url-handler",
            "/Users/dev/Applications/Claude Code URL Handler.app",
        );
        helper.bundle_name = Some("Claude".to_string());
        let owners = owners_with(vec![claude, helper]);
        let cand = candidate("Claude", EntryKind::AppSupport, None);
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::NameMatch);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key, "com.anthropic.claudefordesktop");
    }

    #[test]
    fn unrelated_bundle_id_last_component_does_not_match() {
        // ChatGPT.app's bundle id is `com.openai.codex`; `~/.codex` is the
        // Codex CLI's, not ChatGPT's.
        let owners = owners_with(vec![app_owner(
            "com.openai.codex",
            "/Applications/ChatGPT.app",
        )]);
        let mut cand = candidate(".codex", EntryKind::DotDir, None);
        cand.path = PathBuf::from("/Users/dev/.codex");
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert!(hits.is_empty());
    }

    #[test]
    fn app_and_cli_tool_sharing_a_name_split_by_location() {
        use crate::attribution::apps::owners::ToolOwner;
        let mut owners = owners_with(vec![app_owner(
            "com.anthropic.claudefordesktop",
            "/Applications/Claude.app",
        )]);
        owners.tools.push(ToolOwner {
            owner: Owner {
                key: "tool:claude".to_string(),
                kind: OwnerKind::Tool,
                name: "claude".to_string(),
                path: None,
            },
            extra_paths: Vec::new(),
        });
        let lib = candidate("Claude", EntryKind::AppSupport, None);
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &lib);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key, "com.anthropic.claudefordesktop");

        let mut dot = candidate(".claude", EntryKind::DotDir, None);
        dot.path = PathBuf::from("/Users/dev/.claude");
        dot.name = "claude".to_string();
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &dot);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key, "tool:claude");
    }

    #[test]
    fn depth2_vendor_name_matches_by_vendor_and_bundle_last_component() {
        let owners = owners_with(vec![app_owner(
            "com.google.Chrome",
            "/Applications/Google Chrome.app",
        )]);
        let cand = candidate("Chrome", EntryKind::AppSupport, Some("Google"));
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::NameMatch);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key, "com.google.Chrome");
    }

    #[test]
    fn depth2_wrong_vendor_does_not_match() {
        let owners = owners_with(vec![app_owner(
            "com.google.Chrome",
            "/Applications/Google Chrome.app",
        )]);
        let cand = candidate("Chrome", EntryKind::AppSupport, Some("Microsoft"));
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert!(hits.is_empty());
    }

    #[test]
    fn bundle_name_matches_code_to_vscode() {
        let mut owner = app_owner(
            "com.microsoft.VSCode",
            "/Applications/Visual Studio Code.app",
        );
        owner.bundle_name = Some("Code".to_string());
        let owners = owners_with(vec![owner]);
        let cand = candidate("Code", EntryKind::AppSupport, None);
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::NameMatch);
        assert_eq!(hits[0].key, "com.microsoft.VSCode");
    }

    #[test]
    fn alias_from_a_nested_bundle_id_matches_exactly() {
        let mut owner = app_owner("com.openai.chatgpt", "/Applications/ChatGPT.app");
        owner.aliases.push("com.openai.codex".to_string());
        let owners = owners_with(vec![owner]);
        let cand = candidate("com.openai.codex", EntryKind::Container, None);
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::Exact);
        assert_eq!(hits[0].key, "com.openai.chatgpt");
    }

    #[test]
    fn entitlement_group_matches_exactly() {
        let owner = app_owner(
            "io.robbie.homeassistant",
            "/Applications/Home Assistant.app",
        );
        let owners = owners_with(vec![owner]);
        let mut groups = empty_groups();
        groups.insert(
            PathBuf::from("/Applications/Home Assistant.app"),
            (vec!["group.io.robbie.homeassistant".to_string()], true),
        );
        let cand = candidate(
            "group.io.robbie.homeassistant",
            EntryKind::GroupContainer,
            None,
        );
        let (hits, tier) = resolve_candidate(&owners, &groups, &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::Exact);
        assert_eq!(hits[0].key, "io.robbie.homeassistant");
    }

    #[test]
    fn group_heuristic_matches_team_prefixed_group_without_entitlements() {
        let owner = app_owner(
            "io.robbie.homeassistant",
            "/Applications/Home Assistant.app",
        );
        let owners = owners_with(vec![owner]);
        let cand = candidate(
            "ABCDE12345.group.io.robbie.homeassistant",
            EntryKind::GroupContainer,
            None,
        );
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::Exact);
        assert_eq!(hits[0].key, "io.robbie.homeassistant");
    }

    #[test]
    fn docker_desktop_falls_through_to_curated() {
        let owner = app_owner("com.docker.docker", "/Applications/Docker.app");
        let owners = owners_with(vec![owner]);
        let cand = candidate("Docker Desktop", EntryKind::AppSupport, None);
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::Curated);
        assert_eq!(hits[0].key, "com.docker.docker");
    }

    #[test]
    fn curated_owner_row_is_skipped_when_the_owner_does_not_exist() {
        let owners = owners_with(Vec::new());
        let cand = candidate("Docker Desktop", EntryKind::AppSupport, None);
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert!(hits.is_empty());
    }

    #[test]
    fn vendor_prefix_curated_row_shares_across_every_matching_app() {
        let owners = owners_with(vec![
            app_owner("com.adobe.Photoshop", "/Applications/Adobe Photoshop.app"),
            app_owner(
                "com.adobe.Illustrator",
                "/Applications/Adobe Illustrator.app",
            ),
            app_owner("com.other.App", "/Applications/Other.app"),
        ]);
        let cand = candidate("Adobe", EntryKind::AppSupport, None);
        let (hits, tier) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert_eq!(tier, EvidenceTier::Curated);
        let keys: HashSet<_> = hits.into_iter().map(|h| h.key).collect();
        assert_eq!(
            keys,
            HashSet::from([
                "com.adobe.Photoshop".to_string(),
                "com.adobe.Illustrator".to_string()
            ])
        );
    }

    #[test]
    fn unmatched_candidate_is_unattributed_with_a_name_reason() {
        let owners = owners_with(Vec::new());
        let cand = candidate("SomeRandomVendor", EntryKind::AppSupport, None);
        let (hits, _) = resolve_candidate(&owners, &empty_groups(), &empty_observed(), &cand);
        assert!(hits.is_empty());
        let claim = unattributed_claim(&cand);
        assert_eq!(claim.owner, model::UNATTRIBUTED_OWNER);
        assert_eq!(claim.evidence, "no owner matched `SomeRandomVendor`");
    }

    #[test]
    fn unmatched_apple_system_cache_gets_a_system_component_reason() {
        let cand = candidate("com.apple.Something", EntryKind::Cache, None);
        let claim = unattributed_claim(&cand);
        assert_eq!(claim.evidence, "macOS system component");
    }

    #[test]
    fn formula_sharing_claims_split_a_dependency_among_its_dependents() {
        let leaf = FormulaOwner {
            owner: Owner {
                key: "formula:libidn2".to_string(),
                kind: OwnerKind::Formula,
                name: "libidn2".to_string(),
                path: Some(PathBuf::from("/opt/homebrew/Cellar/libidn2")),
            },
            bin_names: vec!["libidn2".to_string()],
            dependents: vec!["wget".to_string()],
        };
        let dependent = FormulaOwner {
            owner: Owner {
                key: "formula:wget".to_string(),
                kind: OwnerKind::Formula,
                name: "wget".to_string(),
                path: Some(PathBuf::from("/opt/homebrew/Cellar/wget")),
            },
            bin_names: vec!["wget".to_string()],
            dependents: Vec::new(),
        };
        let owners = Owners {
            apps: Vec::new(),
            formulae: vec![leaf, dependent],
            tools: Vec::new(),
            homebrew: None,
        };
        let claims = formula_sharing_claims(&owners);
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].path,
            PathBuf::from("/opt/homebrew/Cellar/libidn2")
        );
        assert_eq!(claims[0].owner, "formula:wget");
    }

    #[test]
    fn parse_lsof_pn_associates_paths_with_the_preceding_pid() {
        let out =
            "p123\nn/Users/dev/Library/Caches/Foo\nn/tmp/x\np456\nn/Users/dev/Library/Logs/Bar";
        let parsed = parse_lsof_pn(out);
        assert_eq!(
            parsed,
            vec![
                (123, PathBuf::from("/Users/dev/Library/Caches/Foo")),
                (123, PathBuf::from("/tmp/x")),
                (456, PathBuf::from("/Users/dev/Library/Logs/Bar")),
            ]
        );
    }

    #[test]
    fn parse_ps_pid_comm_skips_the_header_and_splits_on_the_first_gap() {
        let out = "  PID COMM\n  123 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n 456 /bin/zsh";
        let parsed = parse_ps_pid_comm(out);
        assert_eq!(
            parsed,
            vec![
                (
                    123,
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string()
                ),
                (456, "/bin/zsh".to_string()),
            ]
        );
    }

    #[test]
    fn normalise_ignores_case_spaces_and_punctuation() {
        assert_eq!(normalise("Google Chrome"), normalise("google-chrome"));
        assert_eq!(normalise("com.google.Chrome"), "comgooglechrome");
    }
}
