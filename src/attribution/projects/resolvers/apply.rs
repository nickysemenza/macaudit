//! The one evaluator for `rules.rs`'s three row shapes: `lookups` (project →
//! claims), `reverse_links` (once per scan), `baselines` (once per scan).
//! Template expansion, directory-listing selection policies, and the
//! project-membership test all live here exactly once — see the module doc
//! in `mod.rs` for the drift these fixes replace.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::attribution::model::{
    Claim, EvidenceTier, ResolveEnv, BASELINE_OWNER, UNATTRIBUTED_OWNER,
};
use crate::attribution::paths as attribution_paths;
use crate::attribution::projects::{Project, ProjectIndex, ARTIFACT_DIR_NAMES};
use crate::model::{FindingId, FindingKind, ScannerId};
use crate::scan::walk::listing::{self, Kind};
use crate::scan::walk::DirNode;

use super::parsers;
use super::rules::{
    self, Baseline, ClaimAt, Extract, Extracted, Fallback, Find, Flags, Key, Label, Lookup,
    Matcher, PathFrom, PinSource, ProjectField, ReverseLink, Scan, Select, Source, Target, Trigger,
};

/// Project membership — the ONLY implementation, shared by every row and
/// join (fixes the docker/pnpm resolvers that used to check `project.root`
/// only, ignoring worktrees).
pub fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

fn matches_bundle_id(project_ids: &[String], id: &str) -> bool {
    project_ids
        .iter()
        .any(|p| id == p || id.starts_with(&format!("{p}.")))
}

// ---------------------------------------------------------------------
// Template expansion
// ---------------------------------------------------------------------

/// Replace every `{token}` in `template` with `tokens[token]`; an unknown
/// token is left verbatim (so a row author's typo is visible, not silently
/// eaten).
fn substitute(template: &str, tokens: &HashMap<&str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        let mut name = String::new();
        let mut closed = false;
        for c2 in chars.by_ref() {
            if c2 == '}' {
                closed = true;
                break;
            }
            name.push(c2);
        }
        if closed {
            match tokens.get(name.as_str()) {
                Some(v) => out.push_str(v),
                None => {
                    out.push('{');
                    out.push_str(&name);
                    out.push('}');
                }
            }
        } else {
            out.push('{');
            out.push_str(&name);
        }
    }
    out
}

/// Tokens available while resolving a `Target` (before a specific path is
/// known): `{name}` `{version}` `{key}` `{basename}` (from `Key::extra`)
/// `{name-flat}`.
fn target_tokens(key: &Key) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    m.insert("name", key.name.clone());
    m.insert("version", key.version.clone());
    m.insert("key", key.name.clone());
    m.insert("basename", key.extra.clone().unwrap_or_default());
    m.insert("name-flat", key.name.replace('/', "-"));
    m
}

/// Tokens available once a `Target` has resolved to a real path, for
/// evidence/label templates: everything `target_tokens` has, plus
/// `{basename}` overridden to the resolved path's own file name, `{file}`/
/// `{rel}`/`{relfile}` from the triggering manifest.
fn label_tokens(
    base: &HashMap<&'static str, String>,
    file: &str,
    rel: &str,
    path: &Path,
) -> HashMap<&'static str, String> {
    let mut m = base.clone();
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    m.insert("basename", basename);
    m.insert("file", file.to_string());
    m.insert("rel", rel.to_string());
    let relfile = if rel.is_empty() {
        file.to_string()
    } else {
        format!("{rel}/{file}")
    };
    m.insert("relfile", relfile);
    m
}

/// Expand a single `{a,b,c}` alternation group in `component`, if present.
fn expand_brace(component: &str) -> Option<Vec<String>> {
    let open = component.find('{')?;
    let close = component[open..].find('}')? + open;
    let prefix = &component[..open];
    let inner = &component[open + 1..close];
    let suffix = &component[close + 1..];
    Some(
        inner
            .split(',')
            .map(|opt| format!("{prefix}{opt}{suffix}"))
            .collect(),
    )
}

/// Shell-style `*` wildcards (any number, anywhere) against one
/// directory-entry name: `rollout-*.jsonl`, `*DeviceSupport`, `metadata*`.
fn glob_match(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty(); // no `*` at all: exact match
    };
    for mid in parts {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// Expand `~`, `{a,b,c}` alternation, and `*`/`prefix*`/`*suffix` glob
/// components (each against one real directory listing) in a (token-
/// already-substituted) path template. The result is not existence-
/// filtered — callers gate on `exists()` themselves where that's the row's
/// policy.
fn glob_expand(template: &str, home: &Path) -> Vec<PathBuf> {
    let (mut candidates, rest): (Vec<PathBuf>, &str) =
        if let Some(rest) = template.strip_prefix("~/") {
            (vec![home.to_path_buf()], rest)
        } else if template == "~" {
            return vec![home.to_path_buf()];
        } else if let Some(rest) = template.strip_prefix('/') {
            (vec![PathBuf::from("/")], rest)
        } else {
            (vec![home.to_path_buf()], template)
        };

    for component in rest.split('/') {
        if component.is_empty() {
            continue;
        }
        if let Some(options) = expand_brace(component) {
            candidates = candidates
                .iter()
                .flat_map(|c| options.iter().map(move |o| c.join(o)))
                .collect();
        } else if component.contains('*') {
            let mut next = Vec::new();
            for cand in &candidates {
                let Ok(read) = std::fs::read_dir(cand) else {
                    continue;
                };
                for entry in read.filter_map(|e| e.ok()) {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if glob_match(component, &name_str) {
                        next.push(cand.join(&name));
                    }
                }
            }
            candidates = next;
        } else {
            candidates = candidates.into_iter().map(|c| c.join(component)).collect();
        }
    }
    candidates
}

// ---------------------------------------------------------------------
// LOOKUP
// ---------------------------------------------------------------------

pub fn lookups(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    for row in rules::LOOKUP {
        claims.extend(eval_lookup(row, project, env));
    }
    claims
}

fn eval_lookup(row: &Lookup, project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut out = Vec::new();
    match &row.trigger {
        Trigger::Always => {
            out.extend(eval_target(
                row,
                &Key::default(),
                "",
                "",
                None,
                project,
                env,
            ));
        }
        Trigger::Exists(rel) => {
            let path = project.root.join(rel);
            if path.exists() {
                out.extend(eval_target(
                    row,
                    &Key::default(),
                    "",
                    "",
                    Some(&path),
                    project,
                    env,
                ));
            }
        }
        Trigger::Pin { sources, normalise } => {
            if let Some(pin) = resolve_pin(sources, *normalise, project, env) {
                let key = Key {
                    name: pin.clone(),
                    version: pin,
                    extra: None,
                };
                out.extend(eval_target(row, &key, "", "", None, project, env));
            }
        }
        Trigger::Manifest { find, parse } => match find {
            Find::Root(name, cap) => {
                if let Some(text) = env.read_head(&project.root.join(name), *cap) {
                    for key in parse(&text) {
                        out.extend(eval_target(row, &key, name, "", None, project, env));
                    }
                }
            }
            Find::Subtree { names, depth, cap } => {
                for path in find_in_subtree(&project.root, names, *depth, env) {
                    let Some(text) = env.read_head(&path, *cap) else {
                        continue;
                    };
                    let file = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let rel = relative_dir_label(&project.root, &path);
                    for key in parse(&text) {
                        out.extend(eval_target(row, &key, &file, &rel, None, project, env));
                    }
                }
            }
        },
        Trigger::Field(field) => {
            let names: Vec<String> = match field {
                ProjectField::Names => project.names.clone(),
                ProjectField::BundleIds => project.bundle_ids.clone(),
            };
            for name in names {
                let key = Key {
                    name,
                    version: String::new(),
                    extra: None,
                };
                out.extend(eval_target(row, &key, "", "", None, project, env));
            }
        }
    }
    out
}

/// The first source that yields a value `normalise` accepts.
fn resolve_pin(
    sources: &[PinSource],
    normalise: fn(&str) -> Option<String>,
    project: &Project,
    env: &ResolveEnv<'_>,
) -> Option<String> {
    for source in sources {
        let raw: Option<String> = match source {
            PinSource::Line(file) => env
                .read_head(&project.root.join(file), rules::MANIFEST_CAP)
                .and_then(|t| parsers::first_bare_line(&t)),
            PinSource::TomlKey(file, key) => env
                .read_head(&project.root.join(file), rules::MANIFEST_CAP)
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| parsers::key_value_field(l.trim(), key))
                }),
            PinSource::JsonPath(file, path) => env
                .read_head(&project.root.join(file), rules::MANIFEST_CAP)
                .and_then(|t| {
                    let json: serde_json::Value = serde_json::from_str(&t).ok()?;
                    let mut cur = &json;
                    for k in *path {
                        cur = cur.get(k)?;
                    }
                    cur.as_str().map(str::to_string)
                }),
        };
        if let Some(raw) = raw {
            if let Some(pin) = normalise(&raw) {
                return Some(pin);
            }
        }
    }
    None
}

/// Evaluate `row.target` for one `Key`, producing zero or more claims — the
/// generic per-path evidence/label templating (`label_tokens`) is shared by
/// every `Target` variant, including `Derive`.
fn eval_target(
    row: &Lookup,
    key: &Key,
    file: &str,
    rel: &str,
    trigger_path: Option<&Path>,
    project: &Project,
    env: &ResolveEnv<'_>,
) -> Vec<Claim> {
    let home = &env.paths.home;
    let t_tokens = target_tokens(key);
    let resolved: Vec<(PathBuf, Option<FindingId>)> = match &row.target {
        Target::Path(templates) => {
            if templates.is_empty() {
                trigger_path
                    .map(|p| (p.to_path_buf(), None))
                    .into_iter()
                    .collect()
            } else {
                templates
                    .iter()
                    .flat_map(|t| glob_expand(&substitute(t, &t_tokens), home))
                    .filter(|p| p.exists())
                    .map(|p| (p, None))
                    .collect()
            }
        }
        Target::Match {
            dirs,
            prefix,
            select,
        } => eval_match(dirs, prefix, select, &t_tokens, home, row.flags)
            .into_iter()
            .map(|p| (p, None))
            .collect(),
        Target::Finding {
            scanner,
            kind,
            key_meta,
            path,
        } => {
            let Some(finding) = env.findings(*scanner).iter().find(|f| {
                f.kind == *kind
                    && key_meta
                        .iter()
                        .any(|m| f.meta_str(m) == Some(key.name.as_str()))
            }) else {
                return Vec::new();
            };
            let paths: Vec<PathBuf> = match path {
                PathFrom::Path => finding.path.clone().into_iter().collect(),
                PathFrom::AppPaths => finding
                    .meta
                    .get("app_paths")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(PathBuf::from)
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            paths.into_iter().map(|p| (p, Some(finding.id))).collect()
        }
        Target::Derive(f) => f(key, project, env)
            .into_iter()
            .map(|p| (p, None))
            .collect(),
    };

    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::with_capacity(resolved.len());
    for (path, finding_id) in resolved {
        let l_tokens = label_tokens(&t_tokens, file, rel, &path);
        let evidence = substitute(row.evidence, &l_tokens);
        let label = substitute(row.label, &l_tokens);
        let mut claim = Claim::new(path, owner.clone(), row.kind, row.tier, evidence).label(label);
        if row.flags & rules::CLONE_OF_STORE != 0 {
            claim = claim.clone_of_store();
        }
        if let Some(id) = finding_id {
            claim = claim.finding(id);
        }
        if let Some(eco) = row.ecosystem {
            claim = claim.ecosystem(eco);
        }
        claims.push(claim);
    }
    claims
}

/// One directory listing (across every root in `dirs`) filtered by
/// `prefix`, selected by `select`. `dirs.len() > 1` merges every root's
/// entries into one candidate set before selecting (node's five version
/// roots): the first root wins a name collision, matching the historical
/// "first found" precedence.
fn eval_match(
    dirs: &[&str],
    prefix: &str,
    select: &Select,
    tokens: &HashMap<&str, String>,
    home: &Path,
    flags: Flags,
) -> Vec<PathBuf> {
    let prefix = substitute(prefix, tokens);
    // (compare-name, path) for every match, across every listed dir — the
    // same name can legitimately appear under two dirs (cargo's
    // `git/checkouts/x-hash` and `git/db/x-hash`) and both are claimed.
    let mut matches: Vec<(String, PathBuf)> = Vec::new();
    for dir_template in dirs {
        for dir in glob_expand(&substitute(dir_template, tokens), home) {
            let Ok(read) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in read.filter_map(|e| e.ok()) {
                let mut name = entry.file_name().to_string_lossy().into_owned();
                if flags & rules::V_PREFIX != 0 && !name.starts_with('v') {
                    name = format!("v{name}");
                }
                let (cmp_name, cmp_prefix) = if flags & rules::CASE_INSENSITIVE != 0 {
                    (name.to_ascii_lowercase(), prefix.to_ascii_lowercase())
                } else {
                    (name.clone(), prefix.clone())
                };
                if !cmp_name.starts_with(&cmp_prefix) {
                    continue;
                }
                matches.push((name, entry.path()));
            }
        }
    }
    let path_named = |name: &str| {
        matches
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
    };

    match select {
        Select::All => matches.into_iter().map(|(_, p)| p).collect(),
        Select::First => {
            let first = matches.iter().map(|(n, _)| n).min().cloned();
            first.and_then(|n| path_named(&n)).into_iter().collect()
        }
        Select::MaxSemver => {
            let pin = tokens.get("key").cloned().unwrap_or_default();
            let names: Vec<String> = matches.iter().map(|(n, _)| n.clone()).collect();
            let (pin, candidates) = if prefix.is_empty() {
                (pin, names)
            } else {
                let tails: Vec<String> = names
                    .iter()
                    .filter_map(|n| n.strip_prefix(prefix.as_str()).map(str::to_string))
                    .collect();
                (pin, tails)
            };
            parsers::newest_matching_version(&pin, &candidates)
                .map(|tail| format!("{prefix}{tail}"))
                .and_then(|winner| path_named(&winner))
                .into_iter()
                .collect()
        }
    }
}

/// Every `names`-matching file found walking `root`'s subtree (via the
/// walked tree + one `listing::list` per directory) down to `depth`,
/// pruning hidden and `ARTIFACT_DIR_NAMES` directories.
fn find_in_subtree(
    root: &Path,
    names: &[&str],
    depth: usize,
    env: &ResolveEnv<'_>,
) -> Vec<PathBuf> {
    let Some(root_node) = attribution_paths::node_at(env.trees, root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, &DirNode, usize)> = vec![(root.to_path_buf(), root_node, 0)];
    while let Some((path, node, d)) = stack.pop() {
        if let Ok(dir_listing) = listing::list(&path) {
            for entry in &dir_listing.entries {
                if entry.kind == Kind::Dir {
                    continue;
                }
                let Some(name) = entry.name.to_str() else {
                    continue;
                };
                if names.iter().any(|pat| glob_match(pat, name)) {
                    out.push(path.join(name));
                }
            }
        }
        if d >= depth {
            continue;
        }
        for child in node.children.iter() {
            let cname = &*child.name;
            if cname.starts_with('.') || ARTIFACT_DIR_NAMES.contains(&cname) {
                continue;
            }
            stack.push((path.join(cname), child, d + 1));
        }
    }
    out.sort();
    out
}

/// A manifest's directory relative to the project root, e.g.
/// `"recipebridge"` — empty for a root-level manifest.
fn relative_dir_label(root: &Path, file_path: &Path) -> String {
    let dir = file_path.parent().unwrap_or(root);
    if dir == root {
        String::new()
    } else {
        dir.strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------
// REVERSE
// ---------------------------------------------------------------------

pub fn reverse_links(env: &ResolveEnv<'_>, index: &ProjectIndex) -> Vec<Claim> {
    let mut claims = Vec::new();
    for row in rules::REVERSE {
        claims.extend(eval_reverse(row, env, index));
    }
    attach_matching_fs_findings(&mut claims, env);
    claims
}

fn scan_dirs(roots: &[&str], depth: usize, skip: &[&str], home: &Path) -> Vec<PathBuf> {
    let resolved_roots: Vec<PathBuf> = roots.iter().flat_map(|r| glob_expand(r, home)).collect();
    if depth == 0 {
        return resolved_roots;
    }
    let mut out = Vec::new();
    let mut frontier = resolved_roots;
    for _ in 0..depth {
        let mut next = Vec::new();
        for dir in &frontier {
            let Ok(read) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in read.filter_map(|e| e.ok()) {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if !file_type.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                if skip.iter().any(|s| name == std::ffi::OsStr::new(s)) {
                    continue;
                }
                next.push(entry.path());
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

fn scan_files(roots: &[&str], name: Option<&str>, cap: usize, home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited = 0usize;
    let mut stack: Vec<PathBuf> = roots.iter().flat_map(|r| glob_expand(r, home)).collect();
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.filter_map(|e| e.ok()) {
            if visited >= cap {
                return out;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            visited += 1;
            let matches = match name {
                None => true,
                Some(pattern) => path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| glob_match(pattern, n)),
            };
            if matches {
                out.push(path);
            }
        }
    }
    out
}

fn claim_at(entry: &Path, at: &ClaimAt) -> PathBuf {
    match at {
        ClaimAt::Entry => entry.to_path_buf(),
        ClaimAt::Parent => entry.parent().unwrap_or(entry).to_path_buf(),
    }
}

fn eval_reverse(row: &ReverseLink, env: &ResolveEnv<'_>, index: &ProjectIndex) -> Vec<Claim> {
    let home = &env.paths.home;
    let entries = match &row.scan {
        Scan::Dirs { roots, depth, skip } => scan_dirs(roots, *depth, skip, home),
        Scan::Files { roots, name, cap } => scan_files(roots, *name, *cap, home),
    };

    if let Extract::SymlinkTargets { subdir } = &row.extract {
        return eval_symlink_targets(row, &entries, subdir, index);
    }

    let mut claims = Vec::new();
    for entry in &entries {
        match row.matcher {
            Matcher::PathUnderProject => {
                if let Some(extracted) = extract_one(&row.extract, entry, env) {
                    let tree_path = attribution_paths::tree_path(&extracted.path);
                    let gone = row.stale.is_some() && !tree_path.exists();
                    if let Some(project) = index.owner_of(&tree_path) {
                        // Still the project's (a deleted worktree's
                        // DerivedData is that repo's junk), but flagged so
                        // the UI shows it as reclaimable.
                        let claim = build_reverse_claim(row, entry, project, &extracted, None);
                        claims.push(if gone { claim.stale() } else { claim });
                    } else if gone {
                        claims.push(build_stale_claim(row, entry, &tree_path));
                    }
                    // else: extracted, but neither owned by a known project
                    // nor stale (still exists on disk, just untracked) — no
                    // claim, same as the original per-project resolvers
                    // silently skipping.
                } else if matches!(row.fallback, Some(Fallback::EncodedProjectDir)) {
                    if let Some(project) = fallback_encoded_project_dir(entry, index) {
                        let owner = project.root.to_string_lossy().into_owned();
                        let claim_path = claim_at(entry, &row.claim);
                        let tokens = reverse_tokens(&claim_path, "", "");
                        let label = substitute(row.label, &tokens);
                        claims.push(
                            Claim::new(
                                claim_path,
                                owner,
                                row.kind,
                                EvidenceTier::NameMatch,
                                "encoded project path",
                            )
                            .label(label)
                            .ecosystem(row.ecosystem.unwrap_or_default()),
                        );
                    }
                }
            }
            Matcher::BundleId => {
                if let Some(extracted) = extract_one(&row.extract, entry, env) {
                    let bundle_id = extracted.path.to_string_lossy().into_owned();
                    if let Some(project) = index
                        .projects()
                        .iter()
                        .find(|p| matches_bundle_id(&p.bundle_ids, &bundle_id))
                    {
                        claims.push(build_reverse_claim(
                            row,
                            entry,
                            project,
                            &extracted,
                            Some(&bundle_id),
                        ));
                    }
                }
            }
        }
    }
    claims
}

fn reverse_tokens(
    claim_path: &Path,
    bundle_id: &str,
    device: &str,
) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    // The same trailing-`-hash` convention DerivedData's own names use;
    // harmless for rows whose entries don't have one (no trailing `-` at
    // all leaves the name unchanged).
    let basename = claim_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let basename = basename
        .rsplit_once('-')
        .map(|(n, _)| n.to_string())
        .unwrap_or(basename);
    m.insert("basename", basename);
    m.insert("bundle_id", bundle_id.to_string());
    m.insert("device", device.to_string());
    m
}

fn build_reverse_claim(
    row: &ReverseLink,
    entry: &Path,
    project: &Project,
    extracted: &Extracted,
    bundle_id: Option<&str>,
) -> Claim {
    let claim_path = claim_at(entry, &row.claim);
    let owner = project.root.to_string_lossy().into_owned();
    let device = extracted.label_extra.clone().unwrap_or_default();
    let tokens = reverse_tokens(&claim_path, bundle_id.unwrap_or_default(), &device);
    let evidence = substitute(row.evidence, &tokens);
    let label = substitute(row.label, &tokens);
    let mut claim = Claim::new(claim_path, owner, row.kind, row.tier, evidence).label(label);
    if let Some(eco) = row.ecosystem {
        claim = claim.ecosystem(eco);
    }
    claim
}

fn build_stale_claim(row: &ReverseLink, entry: &Path, tree_path: &Path) -> Claim {
    let claim_path = claim_at(entry, &row.claim);
    let tokens = reverse_tokens(&claim_path, "", "");
    let mut tokens = tokens;
    tokens.insert("path", tree_path.display().to_string());
    let evidence = substitute(row.stale.unwrap_or_default(), &tokens);
    let label = substitute(row.label, &tokens);
    Claim::new(
        claim_path,
        UNATTRIBUTED_OWNER,
        row.kind,
        EvidenceTier::Observed,
        evidence,
    )
    .label(label)
    .stale()
}

fn extract_one(spec: &Extract, entry: &Path, env: &ResolveEnv<'_>) -> Option<Extracted> {
    match spec {
        Extract::PlistKey { file, key } => {
            let value = plist::Value::from_file(entry.join(file)).ok()?;
            let s = value.as_dictionary()?.get(key)?.as_string()?;
            Some(Extracted {
                path: PathBuf::from(s),
                label_extra: None,
            })
        }
        Extract::JsonUri { file, keys } => {
            let text = env.read_head(&entry.join(file), rules::MANIFEST_CAP)?;
            let json: serde_json::Value = serde_json::from_str(&text).ok()?;
            for k in *keys {
                if let Some(uri) = json.get(*k).and_then(|v| v.as_str()) {
                    if let Some(path) = attribution_paths::from_file_uri(uri) {
                        return Some(Extracted {
                            path,
                            label_extra: None,
                        });
                    }
                }
            }
            None
        }
        Extract::JsonlCwd { max_files, head } => {
            if entry.is_dir() {
                let read = std::fs::read_dir(entry).ok()?;
                let mut checked = 0usize;
                for e in read.filter_map(|e| e.ok()) {
                    if checked >= *max_files {
                        break;
                    }
                    let p = e.path();
                    if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                        continue;
                    }
                    checked += 1;
                    if let Some(text) = env.read_head(&p, *head) {
                        if let Some(cwd) = parsers::extract_cwd(&text) {
                            return Some(Extracted {
                                path: PathBuf::from(cwd),
                                label_extra: None,
                            });
                        }
                    }
                }
                None
            } else {
                let text = env.read_head(entry, *head)?;
                let cwd = parsers::extract_cwd(&text)?;
                Some(Extracted {
                    path: PathBuf::from(cwd),
                    label_extra: None,
                })
            }
        }
        Extract::SymlinkTargets { .. } => None, // handled by eval_symlink_targets
        Extract::Fn(f) => f(entry),
    }
}

/// `pnpm-store`'s shape: one scanned entry (a `projects/` dir) can resolve
/// to several symlinks, any one of which is enough to claim the entry's
/// parent for its owning project.
fn eval_symlink_targets(
    row: &ReverseLink,
    entries: &[PathBuf],
    subdir: &str,
    index: &ProjectIndex,
) -> Vec<Claim> {
    let mut claims = Vec::new();
    for entry in entries {
        let links_dir = if subdir.is_empty() {
            entry.clone()
        } else {
            entry.join(subdir)
        };
        let Ok(read) = std::fs::read_dir(&links_dir) else {
            continue;
        };
        // Every project that links this store shares it — collect them all
        // (deduped by root), not just the first.
        let mut matched: Vec<&Project> = Vec::new();
        for link in read.filter_map(|e| e.ok()) {
            let link_path = link.path();
            let Ok(target) = std::fs::read_link(&link_path) else {
                continue;
            };
            let resolved = if target.is_absolute() {
                target
            } else {
                link_path
                    .parent()
                    .map(|p| p.join(&target))
                    .unwrap_or(target)
            };
            let tree_path = attribution_paths::tree_path(&normalize_path(&resolved));
            if let Some(project) = index.owner_of(&tree_path) {
                if !matched.iter().any(|p| p.root == project.root) {
                    matched.push(project);
                }
            }
        }
        for project in matched {
            claims.push(build_reverse_claim(
                row,
                entry,
                project,
                &Extracted {
                    path: PathBuf::new(),
                    label_extra: None,
                },
                None,
            ));
        }
    }
    claims
}

/// Resolve `..`/`.` components without touching the filesystem — a relative
/// symlink target may point at a checkout that no longer exists.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn fallback_encoded_project_dir<'a>(entry: &Path, index: &'a ProjectIndex) -> Option<&'a Project> {
    let dir_name = entry.file_name()?.to_str()?;
    index.projects().iter().find(|project| {
        let encoded = parsers::encode_claude_project_dir(&project.root);
        dir_name == encoded || dir_name.starts_with(&format!("{encoded}-"))
    })
}

/// `.finding(id)` attached generically: any claim whose path equals an Fs
/// finding's path gets that finding's id (replaces the old
/// `xcode::matching_fs_cache_dir_finding`, which only ever looked at
/// DerivedData).
fn attach_matching_fs_findings(claims: &mut [Claim], env: &ResolveEnv<'_>) {
    let fs_findings: HashMap<PathBuf, FindingId> = env
        .findings(ScannerId::Fs)
        .iter()
        .filter(|f| f.kind == FindingKind::CacheDir)
        .filter_map(|f| {
            f.path
                .as_deref()
                .map(|p| (attribution_paths::tree_path(p), f.id))
        })
        .collect();
    for claim in claims.iter_mut() {
        if claim.finding.is_some() {
            continue;
        }
        let key = attribution_paths::tree_path(&claim.path);
        if let Some(id) = fs_findings.get(&key) {
            claim.finding = Some(*id);
        }
    }
}

// ---------------------------------------------------------------------
// BASELINE
// ---------------------------------------------------------------------

pub fn baselines(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    for row in rules::BASELINE {
        claims.extend(eval_baseline(row, env));
    }
    claims
}

fn eval_baseline(row: &Baseline, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let home = &env.paths.home;
    match &row.source {
        Source::FromFinding {
            scanner,
            kind,
            name,
        } => {
            let Some(finding) = env.findings(*scanner).iter().find(|f| {
                f.kind == *kind && (f.title == *name || f.meta_str("name") == Some(*name))
            }) else {
                return Vec::new();
            };
            let Some(path) = &finding.path else {
                return Vec::new();
            };
            vec![baseline_claim(row, path.clone())]
        }
        Source::FromFile { file, parse } => {
            let Some(text) = env.read_head(&env.paths.expand(file), rules::MANIFEST_CAP) else {
                return Vec::new();
            };
            let Some(value) = parse(&text) else {
                return Vec::new();
            };
            let path = env.paths.expand(&row.path.replace("{value}", &value));
            if !path.exists() {
                return Vec::new();
            }
            vec![baseline_claim(row, path)]
        }
        Source::Fixed => glob_expand(row.path, home)
            .into_iter()
            .filter(|p| p.exists())
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                !row.exclude.contains(&name)
            })
            .map(|p| baseline_claim(row, p))
            .collect(),
    }
}

fn baseline_claim(row: &Baseline, path: PathBuf) -> Claim {
    let label = match &row.label {
        Label::Static(s) => s.to_string(),
        Label::Basename => path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        Label::Fn(f) => f(&path),
    };
    Claim::new(
        path,
        BASELINE_OWNER,
        row.kind,
        EvidenceTier::EcosystemDefault,
        row.evidence,
    )
    .label(label)
    .baseline(row.ecosystem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_handles_stars_anywhere() {
        assert!(glob_match(
            "rollout-*.jsonl",
            "rollout-2026-09-24T08-28.jsonl"
        ));
        assert!(!glob_match("rollout-*.jsonl", "rollout-2026.json"));
        assert!(glob_match("*DeviceSupport", "iOS DeviceSupport"));
        assert!(glob_match("metadata*", "metadata-v1.3"));
        assert!(glob_match("*.sqlite*", "logs_2.sqlite-wal"));
        assert!(glob_match("a*b*c", "a-b-c"));
        assert!(!glob_match("ab*ba", "aba"));
        assert!(glob_match("exact", "exact") && !glob_match("exact", "exactly"));
    }

    #[test]
    fn substitute_replaces_known_tokens_and_leaves_unknown_ones() {
        let mut tokens = HashMap::new();
        tokens.insert("name", "cubby".to_string());
        tokens.insert("version", "1.2.3".to_string());
        assert_eq!(
            substitute("{name} {version} {nope}", &tokens),
            "cubby 1.2.3 {nope}"
        );
    }

    #[test]
    fn glob_match_supports_prefix_suffix_mid_and_exact() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("cpython-*", "cpython-3.12.1"));
        assert!(!glob_match("cpython-*", "pyenv-3.12.1"));
        assert!(glob_match("*DeviceSupport", "17.0 DeviceSupport"));
        assert!(glob_match("*.sqlite*", "state.sqlite3"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }

    #[test]
    fn expand_brace_expands_one_alternation_group() {
        assert_eq!(
            expand_brace("{Code,Cursor}"),
            Some(vec!["Code".to_string(), "Cursor".to_string()])
        );
        assert_eq!(expand_brace("plain"), None);
    }

    #[test]
    fn glob_expand_handles_tilde_and_literal_components() {
        let home = Path::new("/Users/nicky");
        assert_eq!(
            glob_expand("~/Library/Caches", home),
            vec![PathBuf::from("/Users/nicky/Library/Caches")]
        );
        assert_eq!(
            glob_expand("/Library/Developer/CoreSimulator/Volumes", home),
            vec![PathBuf::from("/Library/Developer/CoreSimulator/Volumes")]
        );
    }

    #[test]
    fn glob_expand_expands_brace_alternation_without_touching_disk() {
        let home = Path::new("/Users/nicky");
        let mut got = glob_expand("~/Library/Application Support/{Code,Cursor}/User", home);
        got.sort();
        assert_eq!(
            got,
            vec![
                PathBuf::from("/Users/nicky/Library/Application Support/Code/User"),
                PathBuf::from("/Users/nicky/Library/Application Support/Cursor/User"),
            ]
        );
    }

    #[test]
    fn glob_expand_lists_a_real_directory_for_a_star_component() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("v1")).unwrap();
        std::fs::create_dir(tmp.path().join("v2")).unwrap();
        std::fs::write(tmp.path().join("not-a-dir"), b"x").unwrap();
        let template = format!("{}/*", tmp.path().display());
        let mut got = glob_expand(&template, Path::new("/unused"));
        got.sort();
        assert_eq!(got.len(), 3); // read_dir doesn't filter by type here
        assert!(got.contains(&tmp.path().join("v1")));
    }

    #[test]
    fn under_project_matches_root_and_worktrees() {
        let project = Project {
            root: PathBuf::from("/Users/dev/cubby"),
            name: "cubby".into(),
            worktrees: vec![PathBuf::from("/Users/dev/cubby-worktrees/feature")],
            names: Vec::new(),
            bundle_ids: Vec::new(),
            is_git: true,
        };
        assert!(under_project(
            Path::new("/Users/dev/cubby/apps/api"),
            &project
        ));
        assert!(under_project(
            Path::new("/Users/dev/cubby-worktrees/feature/apps/api"),
            &project
        ));
        assert!(!under_project(Path::new("/Users/dev/other"), &project));
    }

    #[test]
    fn eval_match_max_semver_picks_the_newest_within_the_pin() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["v24.2.0", "v24.15.0", "v20.1.0"] {
            std::fs::create_dir(tmp.path().join(name)).unwrap();
        }
        let mut tokens = HashMap::new();
        tokens.insert("key", "v24".to_string());
        let dir_str: &'static str = Box::leak(tmp.path().display().to_string().into_boxed_str());
        let dirs: &'static [&'static str] = Box::leak(vec![dir_str].into_boxed_slice());
        let got = eval_match(
            dirs,
            "",
            &Select::MaxSemver,
            &tokens,
            Path::new("/unused"),
            0,
        );
        assert_eq!(got, vec![tmp.path().join("v24.15.0")]);
    }

    #[test]
    fn eval_match_all_returns_every_prefix_match() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("lodash-npm-4.17.21-abc.zip"), b"x").unwrap();
        std::fs::write(tmp.path().join("lodash-npm-4.17.20-def.zip"), b"x").unwrap();
        std::fs::write(tmp.path().join("other-file"), b"x").unwrap();
        let tokens = HashMap::new();
        let dir_str: &'static str = Box::leak(tmp.path().display().to_string().into_boxed_str());
        let dirs: &'static [&'static str] = Box::leak(vec![dir_str].into_boxed_slice());
        let got = eval_match(
            dirs,
            "lodash-npm-",
            &Select::All,
            &tokens,
            Path::new("/unused"),
            0,
        );
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn reverse_link_matched_vs_stale() {
        let index = ProjectIndex::new(vec![Project {
            root: PathBuf::from("/Users/dev/cubby"),
            name: "cubby".into(),
            worktrees: Vec::new(),
            names: Vec::new(),
            bundle_ids: Vec::new(),
            is_git: true,
        }]);
        assert!(index.owner_of(Path::new("/Users/dev/cubby/src")).is_some());
        assert!(index.owner_of(Path::new("/Users/dev/gone")).is_none());
    }

    #[test]
    fn extract_json_uri_reads_the_first_present_key() {
        let fixture = crate::attribution::testutil::EnvFixture::new();
        let env = fixture.env();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("workspace.json"),
            r#"{"folder":"file:///Users/dev/cubby"}"#,
        )
        .unwrap();
        let extracted = extract_one(
            &Extract::JsonUri {
                file: "workspace.json",
                keys: &["folder", "workspace"],
            },
            tmp.path(),
            &env,
        )
        .expect("workspace.json parses");
        assert_eq!(extracted.path, PathBuf::from("/Users/dev/cubby"));
    }
}
