//! Homebrew dependency graph: pure data + algorithms, no IO.
//!
//! Built once per scan from `brew info --json=v2 --installed` (and rebuilt
//! from stored findings for previews without re-running brew). Answers the
//! questions the Brew explorer and the cleanup preflight need:
//!
//! - what does X need / why is X installed (forward / reverse walks)
//! - is X explicitly installed, a dependency, of unknown origin, a leaf
//! - what would removing this *set* of packages leave behind or orphan
//!
//! Origin is taken from Homebrew's own `installed_on_request` flag. A *leaf*
//! (nothing installed depends on it) is a structural fact and never implies
//! "user-requested" or "safe to remove"; a missing flag is `Unknown`, never
//! guessed. Predicted orphans are distinct from Homebrew-confirmed autoremove
//! candidates, which come from `brew autoremove --dry-run`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{Finding, FindingKind};

/// Formula `full_name`, or `cask:<token>` for casks.
pub type NodeId = String;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Formula,
    Cask,
}

/// Why a package is installed, from Homebrew's `installed_on_request`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InstallReason {
    /// `installed_on_request: true` — the user asked for it.
    Requested,
    /// `installed_on_request: false` — pulled in as a dependency.
    DependencyOnly,
    /// Flag absent (older receipts, partial metadata): do not guess.
    #[default]
    Unknown,
}

impl InstallReason {
    pub fn from_flag(flag: Option<bool>) -> Self {
        match flag {
            Some(true) => InstallReason::Requested,
            Some(false) => InstallReason::DependencyOnly,
            None => InstallReason::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            InstallReason::Requested => "requested",
            InstallReason::DependencyOnly => "dependency",
            InstallReason::Unknown => "unknown",
        }
    }
}

/// Where a node's outgoing edges came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSource {
    /// The install receipt's `runtime_dependencies` — what this build links.
    InstalledRuntime,
    /// The formula's *current* declarations — may differ from what was built.
    FormulaDeclaration,
    /// A cask's `depends_on`.
    CaskDependsOn,
}

impl EdgeSource {
    pub fn label(self) -> &'static str {
        match self {
            EdgeSource::InstalledRuntime => "installed_runtime",
            EdgeSource::FormulaDeclaration => "formula_declaration",
            EdgeSource::CaskDependsOn => "cask_depends_on",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    /// Short name (formula `name` / cask `token`).
    pub name: String,
    pub version: Option<String>,
    pub tap: Option<String>,
    pub aliases: Vec<String>,
    pub installed_on_request: Option<bool>,
    pub installed_as_dependency: Option<bool>,
    pub pinned: bool,
    pub outdated: bool,
    pub current_version: Option<String>,
    pub size_bytes: Option<u64>,
    /// Referenced by an edge but absent from the installed inventory.
    pub stub: bool,
    /// `None` when the source data carried no dependency information at all
    /// (legacy findings), which the explorer shows as "unavailable".
    pub dependency_source: Option<EdgeSource>,
}

impl Node {
    pub fn reason(&self) -> InstallReason {
        InstallReason::from_flag(self.installed_on_request)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub to: NodeId,
    /// `Some(false)` marks a flattened transitive runtime dependency.
    pub declared_directly: Option<bool>,
    pub source: EdgeSource,
    /// False when the target name could not be matched to an installed node.
    pub resolved: bool,
}

impl Edge {
    pub fn is_direct(&self) -> bool {
        self.declared_directly != Some(false)
    }
}

// ---- `brew info --json=v2 --installed` shapes (only the fields we read) ----

#[derive(Deserialize, Default, Debug)]
pub struct InfoRoot {
    #[serde(default)]
    pub formulae: Vec<FormulaInfo>,
    #[serde(default)]
    pub casks: Vec<CaskInfo>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct FormulaInfo {
    pub name: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub tap: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub oldnames: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub installed: Vec<InstalledInfo>,
    #[serde(default)]
    pub linked_keg: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub outdated: bool,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct InstalledInfo {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub runtime_dependencies: Option<Vec<RuntimeDep>>,
    #[serde(default)]
    pub installed_on_request: Option<bool>,
    #[serde(default)]
    pub installed_as_dependency: Option<bool>,
    #[serde(default)]
    pub time: Option<u64>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct RuntimeDep {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub declared_directly: Option<bool>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct CaskInfo {
    pub token: String,
    #[serde(default)]
    pub full_token: Option<String>,
    #[serde(default)]
    pub name: Vec<String>,
    /// Installed version (string) — `null`/absent when not installed.
    #[serde(default)]
    pub installed: Option<String>,
    #[serde(default)]
    pub outdated: bool,
    #[serde(default)]
    pub depends_on: Value,
    #[serde(default)]
    pub artifacts: Vec<Value>,
}

impl CaskInfo {
    /// `/Applications/<name>` for every `app` artifact.
    pub fn app_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for art in &self.artifacts {
            if let Some(apps) = art.get("app").and_then(|a| a.as_array()) {
                for a in apps {
                    if let Some(name) = a.as_str() {
                        out.push(format!("/Applications/{name}"));
                    }
                }
            }
        }
        out
    }

    /// `{source, target}` for every `binary` artifact. `target` is the
    /// absolute launcher path Homebrew links into its bin dir. Real output is
    /// `{"binary": ["bin/codex"], "target": "/opt/homebrew/bin/codex"}`; the
    /// target may also appear inside the array as `{"target": ...}`.
    pub fn binaries(&self) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for art in &self.artifacts {
            if let Some(bins) = art.get("binary").and_then(|b| b.as_array()) {
                let mut source = None;
                let mut target = art
                    .get("target")
                    .and_then(|t| t.as_str())
                    .map(str::to_string);
                for b in bins {
                    if let Some(s) = b.as_str() {
                        source = Some(s.to_string());
                    } else if let Some(t) = b.get("target").and_then(|t| t.as_str()) {
                        target = Some(t.to_string());
                    }
                }
                if let Some(s) = source {
                    out.push((s, target));
                }
            }
        }
        out
    }

    fn depends_on_list(&self, key: &str) -> Vec<String> {
        self.depends_on
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Parse `brew autoremove --dry-run` stdout. Homebrew prints a header
/// (`==> Would autoremove N unneeded formulae:`) followed by one name per
/// line, and nothing at all when there is nothing to remove.
pub fn parse_autoremove_dry_run(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("==>") && !l.contains(' '))
        .map(str::to_string)
        .collect()
}

// ---- the graph ----

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// "What does X need?"
    Forward,
    /// "Why is X installed?" — who needs it.
    Reverse,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    Root,
    Direct,
    Transitive,
    /// The parent carried no dependency data.
    Unknown,
    NotInstalled,
}

/// One row of an explorer walk.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WalkNode {
    pub name: String,
    pub id: Option<NodeId>,
    pub depth: u16,
    pub relation: Relation,
    pub installed: bool,
    /// Already on the ancestor path — rendered once, never expandable.
    pub cycle: bool,
    pub has_children: bool,
    /// Expand-state key: `"<prefix>|a/b/c"`.
    pub path_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct WhyInstalled {
    pub reason: InstallReason,
    /// Explicitly installed packages that (transitively) need this one.
    pub requested_roots: Vec<NodeId>,
    /// Up to three example chains from this node up to a requested root.
    pub paths: Vec<Vec<NodeId>>,
}

/// What removing a set of packages would do. Every list is sorted and
/// de-duplicated; `bytes_*` are set-based so shared dependencies count once.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RemovalPreview {
    /// Selected packages that nothing outside the selection still needs.
    pub removable: Vec<NodeId>,
    /// Selected packages that are still needed → (package, retained dependents).
    pub blocked: Vec<(NodeId, Vec<NodeId>)>,
    /// Dependencies whose every dependent is in the removal set and whose
    /// origin is `DependencyOnly` — predicted to become unneeded.
    pub newly_orphaned: Vec<NodeId>,
    /// `newly_orphaned` ∩ Homebrew's own autoremove list (when known).
    pub confirmed_orphans: Vec<NodeId>,
    /// Would qualify as orphans but their origin is unknown — verify first.
    pub uncertain_orphans: Vec<NodeId>,
    /// Sizes of the selected packages (None when any is unsized).
    pub bytes_selected: Option<u64>,
    /// Selected + predicted orphans, each counted once.
    pub bytes_with_orphans: Option<u64>,
    /// Safe removal order (dependents before dependencies) over
    /// removable ∪ newly_orphaned.
    pub order: Vec<NodeId>,
    pub caveats: Vec<String>,
    /// Names that could not be resolved to an installed package.
    pub unknown: Vec<String>,
}

type PendingEdges = (NodeId, Vec<String>, Vec<String>, Vec<String>);

#[derive(Clone, Debug, Default)]
pub struct BrewGraph {
    nodes: BTreeMap<NodeId, Node>,
    /// Short names, aliases, old names, tokens → candidate ids.
    names: BTreeMap<String, BTreeSet<NodeId>>,
    deps: BTreeMap<NodeId, Vec<Edge>>,
    rdeps: BTreeMap<NodeId, BTreeSet<NodeId>>,
    pub caveats: Vec<String>,
    /// Homebrew-confirmed autoremove candidates; `None` when the dry-run
    /// could not be run (unknown, not "none").
    pub autoremove: Option<BTreeSet<NodeId>>,
}

impl BrewGraph {
    fn insert_node(&mut self, node: Node, extra_names: &[String]) {
        for n in std::iter::once(&node.name)
            .chain(std::iter::once(&node.id))
            .chain(node.aliases.iter())
            .chain(extra_names.iter())
        {
            if n.is_empty() {
                continue;
            }
            self.names
                .entry(n.clone())
                .or_default()
                .insert(node.id.clone());
        }
        self.nodes.insert(node.id.clone(), node);
    }

    fn add_edge(
        &mut self,
        from: &NodeId,
        to_name: &str,
        declared_directly: Option<bool>,
        source: EdgeSource,
    ) {
        let (to, resolved) = match self.resolve(to_name) {
            Some(id) => (id, true),
            None => {
                let id = to_name.to_string();
                if !self.nodes.contains_key(&id) {
                    self.caveats.push(format!(
                        "{from} depends on {to_name}, which is not in the installed inventory"
                    ));
                    let stub = Node {
                        id: id.clone(),
                        kind: NodeKind::Formula,
                        name: to_name.to_string(),
                        version: None,
                        tap: None,
                        aliases: Vec::new(),
                        installed_on_request: None,
                        installed_as_dependency: None,
                        pinned: false,
                        outdated: false,
                        current_version: None,
                        size_bytes: None,
                        stub: true,
                        dependency_source: None,
                    };
                    self.nodes.insert(id.clone(), stub);
                }
                (id, false)
            }
        };
        if to == *from {
            return;
        }
        let edges = self.deps.entry(from.clone()).or_default();
        if let Some(existing) = edges.iter_mut().find(|e| e.to == to) {
            // A direct declaration wins over a flattened transitive entry.
            if declared_directly == Some(true) {
                existing.declared_directly = Some(true);
            }
            return;
        }
        edges.push(Edge {
            to: to.clone(),
            declared_directly,
            source,
            resolved,
        });
        self.rdeps.entry(to).or_default().insert(from.clone());
    }

    /// Build from `brew info --json=v2 --installed` plus the autoremove
    /// dry-run result (`None` when it could not be run).
    pub fn from_info(info: &InfoRoot, autoremove: Option<BTreeSet<String>>) -> Self {
        let mut g = BrewGraph::default();
        for f in &info.formulae {
            let id = if f.full_name.is_empty() {
                f.name.clone()
            } else {
                f.full_name.clone()
            };
            // The linked keg (or the newest receipt) describes the live install.
            let inst = f
                .installed
                .iter()
                .find(|i| f.linked_keg.as_deref() == Some(i.version.as_str()))
                .or_else(|| f.installed.last());
            let has_runtime = inst
                .map(|i| i.runtime_dependencies.is_some())
                .unwrap_or(false);
            let node = Node {
                id: id.clone(),
                kind: NodeKind::Formula,
                name: f.name.clone(),
                version: inst.map(|i| i.version.clone()).filter(|v| !v.is_empty()),
                tap: f.tap.clone(),
                aliases: f.aliases.clone(),
                installed_on_request: inst.and_then(|i| i.installed_on_request),
                installed_as_dependency: inst.and_then(|i| i.installed_as_dependency),
                pinned: f.pinned,
                outdated: f.outdated,
                current_version: None,
                size_bytes: None,
                stub: false,
                dependency_source: Some(if has_runtime {
                    EdgeSource::InstalledRuntime
                } else {
                    EdgeSource::FormulaDeclaration
                }),
            };
            g.insert_node(node, &f.oldnames);
        }
        for c in &info.casks {
            let node = Node {
                id: format!("cask:{}", c.token),
                kind: NodeKind::Cask,
                name: c.token.clone(),
                version: c.installed.clone().filter(|v| !v.is_empty()),
                tap: None,
                aliases: c.full_token.iter().cloned().collect(),
                // Casks carry no on-request flag; a cask is by definition
                // something the user asked for unless another cask needs it.
                installed_on_request: Some(true),
                installed_as_dependency: None,
                pinned: false,
                outdated: c.outdated,
                current_version: None,
                size_bytes: None,
                stub: false,
                dependency_source: Some(EdgeSource::CaskDependsOn),
            };
            g.insert_node(node, &[]);
        }
        // Edges after every node exists so names resolve.
        for f in &info.formulae {
            let id = if f.full_name.is_empty() {
                f.name.clone()
            } else {
                f.full_name.clone()
            };
            let inst = f
                .installed
                .iter()
                .find(|i| f.linked_keg.as_deref() == Some(i.version.as_str()))
                .or_else(|| f.installed.last());
            match inst.and_then(|i| i.runtime_dependencies.as_ref()) {
                Some(rt) => {
                    for d in rt {
                        g.add_edge(
                            &id,
                            &d.full_name,
                            d.declared_directly,
                            EdgeSource::InstalledRuntime,
                        );
                    }
                }
                None => {
                    if !f.dependencies.is_empty() {
                        g.caveats.push(format!(
                            "{id}: no install receipt with runtime dependencies; using the formula's current declarations"
                        ));
                    }
                    for d in &f.dependencies {
                        g.add_edge(&id, d, Some(true), EdgeSource::FormulaDeclaration);
                    }
                }
            }
        }
        for c in &info.casks {
            let id = format!("cask:{}", c.token);
            for d in c.depends_on_list("formula") {
                g.add_edge(&id, &d, Some(true), EdgeSource::CaskDependsOn);
            }
            for d in c.depends_on_list("cask") {
                let target = format!("cask:{d}");
                g.add_edge(&id, &target, Some(true), EdgeSource::CaskDependsOn);
            }
        }
        g.autoremove = autoremove.map(|set| {
            set.iter()
                .map(|n| g.resolve(n).unwrap_or_else(|| n.clone()))
                .collect()
        });
        g
    }

    /// Rebuild from Brew findings (this scan's enriched meta, or a legacy
    /// snapshot that only carried `dependencies`/`dependents`). Missing flags
    /// stay unknown; missing dependency lists mark the node's source `None`.
    pub fn from_findings<'a>(it: impl Iterator<Item = &'a Finding>) -> Self {
        let mut g = BrewGraph::default();
        // (id, direct deps, transitive deps, cask deps)
        let mut pending: Vec<PendingEdges> = Vec::new();
        let mut any_autoremove_flag = false;
        let mut autoremove = BTreeSet::new();
        for f in it {
            let m = &f.meta;
            let str_list = |key: &str| -> Option<Vec<String>> {
                m.get(key).and_then(|v| v.as_array()).map(|a| {
                    a.iter()
                        .filter_map(|x| {
                            x.as_str().map(str::to_string).or_else(|| {
                                x.get("name").and_then(|n| n.as_str()).map(str::to_string)
                            })
                        })
                        .collect()
                })
            };
            match f.kind {
                FindingKind::BrewFormula => {
                    if m.get("name").is_none() && m.get("full_name").is_none() {
                        continue; // synthetic rows such as the autoremove summary
                    }
                    let name = m
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&f.title)
                        .to_string();
                    let id = m
                        .get("full_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| name.clone());
                    let direct = str_list("dependencies");
                    let transitive = str_list("dependencies_transitive").unwrap_or_default();
                    let auto = m.get("autoremove_candidate").and_then(|v| v.as_bool());
                    if auto.is_some() {
                        any_autoremove_flag = true;
                    }
                    if auto == Some(true) {
                        autoremove.insert(id.clone());
                    }
                    let node = Node {
                        id: id.clone(),
                        kind: NodeKind::Formula,
                        name,
                        version: m
                            .get("version")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        tap: m.get("tap").and_then(|v| v.as_str()).map(str::to_string),
                        aliases: str_list("aliases").unwrap_or_default(),
                        installed_on_request: m
                            .get("installed_on_request")
                            .and_then(|v| v.as_bool()),
                        installed_as_dependency: m
                            .get("installed_as_dependency")
                            .and_then(|v| v.as_bool()),
                        pinned: m.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false),
                        outdated: m.get("outdated").and_then(|v| v.as_bool()).unwrap_or(false),
                        current_version: m
                            .get("current_version")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        size_bytes: f.size_bytes,
                        stub: false,
                        dependency_source: direct.as_ref().map(|_| {
                            match m.get("dependency_source").and_then(|v| v.as_str()) {
                                Some("formula_declaration") => EdgeSource::FormulaDeclaration,
                                _ => EdgeSource::InstalledRuntime,
                            }
                        }),
                    };
                    g.insert_node(node, &[]);
                    pending.push((id, direct.unwrap_or_default(), transitive, Vec::new()));
                }
                FindingKind::BrewCask => {
                    let token = m
                        .get("token")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&f.title)
                        .to_string();
                    let id = format!("cask:{token}");
                    let node = Node {
                        id: id.clone(),
                        kind: NodeKind::Cask,
                        name: token,
                        version: m
                            .get("version")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        tap: None,
                        aliases: Vec::new(),
                        installed_on_request: Some(true),
                        installed_as_dependency: None,
                        pinned: false,
                        outdated: m.get("outdated").and_then(|v| v.as_bool()).unwrap_or(false),
                        current_version: m
                            .get("current_version")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        size_bytes: f.size_bytes,
                        stub: false,
                        dependency_source: Some(EdgeSource::CaskDependsOn),
                    };
                    g.insert_node(node, &[]);
                    let formula_deps = m
                        .get("depends_on")
                        .and_then(|d| d.get("formula"))
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let cask_deps: Vec<String> = m
                        .get("depends_on")
                        .and_then(|d| d.get("cask"))
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(|s| format!("cask:{s}")))
                                .collect()
                        })
                        .unwrap_or_default();
                    pending.push((id, formula_deps, Vec::new(), cask_deps));
                }
                _ => {}
            }
        }
        for (id, direct, transitive, casks) in pending {
            let source = g
                .nodes
                .get(&id)
                .and_then(|n| n.dependency_source)
                .unwrap_or(EdgeSource::InstalledRuntime);
            for d in direct {
                g.add_edge(&id, &d, Some(true), source);
            }
            for d in transitive {
                g.add_edge(&id, &d, Some(false), source);
            }
            for d in casks {
                g.add_edge(&id, &d, Some(true), EdgeSource::CaskDependsOn);
            }
        }
        g.autoremove = any_autoremove_flag.then_some(autoremove);
        g
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn get(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn set_size(&mut self, id: &str, bytes: Option<u64>) {
        if let Some(n) = self.nodes.get_mut(id) {
            n.size_bytes = bytes;
        }
    }

    pub fn set_current_version(&mut self, id: &str, version: Option<String>) {
        if let Some(n) = self.nodes.get_mut(id) {
            if version.is_some() {
                n.outdated = true;
            }
            n.current_version = version;
        }
    }

    /// Resolve a user-facing name (full name, short name, alias, old name,
    /// cask token, `cask:token`) to a node id. Ambiguous short names (two
    /// taps) resolve to nothing — the caller sees a caveat instead of a guess.
    pub fn resolve(&self, name: &str) -> Option<NodeId> {
        if self.nodes.contains_key(name) && !self.nodes[name].stub {
            return Some(name.to_string());
        }
        let cands = self.names.get(name)?;
        let installed: Vec<&NodeId> = cands
            .iter()
            .filter(|id| self.nodes.get(*id).map(|n| !n.stub).unwrap_or(false))
            .collect();
        match installed.as_slice() {
            [one] => Some((*one).clone()),
            [] => None,
            many => {
                // Prefer a homebrew/core formula over tap formulae with the
                // same short name; otherwise refuse to guess.
                let core: Vec<&&NodeId> = many.iter().filter(|id| !id.contains('/')).collect();
                match core.as_slice() {
                    [one] => Some((**one).clone()),
                    _ => None,
                }
            }
        }
    }

    pub fn node(&self, name: &str) -> Option<&Node> {
        self.resolve(name).and_then(|id| self.nodes.get(&id))
    }

    pub fn edges(&self, id: &str) -> &[Edge] {
        self.deps.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Direct dependencies (installed or stub ids).
    pub fn direct_deps(&self, id: &str) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .edges(id)
            .iter()
            .filter(|e| e.is_direct())
            .map(|e| e.to.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Installed packages that depend on `id` (directly or via a flattened
    /// runtime entry) — the set that must be gone before `id` is unneeded.
    pub fn dependents(&self, id: &str) -> Vec<NodeId> {
        self.rdeps
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Packages whose *direct* declaration includes `id`.
    pub fn direct_dependents(&self, id: &str) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .dependents(id)
            .into_iter()
            .filter(|d| self.edges(d).iter().any(|e| e.to == id && e.is_direct()))
            .collect();
        v.sort();
        v
    }

    pub fn cask_dependents(&self, id: &str) -> Vec<NodeId> {
        self.dependents(id)
            .into_iter()
            .filter(|d| d.starts_with("cask:"))
            .collect()
    }

    /// Structural leaf: no installed package depends on it.
    pub fn is_leaf(&self, id: &str) -> bool {
        self.dependents(id).is_empty()
    }

    fn bfs(&self, start: &str, dir: Direction) -> BTreeMap<NodeId, u16> {
        let mut seen: BTreeMap<NodeId, u16> = BTreeMap::new();
        let mut q = VecDeque::new();
        q.push_back((start.to_string(), 0u16));
        while let Some((cur, d)) = q.pop_front() {
            let next: Vec<NodeId> = match dir {
                Direction::Forward => self.edges(&cur).iter().map(|e| e.to.clone()).collect(),
                Direction::Reverse => self.dependents(&cur),
            };
            for n in next {
                if n == start || seen.contains_key(&n) {
                    continue;
                }
                seen.insert(n.clone(), d + 1);
                q.push_back((n, d + 1));
            }
        }
        seen
    }

    /// Everything `id` needs, with distance (1 = direct). Cycle-safe.
    pub fn transitive_deps(&self, id: &str) -> BTreeMap<NodeId, u16> {
        self.bfs(id, Direction::Forward)
    }

    /// Everything that needs `id`, with distance. Cycle-safe.
    pub fn transitive_dependents(&self, id: &str) -> BTreeMap<NodeId, u16> {
        self.bfs(id, Direction::Reverse)
    }

    pub fn why_installed(&self, id: &str) -> WhyInstalled {
        let reason = self
            .get(id)
            .map(Node::reason)
            .unwrap_or(InstallReason::Unknown);
        let ancestors = self.transitive_dependents(id);
        let mut requested_roots: Vec<NodeId> = ancestors
            .keys()
            .filter(|a| {
                self.get(a)
                    .map(|n| n.reason() == InstallReason::Requested)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        requested_roots.sort();
        // Example chains: DFS upward from `id`, stop at a requested root.
        let mut paths = Vec::new();
        let mut stack: Vec<Vec<NodeId>> = vec![vec![id.to_string()]];
        while let Some(path) = stack.pop() {
            if paths.len() >= 3 {
                break;
            }
            let last = path.last().cloned().unwrap();
            if path.len() > 1
                && self
                    .get(&last)
                    .map(|n| n.reason() == InstallReason::Requested)
                    .unwrap_or(false)
            {
                paths.push(path);
                continue;
            }
            if path.len() >= 8 {
                continue;
            }
            for parent in self.direct_dependents(&last).into_iter().rev() {
                if path.contains(&parent) {
                    continue;
                }
                let mut next = path.clone();
                next.push(parent);
                stack.push(next);
            }
        }
        WhyInstalled {
            reason,
            requested_roots,
            paths,
        }
    }

    /// Preview removing `selected` (names or ids) as one batch.
    pub fn removal_preview(&self, selected: &BTreeSet<String>) -> RemovalPreview {
        let mut out = RemovalPreview::default();
        let mut sel: BTreeSet<NodeId> = BTreeSet::new();
        for s in selected {
            match self.resolve(s) {
                Some(id) => {
                    sel.insert(id);
                }
                None => out.unknown.push(s.clone()),
            }
        }
        for id in &sel {
            let retained: Vec<NodeId> = self
                .dependents(id)
                .into_iter()
                .filter(|d| !sel.contains(d))
                .filter(|d| self.get(d).map(|n| !n.stub).unwrap_or(false))
                .collect();
            if retained.is_empty() {
                out.removable.push(id.clone());
            } else {
                out.blocked.push((id.clone(), retained));
            }
        }
        // Orphan prediction: fixpoint over dependency-only packages whose
        // every dependent is already going away.
        let mut going: BTreeSet<NodeId> = sel.clone();
        loop {
            let mut grew = false;
            for (id, node) in &self.nodes {
                if going.contains(id) || node.stub || node.kind == NodeKind::Cask {
                    continue;
                }
                if node.reason() != InstallReason::DependencyOnly {
                    continue;
                }
                let deps = self.dependents(id);
                if !deps.is_empty() && deps.iter().all(|d| going.contains(d)) {
                    going.insert(id.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        out.newly_orphaned = going.difference(&sel).cloned().collect();
        for (id, node) in &self.nodes {
            if going.contains(id) || node.stub || node.reason() != InstallReason::Unknown {
                continue;
            }
            let deps = self.dependents(id);
            if !deps.is_empty() && deps.iter().all(|d| going.contains(d)) {
                out.uncertain_orphans.push(id.clone());
            }
        }
        if let Some(auto) = &self.autoremove {
            out.confirmed_orphans = out
                .newly_orphaned
                .iter()
                .filter(|o| auto.contains(*o))
                .cloned()
                .collect();
        }
        let sum = |ids: &BTreeSet<NodeId>| -> Option<u64> {
            let mut total = 0u64;
            for id in ids {
                total = total.checked_add(self.get(id)?.size_bytes?)?;
            }
            Some(total)
        };
        out.bytes_selected = sum(&sel);
        out.bytes_with_orphans = sum(&going);
        // Order: dependents first (Kahn over the subgraph), cycles broken
        // lexically with a caveat.
        let removing: BTreeSet<NodeId> = out
            .removable
            .iter()
            .chain(out.newly_orphaned.iter())
            .cloned()
            .collect();
        let mut remaining: BTreeSet<NodeId> = removing.clone();
        while !remaining.is_empty() {
            let mut ready: Vec<NodeId> = remaining
                .iter()
                .filter(|id| !self.dependents(id).iter().any(|d| remaining.contains(d)))
                .cloned()
                .collect();
            if ready.is_empty() {
                let mut cyc: Vec<NodeId> = remaining.iter().cloned().collect();
                cyc.sort();
                out.caveats.push(format!(
                    "cycle among {} — removal order not guaranteed",
                    cyc.join(", ")
                ));
                ready = vec![cyc[0].clone()];
            }
            ready.sort();
            for r in ready {
                remaining.remove(&r);
                out.order.push(r);
            }
        }
        out.caveats.extend(self.caveats.iter().cloned());
        out
    }

    /// Explorer children: direct edges only (transitive entries appear deeper
    /// in the tree through their own parents). Reverse includes casks.
    pub fn children(&self, id: &str, dir: Direction) -> Vec<NodeId> {
        match dir {
            Direction::Forward => self.direct_deps(id),
            Direction::Reverse => self.direct_dependents(id),
        }
    }

    /// Flatten a subtree for display. Iterative DFS; a child already on the
    /// ancestor path is emitted once as a cycle marker and never expanded.
    pub fn walk(
        &self,
        root: &str,
        dir: Direction,
        is_expanded: &dyn Fn(&str) -> bool,
        prefix: &str,
        max_depth: u16,
    ) -> Vec<WalkNode> {
        let mut out = Vec::new();
        let root_id = self.resolve(root).unwrap_or_else(|| root.to_string());
        let root_key = format!("{prefix}|{root_id}");
        // stack of (id, depth, path_key, ancestors)
        let mut stack: Vec<(NodeId, u16, String, Vec<NodeId>)> =
            vec![(root_id.clone(), 1, root_key, Vec::new())];
        while let Some((id, depth, key, ancestors)) = stack.pop() {
            let node = self.get(&id);
            let installed = node.map(|n| !n.stub).unwrap_or(false);
            let cycle = ancestors.contains(&id);
            let data_unknown = node.map(|n| n.dependency_source.is_none()).unwrap_or(true);
            let kids = if cycle || !installed || depth >= max_depth {
                Vec::new()
            } else {
                self.children(&id, dir)
            };
            let relation = if depth == 1 {
                Relation::Root
            } else if !installed {
                Relation::NotInstalled
            } else if depth == 2 {
                Relation::Direct
            } else {
                Relation::Transitive
            };
            let has_children =
                !kids.is_empty() || (installed && data_unknown && depth > 0 && !cycle);
            let expanded = has_children && is_expanded(&key);
            out.push(WalkNode {
                name: node.map(|n| n.name.clone()).unwrap_or_else(|| id.clone()),
                id: installed.then(|| id.clone()),
                depth,
                relation,
                installed,
                cycle,
                has_children,
                path_key: key.clone(),
            });
            if !expanded {
                continue;
            }
            if installed && data_unknown && dir == Direction::Forward {
                out.push(WalkNode {
                    name: "(dependency data unavailable)".to_string(),
                    id: None,
                    depth: depth + 1,
                    relation: Relation::Unknown,
                    installed: false,
                    cycle: false,
                    has_children: false,
                    path_key: format!("{key}/?"),
                });
                continue;
            }
            let mut next_ancestors = ancestors.clone();
            next_ancestors.push(id.clone());
            for kid in kids.into_iter().rev() {
                stack.push((
                    kid.clone(),
                    depth + 1,
                    format!("{key}/{kid}"),
                    next_ancestors.clone(),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formula(
        name: &str,
        on_request: Option<bool>,
        runtime: Option<Vec<(&str, bool)>>,
        declared: Vec<&str>,
    ) -> FormulaInfo {
        FormulaInfo {
            name: name.to_string(),
            full_name: name.to_string(),
            installed: vec![InstalledInfo {
                version: "1.0".into(),
                runtime_dependencies: runtime.map(|r| {
                    r.into_iter()
                        .map(|(n, direct)| RuntimeDep {
                            full_name: n.into(),
                            version: None,
                            declared_directly: Some(direct),
                        })
                        .collect()
                }),
                installed_on_request: on_request,
                installed_as_dependency: None,
                time: None,
            }],
            dependencies: declared.into_iter().map(String::from).collect(),
            linked_keg: Some("1.0".into()),
            ..Default::default()
        }
    }

    /// actionlint → shellcheck → gmp; wget → openssl@3; python (requested)
    /// → openssl@3; libfoo (unknown origin) alone.
    fn sample() -> BrewGraph {
        let info = InfoRoot {
            formulae: vec![
                formula(
                    "actionlint",
                    Some(true),
                    Some(vec![("shellcheck", true), ("gmp", false)]),
                    vec![],
                ),
                formula("shellcheck", Some(false), Some(vec![("gmp", true)]), vec![]),
                formula("gmp", Some(false), Some(vec![]), vec![]),
                formula("wget", Some(true), Some(vec![("openssl@3", true)]), vec![]),
                formula(
                    "python@3.14",
                    Some(true),
                    Some(vec![("openssl@3", true)]),
                    vec![],
                ),
                formula("openssl@3", Some(false), Some(vec![]), vec![]),
                formula("libfoo", None, Some(vec![]), vec![]),
            ],
            casks: vec![],
        };
        BrewGraph::from_info(&info, Some(BTreeSet::new()))
    }

    #[test]
    fn leaf_is_not_requested() {
        // A leaf with installed_on_request:false is a dependency whose
        // dependents are gone — never "requested".
        let info = InfoRoot {
            formulae: vec![formula("orphan-leaf", Some(false), Some(vec![]), vec![])],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        let n = g.node("orphan-leaf").unwrap();
        assert!(g.is_leaf("orphan-leaf"));
        assert_eq!(n.reason(), InstallReason::DependencyOnly);
    }

    #[test]
    fn install_reason_unknown_when_flag_absent() {
        let g = sample();
        assert_eq!(g.node("libfoo").unwrap().reason(), InstallReason::Unknown);
        assert!(g.is_leaf("libfoo"));
    }

    #[test]
    fn runtime_deps_preferred_over_declarations() {
        let info = InfoRoot {
            formulae: vec![
                formula("a", Some(true), Some(vec![("b", true)]), vec!["c"]),
                formula("b", Some(false), Some(vec![]), vec![]),
                formula("c", Some(false), Some(vec![]), vec![]),
            ],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        assert_eq!(g.direct_deps("a"), vec!["b".to_string()]);
        assert_eq!(
            g.node("a").unwrap().dependency_source,
            Some(EdgeSource::InstalledRuntime)
        );
        assert!(g.caveats.is_empty());
    }

    #[test]
    fn fallback_to_declarations_is_flagged() {
        let info = InfoRoot {
            formulae: vec![
                formula("a", Some(true), None, vec!["b"]),
                formula("b", Some(false), Some(vec![]), vec![]),
            ],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        assert_eq!(g.direct_deps("a"), vec!["b".to_string()]);
        assert_eq!(
            g.node("a").unwrap().dependency_source,
            Some(EdgeSource::FormulaDeclaration)
        );
        assert!(g.caveats.iter().any(|c| c.contains("current declarations")));
    }

    #[test]
    fn alias_and_tap_resolution() {
        let mut gnupg = formula("gnupg", Some(true), Some(vec![]), vec![]);
        gnupg.aliases = vec!["gpg".into(), "gpg2".into()];
        let mut tap = formula("clamp", Some(true), Some(vec![]), vec![]);
        tap.full_name = "wsagency/tap/clamp".into();
        let mut other = formula("clamp", Some(true), Some(vec![]), vec![]);
        other.full_name = "other/tap/clamp".into();
        let info = InfoRoot {
            formulae: vec![gnupg, tap.clone(), other],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        assert_eq!(g.resolve("gpg").as_deref(), Some("gnupg"));
        assert_eq!(
            g.resolve("wsagency/tap/clamp").as_deref(),
            Some("wsagency/tap/clamp")
        );
        // Two taps share the short name: refuse to guess.
        assert_eq!(g.resolve("clamp"), None);
        // With a single tap formula the short name resolves.
        let g2 = BrewGraph::from_info(
            &InfoRoot {
                formulae: vec![tap],
                casks: vec![],
            },
            None,
        );
        assert_eq!(g2.resolve("clamp").as_deref(), Some("wsagency/tap/clamp"));
    }

    #[test]
    fn missing_dependency_becomes_stub_with_caveat() {
        let info = InfoRoot {
            formulae: vec![formula(
                "a",
                Some(true),
                Some(vec![("ghost", true)]),
                vec![],
            )],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        assert!(g.get("ghost").unwrap().stub);
        assert_eq!(g.resolve("ghost"), None);
        assert!(g.caveats.iter().any(|c| c.contains("ghost")));
        let walk = g.walk("a", Direction::Forward, &|_| true, "fwd", 8);
        assert_eq!(walk[1].relation, Relation::NotInstalled);
    }

    #[test]
    fn cycle_terminates_and_orders_with_caveat() {
        let info = InfoRoot {
            formulae: vec![
                formula("a", Some(false), Some(vec![("b", true)]), vec![]),
                formula("b", Some(false), Some(vec![("a", true)]), vec![]),
            ],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        assert_eq!(g.transitive_deps("a").len(), 1);
        let walk = g.walk("a", Direction::Forward, &|_| true, "fwd", 8);
        // a → b → a(cycle); the cycle row is never expanded.
        assert_eq!(walk.len(), 3);
        assert!(walk[2].cycle);
        assert!(!walk[2].has_children);
        let pv = g.removal_preview(&["a".to_string(), "b".to_string()].into_iter().collect());
        assert_eq!(pv.order.len(), 2);
        assert!(pv.caveats.iter().any(|c| c.contains("cycle")));
    }

    #[test]
    fn removal_preview_blocked_and_orphans() {
        let g = sample();
        let pv = g.removal_preview(&["actionlint".to_string()].into_iter().collect());
        assert_eq!(pv.removable, vec!["actionlint".to_string()]);
        assert!(pv.blocked.is_empty());
        assert_eq!(
            pv.newly_orphaned,
            vec!["gmp".to_string(), "shellcheck".to_string()]
        );
        assert_eq!(pv.order, vec!["actionlint", "shellcheck", "gmp"]);
        // Nothing confirmed: the dry-run listed nothing.
        assert!(pv.confirmed_orphans.is_empty());

        let pv = g.removal_preview(&["shellcheck".to_string()].into_iter().collect());
        assert!(pv.removable.is_empty());
        assert_eq!(
            pv.blocked,
            vec![("shellcheck".to_string(), vec!["actionlint".to_string()])]
        );
        assert!(pv.newly_orphaned.is_empty());
    }

    #[test]
    fn shared_dependency_stays_required_and_is_counted_once() {
        let mut g = sample();
        g.set_size("wget", Some(10));
        g.set_size("python@3.14", Some(20));
        g.set_size("openssl@3", Some(100));
        // Removing wget alone: openssl@3 still needed by python.
        let pv = g.removal_preview(&["wget".to_string()].into_iter().collect());
        assert!(pv.newly_orphaned.is_empty());
        assert_eq!(pv.bytes_selected, Some(10));
        assert_eq!(pv.bytes_with_orphans, Some(10));
        // Removing both: openssl@3 orphaned, counted once.
        let pv = g.removal_preview(
            &["wget".to_string(), "python@3.14".to_string()]
                .into_iter()
                .collect(),
        );
        assert_eq!(pv.newly_orphaned, vec!["openssl@3".to_string()]);
        assert_eq!(pv.bytes_selected, Some(30));
        assert_eq!(pv.bytes_with_orphans, Some(130));
        assert_eq!(pv.order, vec!["python@3.14", "wget", "openssl@3"]);
    }

    #[test]
    fn unknown_origin_goes_to_uncertain() {
        let info = InfoRoot {
            formulae: vec![
                formula("app", Some(true), Some(vec![("lib", true)]), vec![]),
                formula("lib", None, Some(vec![]), vec![]),
            ],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, None);
        let pv = g.removal_preview(&["app".to_string()].into_iter().collect());
        assert!(pv.newly_orphaned.is_empty());
        assert_eq!(pv.uncertain_orphans, vec!["lib".to_string()]);
    }

    #[test]
    fn confirmed_orphans_come_only_from_autoremove() {
        let info = InfoRoot {
            formulae: vec![
                formula("app", Some(true), Some(vec![("lib", true)]), vec![]),
                formula("lib", Some(false), Some(vec![]), vec![]),
            ],
            casks: vec![],
        };
        let g = BrewGraph::from_info(&info, Some(["lib".to_string()].into_iter().collect()));
        let pv = g.removal_preview(&["app".to_string()].into_iter().collect());
        assert_eq!(pv.confirmed_orphans, vec!["lib".to_string()]);
        let g = BrewGraph::from_info(&info, None);
        let pv = g.removal_preview(&["app".to_string()].into_iter().collect());
        assert!(pv.confirmed_orphans.is_empty());
        assert!(g.autoremove.is_none());
    }

    #[test]
    fn why_installed_finds_requested_roots_and_paths() {
        let g = sample();
        let why = g.why_installed("gmp");
        assert_eq!(why.reason, InstallReason::DependencyOnly);
        assert_eq!(why.requested_roots, vec!["actionlint".to_string()]);
        assert!(why
            .paths
            .iter()
            .any(|p| p == &["gmp", "shellcheck", "actionlint"]));
    }

    #[test]
    fn direct_versus_transitive_walk() {
        let g = sample();
        let walk = g.walk("actionlint", Direction::Forward, &|_| true, "fwd", 8);
        let names: Vec<(&str, Relation)> =
            walk.iter().map(|w| (w.name.as_str(), w.relation)).collect();
        // gmp is a flattened runtime entry of actionlint but is listed only
        // under shellcheck, as transitive.
        assert_eq!(
            names,
            vec![
                ("actionlint", Relation::Root),
                ("shellcheck", Relation::Direct),
                ("gmp", Relation::Transitive),
            ]
        );
        let rev = g.walk("gmp", Direction::Reverse, &|_| true, "rev", 8);
        assert_eq!(
            rev.iter().map(|w| w.name.as_str()).collect::<Vec<_>>(),
            ["gmp", "shellcheck", "actionlint"]
        );
        // Collapsed by default: only the root.
        let collapsed = g.walk("actionlint", Direction::Forward, &|_| false, "fwd", 8);
        assert_eq!(collapsed.len(), 1);
        assert!(collapsed[0].has_children);
    }

    #[test]
    fn cask_relationships() {
        let info = InfoRoot {
            formulae: vec![formula("openjdk", Some(false), Some(vec![]), vec![])],
            casks: vec![CaskInfo {
                token: "pdftk".into(),
                installed: Some("3.3".into()),
                depends_on: serde_json::json!({ "formula": ["openjdk"] }),
                artifacts: vec![
                    serde_json::json!({ "binary": ["bin/pdftk", { "target": "/opt/homebrew/bin/pdftk" }] }),
                ],
                ..Default::default()
            }],
        };
        let g = BrewGraph::from_info(&info, None);
        assert_eq!(g.cask_dependents("openjdk"), vec!["cask:pdftk".to_string()]);
        assert!(!g.is_leaf("openjdk"));
        let pv = g.removal_preview(&["pdftk".to_string()].into_iter().collect());
        assert_eq!(pv.removable, vec!["cask:pdftk".to_string()]);
        assert_eq!(pv.newly_orphaned, vec!["openjdk".to_string()]);
        assert_eq!(
            info.casks[0].binaries(),
            vec![(
                "bin/pdftk".to_string(),
                Some("/opt/homebrew/bin/pdftk".to_string())
            )]
        );
    }

    #[test]
    fn from_findings_roundtrips_and_accepts_legacy_meta() {
        let legacy = Finding::new(FindingKind::BrewFormula, "jq", "jq").meta(serde_json::json!({
            "name": "jq", "version": "1.7.1", "is_leaf": true,
            "dependencies": ["oniguruma"], "dependents": [], "outdated": false,
            "current_version": null,
        }));
        let dep = Finding::new(FindingKind::BrewFormula, "oniguruma", "oniguruma").meta(
            serde_json::json!({ "name": "oniguruma", "version": "6.9", "is_leaf": false,
                "dependencies": [], "dependents": ["jq"] }),
        );
        let g = BrewGraph::from_findings([&legacy, &dep].into_iter());
        assert_eq!(g.node("jq").unwrap().reason(), InstallReason::Unknown);
        assert_eq!(g.direct_deps("jq"), vec!["oniguruma".to_string()]);
        assert!(g.autoremove.is_none());
        let pv = g.removal_preview(&["jq".to_string()].into_iter().collect());
        // Origin unknown ⇒ uncertain, never predicted.
        assert_eq!(pv.uncertain_orphans, vec!["oniguruma".to_string()]);

        let enriched = Finding::new(FindingKind::BrewFormula, "jq", "jq").meta(serde_json::json!({
            "name": "jq", "full_name": "jq", "version": "1.7.1", "installed_on_request": true,
            "dependencies": ["oniguruma"], "dependencies_transitive": [], "autoremove_candidate": false,
        }));
        let dep2 = Finding::new(FindingKind::BrewFormula, "oniguruma", "oniguruma").meta(
            serde_json::json!({ "name": "oniguruma", "installed_on_request": false,
                "dependencies": [], "autoremove_candidate": false }),
        );
        let g = BrewGraph::from_findings([&enriched, &dep2].into_iter());
        let pv = g.removal_preview(&["jq".to_string()].into_iter().collect());
        assert_eq!(pv.newly_orphaned, vec!["oniguruma".to_string()]);
        assert_eq!(g.autoremove, Some(BTreeSet::new()));
    }

    #[test]
    fn autoremove_parse() {
        let out = "==> Would autoremove 2 unneeded formulae:\nfoo\nbar\n";
        assert_eq!(
            parse_autoremove_dry_run(out),
            ["bar".to_string(), "foo".to_string()].into_iter().collect()
        );
        assert!(parse_autoremove_dry_run("").is_empty());
    }

    #[test]
    fn unknown_selection_is_reported_not_guessed() {
        let g = sample();
        let pv = g.removal_preview(&["nope".to_string()].into_iter().collect());
        assert_eq!(pv.unknown, vec!["nope".to_string()]);
        assert!(pv.removable.is_empty());
    }
}
