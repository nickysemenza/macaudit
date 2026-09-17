//! Two small, hand-maintained, last-resort tables: well-known Apple data
//! locations (Photos library, Mail, Messages, Music, TV, iCloud Drive,
//! Safari, `CloudStorage/<Provider>-*`, `~/Library/Developer` → Xcode) and
//! the curated owner heuristics table (≤25 rows: Docker Desktop, Ableton,
//! Adobe's shared `com.adobe.*`, BraveSoftware, ...).
//!
//! Both tables are static data only — turning them into `Claim`s (which
//! needs `ResolveEnv` for the home dir, and the live owner list for the
//! existence checks curated rows need) happens in `candidates.rs` and
//! `linkers.rs` respectively.

/// One well-known Apple data location, expressed as a path relative to the
/// user's home dir. The two locations that need globbing a live directory
/// (Photos libraries, CloudStorage providers) aren't representable this way
/// and are built directly in `candidates::apple_data`.
pub(crate) struct AppleDataLocation {
    pub bundle_id: &'static str,
    pub home_suffix: &'static str,
    pub label: &'static str,
}

pub(crate) const APPLE_DATA: &[AppleDataLocation] = &[
    AppleDataLocation {
        bundle_id: "com.apple.mail",
        home_suffix: "Library/Mail",
        label: "Mail",
    },
    AppleDataLocation {
        bundle_id: "com.apple.MobileSMS",
        home_suffix: "Library/Messages",
        label: "Messages",
    },
    AppleDataLocation {
        bundle_id: "com.apple.Music",
        home_suffix: "Music/Music",
        label: "Music",
    },
    AppleDataLocation {
        bundle_id: "com.apple.TV",
        home_suffix: "Movies/TV",
        label: "TV",
    },
    AppleDataLocation {
        bundle_id: "com.apple.finder",
        home_suffix: "Library/Mobile Documents",
        label: "iCloud Drive",
    },
    AppleDataLocation {
        bundle_id: "com.apple.Safari",
        home_suffix: "Library/Safari",
        label: "Safari",
    },
    AppleDataLocation {
        bundle_id: "com.apple.dt.Xcode",
        home_suffix: "Library/Developer",
        label: "Xcode developer data",
    },
    AppleDataLocation {
        bundle_id: "com.apple.Podcasts",
        home_suffix: "Library/Group Containers/243LU875E5.groups.com.apple.podcasts",
        label: "Podcasts",
    },
    AppleDataLocation {
        bundle_id: "com.apple.iBooksX",
        home_suffix: "Library/Containers/com.apple.BKAgentService",
        label: "Books",
    },
    AppleDataLocation {
        bundle_id: "com.apple.Notes",
        home_suffix: "Library/Group Containers/group.com.apple.notes",
        label: "Notes",
    },
];

/// The bundle id Photos libraries are attributed to — handled outside
/// `APPLE_DATA` because it needs globbing `~/Pictures/*.photoslibrary`,
/// not a single fixed path.
pub(crate) const PHOTOS_BUNDLE_ID: &str = "com.apple.Photos";

/// `~/Library/CloudStorage/<Provider>-*` name prefix → the app that owns it.
pub(crate) const CLOUD_STORAGE_PROVIDERS: &[(&str, &str)] = &[
    ("GoogleDrive", "com.google.GoogleDrive"),
    ("Dropbox", "com.getdropbox.dropbox"),
    ("OneDrive", "com.microsoft.OneDrive"),
    ("Box", "com.box.desktop"),
];

/// What a curated row resolves a matching candidate to.
pub(crate) enum CuratedTarget {
    /// A fixed owner key — an app bundle id, `formula:<name>`,
    /// `tool:<name>`, or `"homebrew"`. Only turned into a claim when that
    /// owner actually exists this scan (`linkers::owner_exists`) — e.g. the
    /// `pip`/`pipx` rows below only fire when those tools were found by the
    /// Tools scanner.
    Owner(&'static str),
    /// Shared among every currently-installed app owner whose bundle id
    /// starts with this vendor prefix (`"com.adobe."`, `"com.microsoft."`,
    /// ...) — resolved against the live owner list at link time, not baked
    /// in here.
    VendorPrefix(&'static str),
}

/// One curated row: `name` is matched case-insensitively against a
/// candidate's leaf name (or its vendor component, for a depth-2 `<Vendor>/
/// <Name>` candidate).
pub(crate) struct CuratedRow {
    pub name: &'static str,
    pub target: CuratedTarget,
    /// Why no derivable signal (bundle id, entitlement, Info.plist name)
    /// exists for this one.
    pub reason: &'static str,
}

/// The last-resort table: ≤25 rows, each with a one-line reason why no
/// derivable signal exists for it.
pub(crate) const CURATED: &[CuratedRow] = &[
    CuratedRow {
        name: "Docker Desktop",
        target: CuratedTarget::Owner("com.docker.docker"),
        reason: "Docker Desktop's data dir is named after the product, not its bundle id",
    },
    CuratedRow {
        name: "Ableton",
        target: CuratedTarget::Owner("com.ableton.live"),
        reason: "Ableton Live's Application Support dir is the vendor name, not the app's bundle id",
    },
    CuratedRow {
        name: "Adobe",
        target: CuratedTarget::VendorPrefix("com.adobe."),
        reason: "one Application Support/Caches dir is shared by every installed Adobe app",
    },
    CuratedRow {
        name: "BraveSoftware",
        target: CuratedTarget::Owner("com.brave.Browser"),
        reason: "Brave's data dir uses the company name, not the app's bundle id",
    },
    CuratedRow {
        name: "Microsoft",
        target: CuratedTarget::VendorPrefix("com.microsoft."),
        reason: "a bare Microsoft vendor dir is shared by every installed Microsoft app",
    },
    CuratedRow {
        name: "Google",
        target: CuratedTarget::VendorPrefix("com.google."),
        reason: "a bare Google vendor dir with no matching child is shared by every installed Google app",
    },
    CuratedRow {
        name: "Mozilla",
        target: CuratedTarget::Owner("org.mozilla.firefox"),
        reason: "Firefox's profile dir is named after the vendor, not the app's bundle id",
    },
    CuratedRow {
        name: "Firefox",
        target: CuratedTarget::Owner("org.mozilla.firefox"),
        reason: "an alternate spelling of Firefox's data dir name",
    },
    CuratedRow {
        name: "TorBrowser-Data",
        target: CuratedTarget::Owner("org.torproject.torbrowser"),
        reason: "Tor Browser's data dir is a fixed name unrelated to its bundle id",
    },
    CuratedRow {
        name: "Codex",
        target: CuratedTarget::Owner("tool:codex"),
        reason: "the Codex CLI's cache dir predates any app-style identity to match on",
    },
    CuratedRow {
        name: "claude-cli-nodejs",
        target: CuratedTarget::Owner("tool:claude"),
        reason: "the Claude Code CLI's cache dir name doesn't match the `claude` tool name",
    },
    CuratedRow {
        name: "Homebrew",
        target: CuratedTarget::Owner("homebrew"),
        reason: "Homebrew's own Caches/Logs dirs are named after the project, not a formula",
    },
    CuratedRow {
        name: "pnpm",
        target: CuratedTarget::Owner("tool:pnpm"),
        reason: "the global pnpm store/cache dir isn't scoped to any single formula",
    },
    CuratedRow {
        name: "uv",
        target: CuratedTarget::Owner("tool:uv"),
        reason: "uv's cache dir name doesn't vary with its formula/tool identity",
    },
    CuratedRow {
        name: "go-build",
        target: CuratedTarget::Owner("tool:go"),
        reason: "Go's build cache is named by the toolchain, not a formula id",
    },
    CuratedRow {
        name: "ms-playwright",
        target: CuratedTarget::Owner("tool:playwright"),
        reason: "Playwright's browser-download cache predates any bundle/formula naming",
    },
    CuratedRow {
        name: "pip",
        target: CuratedTarget::Owner("tool:pip"),
        reason: "pip's cache dir name doesn't vary by installed formula",
    },
    CuratedRow {
        name: "pipx",
        target: CuratedTarget::Owner("tool:pipx"),
        reason: "pipx's shared venvs dir isn't scoped to any single tool identity",
    },
    CuratedRow {
        name: "virtualenv",
        target: CuratedTarget::Owner("tool:pip"),
        reason: "virtualenv's cache is conventionally grouped with pip's",
    },
    CuratedRow {
        name: ".cargo",
        target: CuratedTarget::Owner("formula:rustup"),
        reason: "rustup provides cargo; no formula or tool is named `cargo` to name-match against",
    },
    CuratedRow {
        name: "org.swift.swiftpm",
        target: CuratedTarget::Owner("com.apple.dt.Xcode"),
        reason: "SwiftPM's cache is keyed by its own bundle id, not Xcode's",
    },
    CuratedRow {
        name: "CocoaPods",
        target: CuratedTarget::Owner("com.apple.dt.Xcode"),
        reason: "CocoaPods is a gem, never an app/formula/tool owner; its cache exists for Xcode projects",
    },
];

/// Display names for the Apple bundle ids the data table attributes to —
/// several (Finder, Photos when not on the Dock, ...) are never discovered
/// as owners, so the row would otherwise be named after the id's last
/// component (`finder`).
pub(crate) fn apple_owner_name(bundle_id: &str) -> Option<&'static str> {
    Some(match bundle_id {
        "com.apple.mail" => "Mail",
        "com.apple.MobileSMS" => "Messages",
        "com.apple.Music" => "Music",
        "com.apple.TV" => "TV",
        "com.apple.finder" => "Finder (iCloud Drive)",
        "com.apple.Safari" => "Safari",
        "com.apple.dt.Xcode" => "Xcode",
        "com.apple.Podcasts" => "Podcasts",
        "com.apple.iBooksX" => "Books",
        "com.apple.Notes" => "Notes",
        "com.apple.Photos" => "Photos",
        _ => return None,
    })
}
