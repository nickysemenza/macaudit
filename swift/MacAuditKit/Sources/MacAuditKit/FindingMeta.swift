import Foundation

/// Typed access to a finding's scanner-specific `metaJson`. The keys mirror
/// the Rust scanners (`src/scan/system.rs`, `fs.rs`, `brew.rs`, `apps.rs`);
/// every accessor is optional because a value can be absent or `null`
/// (e.g. `memory.total_bytes` when `hw.memsize` failed).
public struct FindingMeta: @unchecked Sendable {
    // JSONSerialization values (NSNumber/NSString/NSArray/NSDictionary) are
    // immutable once parsed, which is what makes sharing them across
    // isolation domains sound.
    private let object: [String: Any]

    public init(json: String) {
        guard let data = json.data(using: .utf8),
            let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            object = [:]
            return
        }
        object = raw
    }

    public var isEmpty: Bool { object.isEmpty }
    public var keys: [String] { object.keys.sorted() }

    public func string(_ key: String) -> String? { object[key] as? String }
    public func bool(_ key: String) -> Bool? {
        guard let n = object[key] as? NSNumber, Self.isBoolean(n) else { return nil }
        return n.boolValue
    }
    public func double(_ key: String) -> Double? {
        guard let n = object[key] as? NSNumber, !Self.isBoolean(n) else { return nil }
        return n.doubleValue
    }
    public func uint64(_ key: String) -> UInt64? {
        guard let n = object[key] as? NSNumber, !Self.isBoolean(n) else { return nil }
        let d = n.doubleValue
        return d >= 0 ? UInt64(d) : nil
    }

    /// JSON `true`/`false` parse as `__NSCFBoolean` (objC type "c"); a numeric
    /// 0/1 does not. (`n is Bool` would say yes to any 0/1 number.)
    private static func isBoolean(_ n: NSNumber) -> Bool {
        String(cString: n.objCType) == "c"
    }
    public func strings(_ key: String) -> [String] { object[key] as? [String] ?? [] }
    /// Raw JSON array (of objects, numbers, …) at `key` — used where the
    /// value isn't a flat `[String]`, e.g. `by_kind: [{kind, bytes}]`.
    public func array(_ key: String) -> [Any] { object[key] as? [Any] ?? [] }
    public func has(_ key: String) -> Bool { object[key] != nil && !(object[key] is NSNull) }

    /// Display form of any value, for the inspector's key/value list.
    public func display(_ key: String) -> String {
        guard let v = object[key] else { return "" }
        if let s = v as? String { return s }
        if v is NSNull { return "null" }
        if let d = try? JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed, .sortedKeys]),
            let s = String(data: d, encoding: .utf8)
        {
            return s
        }
        return "\(v)"
    }
}

extension Finding {
    public var meta: FindingMeta { FindingMeta(json: metaJson) }

    /// `meta.role` for System findings: cpu, memory, swap, disk, process.
    public var role: String? { meta.string("role") }
}

// MARK: - System

public struct DiskMetric: Sendable {
    public let capacityBytes: UInt64
    public let usedBytes: UInt64
    public let apfsFreeBytes: UInt64
    public let macosAvailableBytes: UInt64?
    /// macOS-reported purgeable space (available − APFS free).
    public let purgeableBytes: UInt64?
    public let timeMachineSnapshots: UInt64?

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.role == "disk", let cap = m.uint64("capacity_bytes"), let used = m.uint64("used_bytes")
        else { return nil }
        capacityBytes = cap
        usedBytes = used
        apfsFreeBytes = m.uint64("apfs_free_bytes") ?? cap - min(cap, used)
        macosAvailableBytes = m.uint64("macos_available_bytes")
        purgeableBytes = m.uint64("estimated_reclaimable_bytes")
        timeMachineSnapshots = m.uint64("local_time_machine_snapshot_count")
    }
}

public struct MemoryMetric: Sendable {
    public let usedBytes: UInt64
    public let totalBytes: UInt64?
    public let compressedBytes: UInt64
    public let pressurePercent: UInt64?
    public let freePercent: UInt64?

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.role == "memory", let used = m.uint64("used_bytes") else { return nil }
        usedBytes = used
        totalBytes = m.uint64("total_bytes")
        compressedBytes = m.uint64("compressed_bytes") ?? 0
        pressurePercent = m.uint64("pressure_percent")
        freePercent = m.uint64("free_percent")
    }

    public var fraction: Double? {
        guard let total = totalBytes, total > 0 else { return nil }
        return min(1, Double(usedBytes) / Double(total))
    }
}

public struct SwapMetric: Sendable {
    public let usedBytes: UInt64
    public let totalBytes: UInt64

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.role == "swap", let used = m.uint64("used_bytes"), let total = m.uint64("total_bytes")
        else { return nil }
        usedBytes = used
        totalBytes = total
    }

    public var fraction: Double { totalBytes > 0 ? min(1, Double(usedBytes) / Double(totalBytes)) : 0 }
}

public struct CpuMetric: Sendable {
    public let load1: Double
    public let load5: Double
    public let load15: Double
    public let cores: UInt64

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.role == "cpu", let l1 = m.double("load_1") else { return nil }
        load1 = l1
        load5 = m.double("load_5") ?? l1
        load15 = m.double("load_15") ?? l1
        cores = m.uint64("cores") ?? 0
    }
}

public struct ProcessMetric: Sendable {
    public let pid: UInt64?
    public let cpuPercent: Double
    public let memoryPercent: Double
    public let rssBytes: UInt64?
    public let command: String?

    public init?(_ f: Finding) {
        guard f.kind == .processResource else { return nil }
        let m = f.meta
        pid = m.uint64("pid")
        cpuPercent = m.double("cpu_percent") ?? 0
        memoryPercent = m.double("memory_percent") ?? 0
        rssBytes = m.uint64("rss_bytes")
        command = m.string("command")
    }
}

// MARK: - Sections

extension Finding {
    /// Disk allocation category name (`DiskCategory` findings).
    public var diskCategory: String? {
        kind == .diskCategory ? (meta.string("category") ?? title) : nil
    }

    /// A macOS data library (Photos, Music, VM bundle…) sized as one item:
    /// context for where the disk went, never a cleanup candidate.
    public var isDataLibraryPackage: Bool {
        kind == .largeFile && meta.has("package")
    }

    /// Build artifacts older than the configured staleness window.
    public var isStaleArtifact: Bool {
        kind == .buildArtifact && meta.bool("stale") == true
    }

    /// Homebrew `install_reason`: requested | dependency | unknown.
    public var brewInstallReason: String? {
        kind == .brewFormula ? meta.string("install_reason") : nil
    }

    public var isBrewAutoremoveCandidate: Bool {
        kind == .brewFormula && meta.bool("autoremove_candidate") == true
    }

    public var isBrewOutdated: Bool {
        (kind == .brewFormula || kind == .brewCask) && meta.bool("outdated") == true
    }

    /// The Brew scanner's `__autoremove__` summary row (not a package).
    public var isBrewSummaryRow: Bool {
        kind == .brewFormula && meta.has("candidates")
    }

    /// App classification: system | user | app_store | unmanaged | cask.
    public var appClassification: String? {
        kind == .app ? meta.string("classification") : nil
    }

    public var isIntelOnlyApp: Bool {
        kind == .app && meta.bool("rosetta_or_intel_only") == true
    }
}

// MARK: - iOS Devices

/// The storage numbers on one USB-connected iPhone/iPad (`IosDevice`
/// findings with numbers; status rows — no device, tools missing — carry
/// none and produce nil). All from `ideviceinfo -q com.apple.disk_usage`.
///
/// Two consistent tilings of `capacityBytes`, never mixed: apps + unattributed
/// + free (where the bytes are), and committed + purgeable + free (what iOS
/// can free on its own). App data overlaps purgeable by an unknown amount,
/// which is why "apps" and "purgeable" must not share a bar.
public struct IosDeviceStorage: Sendable {
    public let name: String
    public let productType: String
    public let iosVersion: String
    public let udid: String
    public let capacityBytes: UInt64
    public let usedBytes: UInt64
    public let freeBytes: UInt64
    /// What iOS could free on demand beyond `freeBytes`.
    public let purgeableBytes: UInt64
    /// Stays used after iOS purges everything it can.
    public let committedBytes: UInt64
    public let appsBytes: UInt64
    public let appCount: Int
    /// Media, Messages, system, purgeable caches — what USB can't split.
    public let unattributedBytes: UInt64

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.kind == .iosDevice, let cap = m.uint64("capacity_bytes"), let used = m.uint64("used_bytes")
        else { return nil }
        name = m.string("device") ?? f.title
        productType = m.string("product_type") ?? ""
        iosVersion = m.string("ios_version") ?? ""
        udid = m.string("udid") ?? ""
        capacityBytes = cap
        usedBytes = used
        freeBytes = m.uint64("free_bytes") ?? cap - min(cap, used)
        purgeableBytes = m.uint64("purgeable_bytes") ?? 0
        committedBytes = m.uint64("committed_bytes") ?? used
        appsBytes = m.uint64("apps_bytes") ?? 0
        appCount = Int(m.uint64("app_count") ?? 0)
        unattributedBytes = m.uint64("unattributed_bytes") ?? used - min(used, appsBytes)
    }
}

/// One app on a connected iOS device: bundle size vs. its data.
public struct IosAppUsage: Sendable {
    public let bundleId: String
    public let device: String
    /// `User` or `System`.
    public let appType: String
    public let version: String?
    public let staticBytes: UInt64
    public let dynamicBytes: UInt64

    public init?(_ f: Finding) {
        let m = f.meta
        guard f.kind == .iosApp, let bundleId = m.string("bundle_id") else { return nil }
        self.bundleId = bundleId
        device = m.string("device") ?? ""
        appType = m.string("app_type") ?? "User"
        version = m.string("app_version")
        staticBytes = m.uint64("static_bytes") ?? 0
        dynamicBytes = m.uint64("dynamic_bytes") ?? 0
    }
}

// MARK: - Attribution (Projects / App Storage)

extension Finding {
    /// The three synthetic per-axis rows (`bucket_findings` in
    /// `src/attribution/mod.rs`): Baseline, Unattributed, Coverage.
    public var isAttributionBucket: Bool {
        kind == .projectBucket || kind == .appStorageBucket
    }

    /// `baseline` | `unattributed` | `coverage` for a bucket finding, `nil`
    /// otherwise. `bucket_findings` sets `title` literally to
    /// "Baseline"/"Unattributed"/"Coverage" — the most stable signal
    /// available in the FFI's `Finding` (its `key` only feeds the id hash,
    /// it isn't a field).
    public var bucketKind: String? {
        guard isAttributionBucket else { return nil }
        switch title {
        case "Baseline": return "baseline"
        case "Unattributed": return "unattributed"
        case "Coverage": return "coverage"
        default: return nil
        }
    }
}

extension OwnerKind {
    /// Mirrors `OwnerKind::label()` (`src/attribution/model.rs`) for display.
    public var label: String {
        switch self {
        case .project: "Project"
        case .app: "App"
        case .formula: "Formula"
        case .homebrew: "Homebrew"
        case .tool: "Tool"
        case .baseline: "Baseline"
        case .unattributed: "Unattributed"
        }
    }

    /// Reverses `label` — the string an owner Finding's `meta.owner_kind`
    /// carries.
    public init?(label: String) {
        switch label {
        case "Project": self = .project
        case "App": self = .app
        case "Formula": self = .formula
        case "Homebrew": self = .homebrew
        case "Tool": self = .tool
        case "Baseline": self = .baseline
        case "Unattributed": self = .unattributed
        default: return nil
        }
    }
}

extension EvidenceTier {
    /// Mirrors `EvidenceTier::label()` for display: how confident the link
    /// from an entry to its owner is, strongest first.
    public var label: String {
        switch self {
        case .exact: "exact"
        case .nameMatch: "name match"
        case .observed: "observed"
        case .ecosystemDefault: "ecosystem default"
        case .curated: "curated"
        }
    }

    /// Reverses `label` — the string `meta.top_tier` carries.
    public init?(label: String) {
        switch label {
        case "exact": self = .exact
        case "name match": self = .nameMatch
        case "observed": self = .observed
        case "ecosystem default": self = .ecosystemDefault
        case "curated": self = .curated
        default: return nil
        }
    }
}

extension EntryKind {
    /// Mirrors `EntryKind::label()` for display.
    public var label: String {
        switch self {
        case .workingTree: "Working tree"
        case .artifacts: "Artifacts"
        case .worktree: "Worktree"
        case .packageCache: "Package cache"
        case .toolchain: "Toolchain"
        case .xcode: "Xcode"
        case .simulator: "Simulator"
        case .docker: "Docker"
        case .agentState: "Agent state"
        case .editorState: "Editor state"
        case .projectCache: "Project cache"
        case .appBundle: "App bundle"
        case .container: "Container"
        case .groupContainer: "Group container"
        case .appSupport: "App support"
        case .cache: "Cache"
        case .preferences: "Preferences"
        case .logs: "Logs"
        case .webData: "Web data"
        case .savedState: "Saved state"
        case .dotDir: "Dot dir"
        case .data: "Data"
        case .other: "Other"
        }
    }

    /// Reverses `label` — the string each `meta.by_kind[].kind` entry
    /// carries (the typed entries themselves, from
    /// `Engine.footprint(findingId:)`, already carry the FFI enum).
    public init?(label: String) {
        switch label {
        case "Working tree": self = .workingTree
        case "Artifacts": self = .artifacts
        case "Worktree": self = .worktree
        case "Package cache": self = .packageCache
        case "Toolchain": self = .toolchain
        case "Xcode": self = .xcode
        case "Simulator": self = .simulator
        case "Docker": self = .docker
        case "Agent state": self = .agentState
        case "Editor state": self = .editorState
        case "Project cache": self = .projectCache
        case "App bundle": self = .appBundle
        case "Container": self = .container
        case "Group container": self = .groupContainer
        case "App support": self = .appSupport
        case "Cache": self = .cache
        case "Preferences": self = .preferences
        case "Logs": self = .logs
        case "Web data": self = .webData
        case "Saved state": self = .savedState
        case "Dot dir": self = .dotDir
        case "Data": self = .data
        case "Other": self = .other
        default: return nil
        }
    }
}

extension ProcKind {
    public var label: String {
        switch self {
        case .shell: "shell"
        case .server: "server"
        case .other: "other"
        }
    }
}

/// One resource-kind's byte total within an owner's `by_kind` breakdown
/// (`OwnerSummary.byKind`). `kind` is `nil` when the label doesn't match any
/// known `EntryKind` (forward-compatible with a scanner-only label).
public struct OwnerKindBytes: Sendable, Equatable {
    public let kind: EntryKind?
    public let label: String
    public let bytes: UInt64
}

/// Typed view of a Projects/App-Storage owner Finding's summary
/// (`FindingKind.project`/`.appOwner`) — the `meta` keys `footprint_finding`
/// (`src/attribution/mod.rs`) writes. The entry-level breakdown is fetched
/// separately, on demand, via `Engine.footprint(findingId:)`.
public struct OwnerSummary: Sendable, Equatable {
    public let ownerKey: String
    public let ownerKind: OwnerKind?
    public let exclusive: UInt64
    public let shared: UInt64
    public let reach: UInt64
    public let baselineShare: UInt64
    public let byKind: [OwnerKindBytes]
    public let entryCount: Int
    public let worktrees: [String]
    public let processCount: Int
    public let ports: [Int]
    public let topTier: EvidenceTier?
    public let cloneNote: Bool
    public let group: String?

    /// `sizeBytes` on the finding is always `exclusive + shared`
    /// (`footprint_finding`); exposed here so callers don't have to add it
    /// back up themselves.
    public var sizeBytes: UInt64 { exclusive + shared }

    public init?(_ f: Finding) {
        guard f.kind == .project || f.kind == .appOwner else { return nil }
        let m = f.meta
        guard let ownerKey = m.string("owner_key"),
            let exclusive = m.uint64("exclusive"),
            let shared = m.uint64("shared"),
            let reach = m.uint64("reach"),
            let baselineShare = m.uint64("baseline_share")
        else { return nil }
        self.ownerKey = ownerKey
        self.ownerKind = m.string("owner_kind").flatMap(OwnerKind.init(label:))
        self.exclusive = exclusive
        self.shared = shared
        self.reach = reach
        self.baselineShare = baselineShare
        self.byKind = m.array("by_kind").compactMap { raw -> OwnerKindBytes? in
            guard let dict = raw as? [String: Any], let label = dict["kind"] as? String,
                let bytesNumber = dict["bytes"] as? NSNumber, bytesNumber.doubleValue >= 0
            else { return nil }
            return OwnerKindBytes(
                kind: EntryKind(label: label), label: label, bytes: UInt64(bytesNumber.doubleValue))
        }
        self.entryCount = Int(m.uint64("entry_count") ?? 0)
        self.worktrees = m.strings("worktrees")
        self.processCount = Int(m.uint64("process_count") ?? 0)
        self.ports = m.array("ports").compactMap { ($0 as? NSNumber)?.intValue }
        self.topTier = m.string("top_tier").flatMap(EvidenceTier.init(label:))
        self.cloneNote = m.bool("clone_note") ?? false
        self.group = m.string("group")
    }
}
