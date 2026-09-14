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
