import Foundation

/// The engine surface the app talks to. `Engine` (generated) conforms; a
/// stub can stand in for previews and tests. Keep this to what the app
/// actually calls.
public protocol MacAuditEngine: AnyObject, Sendable {
    func selectedRoot() -> String
    func setRoot(root: String) throws
    @discardableResult
    func startRun(root: String, listener: ScanListener) throws -> UInt64
    func sessionMetadata() -> SessionMetadata
    func dirChildrenPage(path: String, offset: UInt64, limit: UInt32) throws -> DirectoryPage
    func dirAncestors(path: String) -> [DirEntry]
    func nameSearch(query: String, limit: UInt32, cancellation: QueryCancellation) throws -> DirectorySearchPage
    func findingsPage(section: SectionId, offset: UInt64, limit: UInt32) throws -> FindingsPage
    func findingsPageForRun(section: SectionId, runId: UInt64, revision: UInt64?, requestId: UInt64?, offset: UInt64, limit: UInt32) throws -> FindingsPage
    func findingsCursorPage(cursor: FindingsCursor, limit: UInt32) throws -> FindingsPage
    func sectionSummary(section: SectionId, runId: UInt64) throws -> SectionSummary
    func liveFilesPage(path: String, limit: UInt32) throws -> LiveFilesPage
    func footprintEntriesPage(findingId: UInt64, offset: UInt64, limit: UInt32) throws -> FootprintEntriesPage
    func footprintForRun(findingId: UInt64, runId: UInt64) throws -> Footprint?
    func footprintEntriesPageForRun(findingId: UInt64, runId: UInt64, revision: UInt64?, requestId: UInt64?, offset: UInt64, limit: UInt32) throws -> FootprintEntriesPage
    func footprintCursorPage(cursor: FootprintCursor, limit: UInt32) throws -> FootprintEntriesPage
    func footprintBucketsForRun(axis: Axis, runId: UInt64) throws -> FootprintBuckets?
    func openNameQuery(query: String, limit: UInt32, cancellation: QueryCancellation) throws -> DirectoryCursor
    func directoryQueryPage(cursor: DirectoryCursor, limit: UInt32) throws -> DirectoryQueryPage
    func releaseDirectoryQuery(cursor: DirectoryCursor)
    func sections() -> [SectionMeta]
    func deleteMode() -> DeleteMode
    func configPath() -> String
    func fullDiskAccess() -> Bool
    @discardableResult
    func startScan(sections: [SectionId], listener: ScanListener) -> UInt64
    func cancelScan()
    func findings(section: SectionId) -> [Finding]
    func plan(selection: [Selection]) throws -> Plan
    func execute(plan: Plan, listener: ExecListener) throws
    func cancelCleanup()
    func dirRoot() -> DirEntry?
    func dirEntry(path: String) -> DirEntry?
    func dirChildren(path: String) -> [DirEntry]
    func dirSubtree(path: String, depth: UInt32, maxNodes: UInt32) -> [DirEntry]
    func dirTopFiles(path: String, n: UInt32) -> [TopFile]
    func largestFiles(n: UInt32) -> [TopFile]
    func dirTreeStats() -> DirTreeStats?
    func footprint(findingId: UInt64) -> Footprint?
    func footprintBuckets(axis: Axis) -> FootprintBuckets?
}

extension Engine: MacAuditEngine {}

extension MacAuditEngine {
    public func selectedRoot() -> String { FileManager.default.homeDirectoryForCurrentUser.path }
    public func setRoot(root: String) throws { throw MacAuditError.Invalid(message: "root selection is unavailable") }
    public func startRun(root: String, listener: ScanListener) throws -> UInt64 {
        try setRoot(root: root)
        return startScan(sections: SectionId.allCases, listener: listener)
    }
    public func sessionMetadata() -> SessionMetadata {
        SessionMetadata(runId: 0, selectedRoot: selectedRoot(), revision: 0, startedAtMs: 0, queriedAtMs: 0,
            diskComplete: false, diskErrors: 0, diskElapsedMs: 0, auditComplete: false,
            cancelled: false, diskCoverage: "unavailable", auditCoverage: "unavailable",
            walkCoverage: WalkCoverage(unreadable: 0, excluded: 0, dataless: 0, aliases: 0,
                mounts: 0, cancelled: false, resourceLimited: false, summariesTruncated: false,
                deadline: false, entryLimit: false, unsupportedPaths: 0),
            diskStopReasons: [], auditStopReasons: [], activeScanners: 0, retiringCount: 0, retiringRuns: [], queryMemory: nil)
    }
    public func liveFilesPage(path: String, limit: UInt32) throws -> LiveFilesPage {
        guard limit > 0, limit <= 500 else { throw MacAuditError.Invalid(message: "page must contain 1...500 entries") }
        return LiveFilesPage(requestId: 0, subjectPath: path, metadata: sessionMetadata(), observedAtMs: 0, coverage: "unavailable",
            files: dirTopFiles(path: path, n: limit), dataless: 0, errors: 0, truncated: false,
            stopReasons: ["unavailable"])
    }
    public func footprintEntriesPage(findingId: UInt64, offset: UInt64, limit: UInt32) throws -> FootprintEntriesPage {
        guard limit > 0, limit <= 500, offset <= UInt64(Int.max) else {
            throw MacAuditError.Invalid(message: "page must contain 1...500 entries")
        }
        let metadata = sessionMetadata()
        let groups = footprint(findingId: findingId)?.groups ?? []
        let rows = groups.lazy.flatMap(\.entries)
        let entries = Array(rows.dropFirst(Int(offset)).prefix(Int(limit)))
        let end = offset + UInt64(entries.count)
        return FootprintEntriesPage(metadata: metadata, findingId: findingId, requestId: 0,
            revision: metadata.revision, total: UInt64(rows.count), entries: entries,
            nextOffset: end < UInt64(rows.count) ? end : nil, nextCursor: end < UInt64(rows.count) ? FootprintCursor(
                findingId: findingId, runId: metadata.runId, revision: metadata.revision, requestId: 0, offset: end) : nil)
    }
    public func footprintForRun(findingId: UInt64, runId: UInt64) throws -> Footprint? {
        guard sessionMetadata().runId == runId else { throw MacAuditError.Invalid(message: "owner belongs to a retired run") }
        return footprint(findingId: findingId)
    }
    public func footprintEntriesPageForRun(findingId: UInt64, runId: UInt64, revision: UInt64?, requestId: UInt64?, offset: UInt64, limit: UInt32) throws -> FootprintEntriesPage {
        let metadata = sessionMetadata()
        guard metadata.runId == runId, revision == nil || revision == metadata.revision,
            offset == 0 || (revision != nil && requestId != nil) else {
            throw MacAuditError.Invalid(message: "owner page belongs to a retired run or revision")
        }
        return try footprintEntriesPage(findingId: findingId, offset: offset, limit: limit)
    }
    public func footprintCursorPage(cursor: FootprintCursor, limit: UInt32) throws -> FootprintEntriesPage {
        try footprintEntriesPageForRun(findingId: cursor.findingId, runId: cursor.runId,
            revision: cursor.revision, requestId: cursor.requestId, offset: cursor.offset, limit: limit)
    }
    public func footprintBucketsForRun(axis: Axis, runId: UInt64) throws -> FootprintBuckets? {
        guard sessionMetadata().runId == runId else { throw MacAuditError.Invalid(message: "owner buckets belong to a retired run") }
        return footprintBuckets(axis: axis)
    }
    public func openNameQuery(query: String, limit: UInt32, cancellation: QueryCancellation) throws -> DirectoryCursor {
        throw MacAuditError.Invalid(message: "query handles are unavailable")
    }
    public func directoryQueryPage(cursor: DirectoryCursor, limit: UInt32) throws -> DirectoryQueryPage {
        throw MacAuditError.Invalid(message: "query handles are unavailable")
    }
    public func releaseDirectoryQuery(cursor: DirectoryCursor) {}
    public func dirChildrenPage(path: String, offset: UInt64, limit: UInt32) throws -> DirectoryPage {
        guard limit > 0, limit <= 500, offset <= UInt64(Int.max) else {
            throw MacAuditError.Invalid(message: "page must contain 1...500 entries")
        }
        let children = dirChildren(path: path)
        let entries = Array(children.dropFirst(Int(offset)).prefix(Int(limit)))
        let end = offset + UInt64(entries.count)
        return DirectoryPage(requestId: 0, subjectPath: path, metadata: sessionMetadata(), entries: entries,
            nextOffset: end < UInt64(children.count) ? end : nil, truncated: end < UInt64(children.count))
    }
    public func dirAncestors(path: String) -> [DirEntry] { [] }
    public func nameSearch(query: String, limit: UInt32, cancellation: QueryCancellation) throws -> DirectorySearchPage {
        DirectorySearchPage(requestId: 0, query: query, metadata: sessionMetadata(), entries: [], files: [],
                            observedAtMs: 0, coverage: "unavailable", stopReasons: ["unavailable"],
                            truncated: false, cancelled: cancellation.isCancelled())
    }
    public func findingsPage(section: SectionId, offset: UInt64, limit: UInt32) throws -> FindingsPage {
        guard limit > 0, limit <= 500, offset <= UInt64(Int.max) else {
            throw MacAuditError.Invalid(message: "page must contain 1...500 entries")
        }
        let rows = findings(section: section)
        let entries = Array(rows.dropFirst(Int(offset)).prefix(Int(limit)))
        let end = offset + UInt64(entries.count)
        let metadata = sessionMetadata()
        return FindingsPage(metadata: metadata, requestId: 0, revision: metadata.revision,
            total: UInt64(rows.count), findings: entries,
            nextOffset: end < UInt64(rows.count) ? end : nil, nextCursor: end < UInt64(rows.count) ? FindingsCursor(
                section: section, runId: metadata.runId, revision: metadata.revision, requestId: 0, offset: end) : nil)
    }
    public func findingsPageForRun(section: SectionId, runId: UInt64, revision: UInt64?, requestId: UInt64?, offset: UInt64, limit: UInt32) throws -> FindingsPage {
        let metadata = sessionMetadata()
        guard metadata.runId == runId, revision == nil || revision == metadata.revision,
            offset == 0 || (revision != nil && requestId != nil) else {
            throw MacAuditError.Invalid(message: "finding page belongs to a retired run or revision")
        }
        return try findingsPage(section: section, offset: offset, limit: limit)
    }
    public func findingsCursorPage(cursor: FindingsCursor, limit: UInt32) throws -> FindingsPage {
        try findingsPageForRun(section: cursor.section, runId: cursor.runId, revision: cursor.revision,
            requestId: cursor.requestId, offset: cursor.offset, limit: limit)
    }
    public func sectionSummary(section: SectionId, runId: UInt64) throws -> SectionSummary {
        let metadata = sessionMetadata()
        guard metadata.runId == runId else { throw MacAuditError.Invalid(message: "section belongs to a retired run") }
        let rows = findings(section: section).prefix(500)
        return SectionSummary(metadata: metadata, section: section, total: UInt64(rows.count),
            reportedBytes: rows.reduce(0) { $0 &+ ($1.sizeBytes ?? 0) }, terminal: false, error: nil)
    }
}

extension DirEntry: Identifiable {
    public var id: String { path }
}

extension TopFile: Identifiable {
    public var id: String { path }
}

extension SectionId: CaseIterable {
    /// Sidebar order — the same order as `Engine.sections()`.
    public static let allCases: [SectionId] = [
        .system, .apps, .brew, .tools, .fs, .projects, .appStorage, .launchd,
        .shellEnv, .runtimes, .docker, .ports, .git, .simulator, .ios,
        .sshKeys, .timeMachine,
    ]
}

extension SectionId: Identifiable {
    public var id: Self { self }
}

extension Finding: Identifiable {}

extension FootprintEntry: Identifiable {
    public var id: String { path }
}

extension SectionId {
    /// The engine's section slug (`macaudit scan --section <slug>`).
    public var slug: String {
        switch self {
        case .system: "system"
        case .apps: "apps"
        case .brew: "brew"
        case .tools: "tools"
        case .fs: "fs"
        case .projects: "projects"
        case .appStorage: "app_storage"
        case .launchd: "launchd"
        case .shellEnv: "shell_env"
        case .runtimes: "runtimes"
        case .docker: "docker"
        case .ports: "ports"
        case .git: "git"
        case .simulator: "simulator"
        case .ios: "ios"
        case .sshKeys: "ssh_keys"
        case .timeMachine: "time_machine"
        }
    }

    /// The attribution axis this section is a lens over, `nil` for every
    /// other section.
    public var attributionAxis: AttributionAxis? {
        switch self {
        case .projects: .projects
        case .appStorage: .appStorage
        default: nil
        }
    }
}
