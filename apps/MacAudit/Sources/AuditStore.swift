import AppKit
import Foundation
import MacAuditCollections
import MacAuditKit
import Observation

enum SectionStatus: Equatable {
    case idle
    case scanning(msg: String, done: UInt64, total: UInt64?)
    case done(durationMs: UInt64?)
    case failed(String)

    var isTerminal: Bool {
        switch self {
        case .done, .failed: true
        case .idle, .scanning: false
        }
    }
}

enum SheetRoute: String {
    case root, confirm, cleanup
}

/// One cleanup batch from confirmation to report.
struct CleanupRun {
    enum Phase: Equatable {
        case preflight
        case executing(index: Int, total: Int)
        case verifying
        case done
    }

    var phase: Phase = .preflight
    var actions: [PlannedActionView]
    var refused: [RefusedAction]
    var results: [Int: (ok: Bool, message: String)] = [:]
    var cancelled: [PlannedActionView] = []
    var cancelRequested = false
    var summary: String?
    var reportPath: String?
    var reportJSON: String?
}

/// What the sidebar can select: the Storage overview, the Projects/Apps
/// attribution lenses, a scanner section, or the Folders drill-down.
enum SidebarItem: Hashable {
    case storage
    case projects
    case apps
    case section(SectionId)
    case folders

    /// The scanner section backing this item, for rescan/status lookups.
    /// `.projects`/`.apps` map to their underlying `SectionId` even though
    /// they aren't reachable through `.section(_:)` — they're top-level
    /// lenses, not entries in the generic Sections list.
    var section: SectionId? {
        switch self {
        case let .section(id): id
        case .projects: .projects
        case .apps: .appStorage
        case .storage, .folders: nil
        }
    }

    /// The attribution axis this item is a lens over, `nil` for every other
    /// item.
    var axis: AttributionAxis? {
        switch self {
        case .projects: .projects
        case .apps: .appStorage
        default: nil
        }
    }
}

extension AttributionAxis {
    /// The sidebar item this axis opens — `AuditStore.openOwner`,
    /// `SectionSidebar`, and `ContentView`'s detail switch all key off this.
    var sidebarItem: SidebarItem {
        switch self {
        case .projects: .projects
        case .appStorage: .apps
        }
    }
}

/// The app's single source of truth: the TUI's `AppState` in Swift. Owns the
/// engine, ingests scan/cleanup events on the main actor, and holds the
/// UI-only state (selection, marks, remedy choices).
@MainActor
@Observable
final class AuditStore {
    private struct RetainedFinding {
        var finding: Finding
        var metadata: SessionMetadata?
    }

    private(set) var engine: any MacAuditEngine
    private(set) var sections: [SectionMeta]
    let auditPages: AuditFindingsBrowser
    private var retainedMarks: OrderedDictionary<UInt64, RetainedFinding> = [:]
    var findings: [SectionId: [UInt64: Finding]] {
        var result: [SectionId: [UInt64: Finding]] = [:]
        for finding in auditPages.cachedRows {
            result[finding.section, default: [:]][finding.id] = finding
        }
        return result
    }

    private(set) var status: [SectionId: SectionStatus] = [:]
    private var expectedGen: [SectionId: UInt64] = [:]
    private(set) var activity: [String] = []
    let browser: DirBrowser
    /// One `OwnerBrowser` per attribution axis, keyed the same way
    /// `LensView`/`ContentView` look them up (`SidebarItem.axis`).
    let owners: [AttributionAxis: OwnerBrowser]

    var selectedItem: SidebarItem? = .folders {
        didSet {
            if oldValue != selectedItem {
                selectedFinding = nil
                searchText = ""
                auditPages.select(selectedItem?.section ?? (selectedItem == .storage ? .system : nil))
            }
        }
    }

    var selectedFinding: UInt64?
    /// Free-text filter for the current section (title / detail / path).
    var searchText = ""
    var marked: Set<UInt64> = []
    var remedyChoice: [UInt64: Int] = [:]

    /// The plan awaiting confirmation (sheet is shown while non-nil).
    private(set) var pendingPlan: Plan?
    private(set) var pendingSummary: PlanSummary?
    private(set) var planError: String?
    private(set) var cleanup: CleanupRun?
    var sheetRoute: SheetRoute?
    private(set) var isPlanning = false
    private(set) var selectedRoot: String
    private(set) var rootError: String?
    private(set) var isStartingRun = false
    private let homeRoot: String
    private var runGeneration: UInt64 = 0
    private var planGeneration: UInt64 = 0
    private var runTask: Task<Void, Never>?
    private let queries: MacAuditQueries

    var canRefresh: Bool {
        !isStartingRun && !isPlanning && cleanup == nil && pendingPlan == nil
    }

    let usingFakeData: Bool
    private var scanBridge: ScanMailbox?
    private var scanTask: Task<Void, Never>?
    private var retirementTask: Task<Void, Never>?
    private var currentRunId: UInt64?
    private(set) var scanMetadata: SessionMetadata?
    private(set) var scanCancelRequested = false
    private let revealLocation: @MainActor (String) -> Void

    var canCancelScan: Bool {
        !isStartingRun && cleanup == nil && scanBridge != nil && isScanning && !scanCancelRequested
    }

    var isRetiringScan: Bool {
        scanCancelRequested && (scanMetadata?.activeScanners ?? 1) > 0
    }

    var scanCancellationStatus: String? {
        guard scanCancelRequested else { return nil }
        guard let metadata = scanMetadata else { return "Cancelling scan · waiting for worker status…" }
        if metadata.activeScanners > 0 {
            return "Cancelling scan · \(metadata.activeScanners) workers retiring · partial results remain available"
        }
        return "Scan cancelled · partial results retained · Disk: \(metadata.diskCoverage) · Global Audit: \(metadata.auditCoverage)"
    }

    /// Whether the engine can currently read TCC-protected user data
    /// (Safari, Mail, …). Refreshed after every fs scan and whenever the app
    /// becomes active again (the user may have just granted it in System
    /// Settings), so the banner clears without a rescan.
    var hasFullDiskAccess = true

    init(engine: any MacAuditEngine, usingFakeData: Bool,
         initialRoot: String = FileManager.default.homeDirectoryForCurrentUser.path,
         homeRoot: String? = nil,
         revealLocation: @escaping @MainActor (String) -> Void = {
             NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: $0)])
         })
    {
        self.engine = engine
        selectedRoot = initialRoot
        self.homeRoot = homeRoot ?? FileManager.default.homeDirectoryForCurrentUser.path
        self.revealLocation = revealLocation
        queries = MacAuditQueries(engine: engine)
        auditPages = AuditFindingsBrowser(engine: engine)
        self.usingFakeData = usingFakeData
        sections = engine.sections()
        browser = DirBrowser(engine: engine)
        owners = [
            .projects: OwnerBrowser(axis: .projects, engine: engine),
            .appStorage: OwnerBrowser(axis: .appStorage, engine: engine),
        ]
        refreshFullDiskAccess()
        // The store lives as long as the app; the observation ends with it.
        Task { [weak self] in
            for await _ in NotificationCenter.default.notifications(named: NSApplication.didBecomeActiveNotification) {
                guard let self else { return }
                refreshFullDiskAccess()
            }
        }
    }

    /// Re-probes Full Disk Access off-main and applies the result on the
    /// main actor.
    func refreshFullDiskAccess() {
        let engine = engine
        Task {
            let ok = await Task.detached { engine.fullDiskAccess() }.value
            hasFullDiskAccess = ok
        }
    }

    // MARK: - Reads

    func meta(for id: SectionId) -> SectionMeta? {
        sections.first { $0.id == id }
    }

    /// `sections` minus the Projects/App Storage lenses — they're top-level
    /// items (Sidebar) and axis-driven rescans, not generic scanner sections;
    /// kept out of the Sections list (`SectionSidebar`), the Refresh-All menu
    /// (`MacAuditApp`), and the menu bar extra the same way.
    var scanSections: [SectionMeta] {
        sections.filter { $0.id != .projects && $0.id != .appStorage }
    }

    func status(of id: SectionId) -> SectionStatus {
        status[id] ?? .idle
    }

    var selectedSection: SectionId? {
        selectedItem?.section
    }

    func findings(in id: SectionId) -> [Finding] {
        auditPages.findings(in: id)
    }

    /// Findings from the fs section whose path is under (or equal to) `path`
    /// — used by the Folders inspector to scope findings to a directory.
    /// Disk findings at or below `path`, largest first.
    func fsFindings(under path: String) -> [Finding] {
        findings(in: .fs)
            .filter { finding in
                guard let findingPath = finding.path else { return false }
                return findingPath == path || findingPath.hasPrefix(path == "/" ? "/" : path + "/")
            }
            .sorted { ($0.sizeBytes ?? 0) > ($1.sizeBytes ?? 0) }
    }

    /// `findings(in:)` narrowed by `searchText`.
    func visibleFindings(in id: SectionId) -> [Finding] {
        let all = findings(in: id)
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return all }
        return all.filter {
            $0.title.localizedCaseInsensitiveContains(q)
                || $0.detail.localizedCaseInsensitiveContains(q)
                || ($0.path?.localizedCaseInsensitiveContains(q) ?? false)
                || $0.group.localizedCaseInsensitiveContains(q)
        }
    }

    /// Bytes the last cleanup batch actually reclaimed (executed actions only).
    var lastReclaimedBytes: UInt64 {
        guard let run = cleanup else { return 0 }
        return run.results.filter(\.value.ok).keys
            .compactMap { run.actions[safe: $0]?.reclaimsBytes }
            .reduce(0, +)
    }

    func finding(_ id: UInt64?) -> Finding? {
        guard let id else { return nil }
        if let finding = retainedMarks[id] {
            return finding.finding
        }
        for map in findings.values {
            if let f = map[id] {
                return f
            }
        }
        return nil
    }

    func count(of id: SectionId) -> Int {
        findings(in: id).count
    }

    func reclaimableBytes(in id: SectionId) -> UInt64 {
        findings(in: id)
            .filter { $0.severity == .reclaimable }
            .reduce(0) { $0 + ($1.sizeBytes ?? 0) }
    }

    var totalReclaimableBytes: UInt64 {
        SectionId.allCases.reduce(0) { $0 + reclaimableBytes(in: $1) }
    }

    /// The headline reclaimable figure partitioned by what it is. Same
    /// filter as `reclaimableBytes(in:)` (severity == reclaimable, `sizeBytes`),
    /// so the segments sum to `totalReclaimableBytes` by construction.
    var reclaimableBreakdown: [BarSegment] {
        var bytes: [String: UInt64] = [:]
        for f in findings.values.flatMap(\.values) where f.severity == .reclaimable {
            guard let size = f.sizeBytes, size > 0 else { continue }
            let name: String
            switch f.kind {
            case .buildArtifact: name = f.isStaleArtifact ? "Stale build artifacts" : "Recent build artifacts"
            case .cacheDir: name = "Caches"
            case .brewFormula: if f.isBrewSummaryRow {
                    continue
                } else {
                    name = "Homebrew"
                }
            case .dockerObject: name = "Docker"
            case .simulator: name = "Simulators"
            case .localSnapshot: name = "Time Machine snapshots"
            case .globalTool: name = "Orphaned tools"
            case .runtimeVersion: name = "Rust toolchains"
            default: name = "Other"
            }
            bytes[name, default: 0] += size
        }
        return bytes.map { BarSegment(name: $0.key, bytes: $0.value) }.sorted { $0.bytes > $1.bytes }
    }

    /// Attention items that carry bytes but are deliberately not counted as
    /// reclaimable: large files/packages and iOS backups need a human look.
    var attentionNotCounted: (bytes: UInt64, count: Int) {
        let items = findings.values.flatMap(\.values)
            .filter { ($0.kind == .largeFile || $0.kind == .iosBackup) && $0.severity != .reclaimable }
            .filter { !$0.isDataLibraryPackage }
        return (items.reduce(0) { $0 + ($1.sizeBytes ?? 0) }, items.count)
    }

    var isScanning: Bool {
        status.values.contains {
            if case .scanning = $0 {
                true
            } else {
                false
            }
        }
    }

    // MARK: - Scanning

    func rescanAll() {
        guard canRefresh else { return }
        startRootRun(selectedRoot)
    }

    static func expandedRoot(_ input: String,
                             home: String = FileManager.default.homeDirectoryForCurrentUser.path) -> String?
    {
        let path = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, !path.contains("\0") else { return nil }
        let expanded: String = if path == "~" {
            home
        } else if path.hasPrefix("~/") {
            (home as NSString).appendingPathComponent(String(path.dropFirst(2)))
        } else if path.hasPrefix("/") {
            path
        } else {
            (home as NSString).appendingPathComponent(path)
        }
        return URL(fileURLWithPath: expanded).standardizedFileURL.path
    }

    func changeRoot(_ input: String) {
        guard canRefresh else { return }
        guard let path = Self.expandedRoot(input, home: homeRoot) else {
            rootError = "Enter a folder path. Relative paths are resolved against Home."
            return
        }
        startRootRun(path)
    }

    private func startRootRun(_ root: String) {
        runGeneration &+= 1
        let generation = runGeneration
        runTask?.cancel()
        isStartingRun = true
        rootError = nil
        let bridge = ScanMailbox()
        let queries = queries
        runTask = Task { [weak self] in
            do {
                let gen = try await queries.startRun(root: root, listener: bridge)
                let metadata = await queries.metadata()
                guard let self, runGeneration == generation, !Task.isCancelled else {
                    bridge.finish()
                    return
                }
                guard metadata.runId == gen else {
                    throw MacAuditError.Invalid(message: "The selected root belongs to a superseded run.")
                }
                acceptRootRun(metadata.selectedRoot, runId: gen, bridge: bridge)
            } catch {
                bridge.finish()
                guard let self, runGeneration == generation else { return }
                isStartingRun = false
                rootError = "\(error)"
            }
        }
    }

    private func acceptRootRun(_ root: String, runId: UInt64, bridge: ScanMailbox) {
        retirementTask?.cancel()
        retirementTask = nil
        currentRunId = runId
        scanMetadata = nil
        scanCancelRequested = false
        scanBridge?.finish()
        scanTask?.cancel()
        scanBridge = bridge
        selectedRoot = root
        expectedGen.removeAll()
        auditPages.reset()
        retainedMarks.removeAll()
        status.removeAll()
        activity.removeAll()
        marked.removeAll()
        remedyChoice.removeAll()
        selectedFinding = nil
        searchText = ""
        pendingPlan = nil
        pendingSummary = nil
        planGeneration &+= 1
        planError = nil
        rootError = nil
        sheetRoute = nil
        browser.reset()
        for owner in owners.values {
            owner.reset()
        }
        for section in sections {
            status[section.id] = .scanning(msg: "Starting…", done: 0, total: nil)
        }
        for section in sections {
            expectedGen[section.id] = runId
        }
        auditPages.activate(runId: runId, section: selectedItem?.section
            ?? (selectedItem == .storage ? .system : nil))
        bridge.activate(runId: runId)
        consume(bridge)
        isStartingRun = false
    }

    private func consume(_ bridge: ScanMailbox) {
        scanTask = Task { [weak self] in
            var revisions: [SectionId: UInt64] = [:]
            for await _ in bridge.updates {
                let snapshot = await bridge.snapshot()
                guard let self, scanBridge === bridge, !Task.isCancelled else { return }
                for (section, state) in snapshot.sections where expectedGen[section] == snapshot.runId {
                    let changed = revisions[section, default: 0] != state.revision
                    revisions[section] = state.revision
                    let wasTerminal = self.status(of: section).isTerminal
                    if let error = state.error {
                        self.status[section] = .failed(error)
                    } else if state.terminal {
                        self.status[section] = .done(durationMs: state.durationMs)
                    } else if !scanCancelRequested {
                        self.status[section] = .scanning(msg: state.progress ?? "", done: state.progressDone ?? 0,
                                                         total: state.progressTotal)
                    }
                    if changed || (state.terminal && !wasTerminal) {
                        self.auditPages.invalidate()
                        if section == .fs {
                            self.browser.inventoryChanged()
                            if state.terminal {
                                self.refreshFullDiskAccess()
                            }
                        }
                        if let axis = section.attributionAxis {
                            self.owners[axis]?.inventoryChanged()
                        }
                    }
                }
            }
        }
    }

    func cancelScan() {
        guard canCancelScan, let runId = currentRunId else { return }
        scanCancelRequested = true
        engine.cancelScan()
        auditPages.invalidate()
        browser.inventoryChanged()
        let queries = queries
        retirementTask = Task { [weak self] in
            while !Task.isCancelled {
                let metadata = await queries.metadata()
                guard let self, currentRunId == runId, metadata.runId == runId, !Task.isCancelled else { return }
                scanMetadata = metadata
                guard metadata.activeScanners == 0 else {
                    do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
                    continue
                }
                for section in sections where expectedGen[section.id] == runId {
                    let summary = try? await queries.sectionSummary(section: section.id, runId: runId)
                    guard currentRunId == runId, !Task.isCancelled else { return }
                    guard !status(of: section.id).isTerminal else { continue }
                    if let error = summary?.error {
                        status[section.id] = .failed(error)
                    } else if summary?.terminal == true {
                        status[section.id] = .done(durationMs: nil)
                    } else {
                        status[section.id] = .failed("Scan cancelled · partial results retained")
                    }
                }
                auditPages.invalidate()
                browser.inventoryChanged()
                for owner in owners.values {
                    owner.inventoryChanged()
                }
                return
            }
        }
    }

    /// Apply a scan event. Same rule as the engine session: only the
    /// generation a section currently expects is accepted.
    func apply(_ event: ScanEvent) {
        switch event {
        case let .sectionStarted(section, gen):
            guard expectedGen[section] == gen, !scanCancelRequested else { return }
            auditPages.invalidate()
            status[section] = .scanning(msg: "", done: 0, total: nil)
        case let .progress(section, gen, msg, done, total):
            guard expectedGen[section] == gen, !scanCancelRequested else { return }
            status[section] = .scanning(msg: msg, done: done, total: total)
        case let .findings(section, gen, _):
            guard expectedGen[section] == gen else { return }
            auditPages.invalidate()
            if section == .fs {
                browser.inventoryChanged()
            }
            if let axis = section.attributionAxis {
                owners[axis]?.inventoryChanged()
            }
        case let .sectionFinished(section, gen, durationMs):
            guard expectedGen[section] == gen else { return }
            status[section] = .done(durationMs: durationMs)
            auditPages.invalidate()
            if section == .fs {
                browser.refreshRoot()
                refreshFullDiskAccess()
            }
            if let axis = section.attributionAxis {
                owners[axis]?.refresh()
            }
        case let .sectionFailed(section, gen, error):
            guard expectedGen[section] == gen else { return }
            status[section] = .failed(error)
            push("\(section.slug): \(error)")
            auditPages.invalidate()
        case let .correlated(gen, batch), let .enriched(gen, batch):
            for f in batch {
                guard expectedGen[f.section] == gen else { continue }
                auditPages.invalidate()
            }
        }
    }

    // MARK: - Folders

    /// Switch the sidebar to Folders and drill the browser into `path`.
    func browse(path: String) {
        guard Self.containsLocation(path, under: selectedRoot) else {
            revealLocation(path)
            return
        }
        browser.navigate(to: path)
        selectedItem = .folders
        selectedFinding = nil
    }

    nonisolated static func containsLocation(_ path: String, under root: String) -> Bool {
        guard path.hasPrefix("/"), root.hasPrefix("/"), !path.contains("\0"), !root.contains("\0") else { return false }
        let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        let rootComponents = URL(fileURLWithPath: root).standardizedFileURL.pathComponents
        return components.starts(with: rootComponents)
    }

    func showFindings(under path: String) {
        selectedItem = .section(.fs)
        selectedFinding = nil
        searchText = ""
        auditPages.filterLocation(path)
    }

    // MARK: - Attribution lenses

    /// Switch the sidebar to the owning lens and open `owner`'s entity page
    /// — used by the "Largest projects"/"Largest apps" cards and by a lens
    /// table's double-click.
    func openOwner(_ owner: Finding, axis: AttributionAxis) {
        owners[axis]?.open(owner)
        selectedItem = axis.sidebarItem
        selectedFinding = nil
    }

    // MARK: - Marks

    func toggleMark(_ id: UInt64) {
        if marked.contains(id) {
            marked.remove(id)
            remedyChoice[id] = nil
            retainedMarks[id] = nil
        } else {
            guard marked.count < 256, let finding = finding(id) else { return }
            marked.insert(id)
            retainedMarks[id] = RetainedFinding(finding: finding, metadata: auditPages.metadata(for: id))
        }
    }

    func chooseRemedy(_ index: Int?, for id: UInt64) {
        guard marked.contains(id) || marked.count < 256, let finding = finding(id) else { return }
        remedyChoice[id] = index
        marked.insert(id)
        retainedMarks[id] = RetainedFinding(finding: finding, metadata: retainedMarks[id]?.metadata ?? auditPages.metadata(for: id))
    }

    var selection: [Selection] {
        marked.sorted().map { Selection(findingId: $0, remedyIndex: remedyChoice[$0].map(UInt32.init)) }
    }

    // MARK: - Cleanup

    /// Plan the marked findings and open the confirm sheet — even when
    /// everything was refused, so the user sees why.
    func openConfirm() {
        guard canRefresh else { return }
        let selection = selection
        guard !selection.isEmpty else { return }
        planError = nil
        isPlanning = true
        planGeneration &+= 1
        let generation = planGeneration
        let engine = engine
        Task {
            do {
                let (plan, summary) = try await Task.detached {
                    let plan = try engine.plan(selection: selection)
                    return (plan, plan.summary())
                }.value
                guard planGeneration == generation else { return }
                isPlanning = false
                pendingPlan = plan
                pendingSummary = summary
                sheetRoute = .confirm
            } catch {
                guard planGeneration == generation else { return }
                isPlanning = false
                planError = "\(error)"
            }
        }
    }

    func clearPlanError() {
        planError = nil
    }

    func dismissConfirm() {
        pendingPlan = nil
        pendingSummary = nil
        if sheetRoute == .confirm {
            sheetRoute = nil
        }
    }

    func executePendingPlan() {
        guard let plan = pendingPlan, let summary = pendingSummary else { return }
        dismissConfirm()
        for a in summary.actions {
            marked.remove(a.findingId)
            remedyChoice[a.findingId] = nil
            retainedMarks[a.findingId] = nil
        }
        cleanup = CleanupRun(actions: summary.actions, refused: summary.refused)
        sheetRoute = .cleanup
        let bridge = ExecBridge()
        do {
            try engine.execute(plan: plan, listener: bridge)
        } catch {
            cleanup = nil
            sheetRoute = nil
            planError = "\(error)"
            return
        }
        Task { [weak self] in
            for await event in bridge.events {
                guard let self else { return }
                apply(event)
            }
        }
    }

    func cancelCleanup() {
        if var run = cleanup {
            run.cancelRequested = true
            cleanup = run
        }
        engine.cancelCleanup()
    }

    func dismissCleanup() {
        if case .done = cleanup?.phase {
            cleanup = nil
            sheetRoute = nil
        }
    }

    func apply(_ event: ExecEvent) {
        // Work on a copy and write back once: `cleanup?.x = f(cleanup)` opens
        // a modify access on the observed property while the right-hand side
        // reads it, which the Swift runtime reports as an exclusivity
        // violation and aborts.
        guard var run = cleanup else { return }
        switch event {
        case let .preflightDone(ok, refused):
            run.actions = ok
            run.refused.append(contentsOf: refused)
            run.phase = .executing(index: 0, total: ok.count)
            if !refused.isEmpty {
                push("cleanup: \(refused.count) action(s) refused by the refreshed preflight")
            }
        case let .actionStarted(index):
            run.phase = .executing(index: Int(index), total: run.actions.count)
        case let .actionDone(index, ok, message):
            run.results[Int(index)] = (ok, message)
            if ok {
                push(message)
            } else {
                let rendered = run.actions[safe: Int(index)]?.rendered ?? ""
                push("error: \(rendered) — \(message)")
            }
        case let .executed(cancelled, rescanning, rescanGen):
            run.cancelled = cancelled
            run.phase = .verifying
            // The engine restarted these sections through the scan listener;
            // expect that generation so their events are accepted.
            if let gen = rescanGen {
                retirementTask?.cancel()
                retirementTask = nil
                currentRunId = gen
                scanMetadata = nil
                scanCancelRequested = false
                auditPages.reset()
                retainedMarks.removeAll()
                expectedGen.removeAll()
                selectedFinding = nil
                marked.removeAll()
                remedyChoice.removeAll()
                searchText = ""
                browser.reset()
                for owner in owners.values {
                    owner.reset()
                }
                for section in rescanning {
                    expectedGen[section] = gen
                    status[section] = .scanning(msg: "", done: 0, total: nil)
                }
                scanBridge?.activate(runId: gen)
                auditPages.activate(runId: gen, section: selectedItem?.section
                    ?? (selectedItem == .storage ? .system : nil))
            }
        case .verifying:
            run.phase = .verifying
        case let .finished(summary, reportPath, reportJSON):
            run.phase = .done
            run.summary = summary
            run.reportPath = reportPath
            run.reportJSON = reportJSON
            push(reportPath.map { "\(summary) — report \($0)" } ?? summary)
        }
        cleanup = run
    }

    // MARK: - Activity

    private func push(_ line: String) {
        activity.append(line)
        if activity.count > 200 {
            activity.removeFirst()
        }
    }
}

extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
