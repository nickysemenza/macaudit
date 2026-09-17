import AppKit
import Foundation
import MacAuditKit
import Observation

enum SectionStatus: Equatable {
    case idle
    case scanning(msg: String, done: UInt64, total: UInt64?)
    case done(durationMs: UInt64)
    case failed(String)

    var isTerminal: Bool {
        switch self {
        case .done, .failed: true
        case .idle, .scanning: false
        }
    }
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

/// What the sidebar can select: the Storage overview, a scanner section, or
/// the Folders drill-down.
enum SidebarItem: Hashable {
    case storage
    case section(SectionId)
    case folders

    var section: SectionId? {
        if case .section(let id) = self { return id }
        return nil
    }
}

/// The app's single source of truth: the TUI's `AppState` in Swift. Owns the
/// engine, ingests scan/cleanup events on the main actor, and holds the
/// UI-only state (selection, marks, remedy choices).
@MainActor
@Observable
final class AuditStore {
    private(set) var engine: any MacAuditEngine
    private(set) var sections: [SectionMeta]
    private(set) var findings: [SectionId: [UInt64: Finding]] = [:]
    private(set) var status: [SectionId: SectionStatus] = [:]
    private var expectedGen: [SectionId: UInt64] = [:]
    private(set) var activity: [String] = []
    let browser: DirBrowser

    var selectedItem: SidebarItem? = .storage
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

    let usingFakeData: Bool
    private var scanBridge: ScanBridge?
    private var scanTask: Task<Void, Never>?

    /// Whether the engine can currently read TCC-protected user data
    /// (Safari, Mail, …). Refreshed after every fs scan and whenever the app
    /// becomes active again (the user may have just granted it in System
    /// Settings), so the banner clears without a rescan.
    var hasFullDiskAccess = true

    init(engine: any MacAuditEngine, usingFakeData: Bool) {
        self.engine = engine
        self.usingFakeData = usingFakeData
        self.sections = engine.sections()
        self.browser = DirBrowser(engine: engine)
        refreshFullDiskAccess()
        // The store lives as long as the app; the observation ends with it.
        Task { [weak self] in
            for await _ in NotificationCenter.default.notifications(named: NSApplication.didBecomeActiveNotification) {
                guard let self else { return }
                self.refreshFullDiskAccess()
            }
        }
    }

    /// Re-probes Full Disk Access off-main and applies the result on the
    /// main actor.
    func refreshFullDiskAccess() {
        let engine = self.engine
        Task {
            let ok = await Task.detached { engine.fullDiskAccess() }.value
            hasFullDiskAccess = ok
        }
    }

    // MARK: - Reads

    func meta(for id: SectionId) -> SectionMeta? {
        sections.first { $0.id == id }
    }

    func status(of id: SectionId) -> SectionStatus {
        status[id] ?? .idle
    }

    var selectedSection: SectionId? { selectedItem?.section }

    func findings(in id: SectionId) -> [Finding] {
        findings[id].map { Array($0.values) } ?? []
    }

    /// Findings from the fs section whose path is under (or equal to) `path`
    /// — used by the Folders inspector to scope findings to a directory.
    /// Disk findings at or below `path`, largest first.
    func fsFindings(under path: String) -> [Finding] {
        findings(in: .fs)
            .filter { $0.path?.hasPrefix(path) == true }
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
        for map in findings.values {
            if let f = map[id] { return f }
        }
        return nil
    }

    func count(of id: SectionId) -> Int {
        findings[id]?.count ?? 0
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
            case .brewFormula: if f.isBrewSummaryRow { continue } else { name = "Homebrew" }
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
        status.values.contains { if case .scanning = $0 { true } else { false } }
    }

    // MARK: - Scanning

    func rescanAll() {
        startScan(SectionId.allCases)
    }

    func rescan(_ id: SectionId) {
        startScan([id])
    }

    private func startScan(_ ids: [SectionId]) {
        if scanBridge == nil {
            let bridge = ScanBridge()
            scanBridge = bridge
            scanTask = Task { [weak self] in
                for await event in bridge.events {
                    guard let self else { return }
                    self.apply(event)
                }
            }
        }
        guard let bridge = scanBridge else { return }
        let gen = engine.startScan(sections: ids, listener: bridge)
        for id in ids {
            expectedGen[id] = gen
            findings[id] = [:]
            status[id] = .scanning(msg: "", done: 0, total: nil)
        }
    }

    func cancelScan() {
        engine.cancelScan()
    }

    /// Apply a scan event. Same rule as the engine session: only the
    /// generation a section currently expects is accepted.
    func apply(_ event: ScanEvent) {
        switch event {
        case .sectionStarted(let section, let gen):
            guard expectedGen[section] == gen else { return }
            findings[section] = [:]
            status[section] = .scanning(msg: "", done: 0, total: nil)
        case .progress(let section, let gen, let msg, let done, let total):
            guard expectedGen[section] == gen else { return }
            status[section] = .scanning(msg: msg, done: done, total: total)
        case .findings(let section, let gen, let batch):
            guard expectedGen[section] == gen else { return }
            var map = findings[section] ?? [:]
            for f in batch { map[f.id] = f }
            findings[section] = map
        case .sectionFinished(let section, let gen, let durationMs):
            guard expectedGen[section] == gen else { return }
            status[section] = .done(durationMs: durationMs)
            dropStaleMarks(after: [section])
            if section == .fs {
                browser.refreshRoot()
                browser.invalidate()
                refreshFullDiskAccess()
            }
        case .sectionFailed(let section, let gen, let error):
            guard expectedGen[section] == gen else { return }
            status[section] = .failed(error)
            push("\(section.slug): \(error)")
            dropStaleMarks(after: [section])
        case .correlated(_, let batch), .enriched(_, let batch):
            for f in batch {
                findings[f.section, default: [:]][f.id] = f
            }
        }
    }

    private func dropStaleMarks(after sections: [SectionId]) {
        guard !marked.isEmpty else { return }
        let present = Set(findings.values.flatMap(\.keys))
        let stale = marked.subtracting(present)
        guard !stale.isEmpty else { return }
        marked.subtract(stale)
        for id in stale { remedyChoice[id] = nil }
        push("dropped \(stale.count) stale mark(s) after rescanning \(sections.map(\.slug).joined(separator: ", "))")
    }

    // MARK: - Folders

    /// Switch the sidebar to Folders and drill the browser into `path`.
    func browse(path: String) {
        browser.navigate(to: path)
        selectedItem = .folders
        selectedFinding = nil
    }

    // MARK: - Marks

    func toggleMark(_ id: UInt64) {
        if marked.contains(id) {
            marked.remove(id)
            remedyChoice[id] = nil
        } else {
            marked.insert(id)
        }
    }

    func chooseRemedy(_ index: Int?, for id: UInt64) {
        remedyChoice[id] = index
        marked.insert(id)
    }

    var selection: [Selection] {
        marked.sorted().map { Selection(findingId: $0, remedyIndex: remedyChoice[$0].map(UInt32.init)) }
    }

    // MARK: - Cleanup

    /// Plan the marked findings and open the confirm sheet — even when
    /// everything was refused, so the user sees why.
    func openConfirm() {
        let selection = self.selection
        guard !selection.isEmpty else { return }
        planError = nil
        let engine = self.engine
        Task {
            do {
                let plan = try await Task.detached { try engine.plan(selection: selection) }.value
                pendingPlan = plan
                pendingSummary = plan.summary()
            } catch {
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
    }

    func executePendingPlan() {
        guard let plan = pendingPlan, let summary = pendingSummary else { return }
        dismissConfirm()
        for a in summary.actions {
            marked.remove(a.findingId)
            remedyChoice[a.findingId] = nil
        }
        cleanup = CleanupRun(actions: summary.actions, refused: summary.refused)
        let bridge = ExecBridge()
        do {
            try engine.execute(plan: plan, listener: bridge)
        } catch {
            cleanup = nil
            planError = "\(error)"
            return
        }
        Task { [weak self] in
            for await event in bridge.events {
                guard let self else { return }
                self.apply(event)
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
        if case .done = cleanup?.phase { cleanup = nil }
    }

    func apply(_ event: ExecEvent) {
        // Work on a copy and write back once: `cleanup?.x = f(cleanup)` opens
        // a modify access on the observed property while the right-hand side
        // reads it, which the Swift runtime reports as an exclusivity
        // violation and aborts.
        guard var run = cleanup else { return }
        switch event {
        case .preflightDone(let ok, let refused):
            run.actions = ok
            run.refused.append(contentsOf: refused)
            run.phase = .executing(index: 0, total: ok.count)
            if !refused.isEmpty {
                push("cleanup: \(refused.count) action(s) refused by the refreshed preflight")
            }
        case .actionStarted(let index):
            run.phase = .executing(index: Int(index), total: run.actions.count)
        case .actionDone(let index, let ok, let message):
            run.results[Int(index)] = (ok, message)
            if ok {
                push(message)
            } else {
                let rendered = run.actions[safe: Int(index)]?.rendered ?? ""
                push("error: \(rendered) — \(message)")
            }
        case .executed(let cancelled, let rescanning, let rescanGen):
            run.cancelled = cancelled
            run.phase = .verifying
            // The engine restarted these sections through the scan listener;
            // expect that generation so their events are accepted.
            if let gen = rescanGen {
                for section in rescanning {
                    expectedGen[section] = gen
                    findings[section] = [:]
                    status[section] = .scanning(msg: "", done: 0, total: nil)
                }
            }
        case .verifying:
            run.phase = .verifying
        case .finished(let summary, let reportPath, let reportJSON):
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
        if activity.count > 200 { activity.removeFirst() }
    }
}

extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
