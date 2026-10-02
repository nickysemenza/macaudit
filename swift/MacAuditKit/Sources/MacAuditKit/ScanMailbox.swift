import Foundation
import OrderedCollections

public struct ScanSectionSnapshot: Sendable {
    public var findings: [Finding]
    public var terminal: Bool
    public var error: String?
    public var progress: String?
    public var durationMs: UInt64?
    public var progressDone: UInt64?
    public var progressTotal: UInt64?
    public var truncated: Bool
    public var revision: UInt64
}

public struct ScanSnapshot: Sendable {
    public var runId: UInt64
    public var sections: [SectionId: ScanSectionSnapshot]
}

public final class ScanMailbox: ScanListener, @unchecked Sendable {
    public static let maximumRowsPerSection = 500
    public let updates: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private let lock = NSLock()
    private var runId: UInt64 = 0
    private var closed = false
    private var rows: [SectionId: OrderedDictionary<UInt64, Finding>] = [:]
    private var terminals = Set<SectionId>()
    private var errors: [SectionId: String] = [:]
    private var progress: [SectionId: String] = [:]
    private var durations: [SectionId: UInt64] = [:]
    private var progressCounts: [SectionId: (UInt64?, UInt64?)] = [:]
    private var truncated = Set<SectionId>()
    private var revisions: [SectionId: UInt64] = [:]

    public init() {
        let pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        updates = pair.stream
        continuation = pair.continuation
    }

    public func activate(runId: UInt64) {
        lock.withLock {
            guard runId > self.runId else { return }
            reset(runId: runId)
        }
        continuation.yield(())
    }

    private func reset(runId: UInt64) {
        self.runId = runId
        rows.removeAll(keepingCapacity: true)
        terminals.removeAll(keepingCapacity: true)
        errors.removeAll(keepingCapacity: true)
        progress.removeAll(keepingCapacity: true)
        durations.removeAll(keepingCapacity: true)
        progressCounts.removeAll(keepingCapacity: true)
        truncated.removeAll(keepingCapacity: true)
        revisions.removeAll(keepingCapacity: true)
    }

    private func upsert(_ finding: Finding, section: SectionId) {
        rows[section, default: [:]].removeValue(forKey: finding.id)
        rows[section, default: [:]][finding.id] = finding
        if rows[section, default: [:]].count > Self.maximumRowsPerSection {
            rows[section, default: [:]].remove(at: 0)
            truncated.insert(section)
        }
        revisions[section, default: 0] &+= 1
    }

    public func onEvent(event: ScanEvent) {
        let accepted = lock.withLock {
            guard !closed, event.runId >= runId else { return false }
            if event.runId > runId { reset(runId: event.runId) }
            switch event {
            case .sectionStarted(let section, _):
                terminals.remove(section)
                errors.removeValue(forKey: section)
            case .findings(let section, _, let findings):
                if findings.isEmpty { revisions[section, default: 0] &+= 1 }
                for finding in findings { upsert(finding, section: section) }
            case .correlated(_, let findings), .enriched(_, let findings):
                for finding in findings {
                    let section = finding.section
                    upsert(finding, section: section)
                }
            case .progress(let section, _, let message, let done, let total):
                progress[section] = message
                progressCounts[section] = (done, total)
            case .sectionFinished(let section, _, let durationMs):
                terminals.insert(section)
                durations[section] = durationMs
            case .sectionFailed(let section, _, let error):
                terminals.insert(section)
                errors[section] = error
            }
            return true
        }
        if accepted { continuation.yield(()) }
    }

    public func snapshot() async -> ScanSnapshot {
        await Task.detached { [self] in
            lock.withLock {
                ScanSnapshot(runId: runId, sections: Dictionary(uniqueKeysWithValues:
                    SectionId.allCases.map { section in
                        (section, ScanSectionSnapshot(findings: rows[section].map { Array($0.values) } ?? [],
                            terminal: terminals.contains(section), error: errors[section], progress: progress[section],
                            durationMs: durations[section], progressDone: progressCounts[section]?.0,
                            progressTotal: progressCounts[section]?.1, truncated: truncated.contains(section),
                            revision: revisions[section, default: 0]))
                    }))
            }
        }.value
    }

    public func finish() {
        lock.withLock { closed = true }
        continuation.finish()
    }

    deinit { continuation.finish() }
}

extension ScanEvent {
    public var runId: UInt64 {
        switch self {
        case .sectionStarted(_, let gen), .progress(_, let gen, _, _, _),
             .findings(_, let gen, _), .sectionFinished(_, let gen, _),
             .sectionFailed(_, let gen, _), .correlated(let gen, _), .enriched(let gen, _): gen
        }
    }
}
