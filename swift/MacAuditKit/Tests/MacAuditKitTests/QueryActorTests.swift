import Foundation
import Testing
@testable import MacAuditKit

private final class DelayedQueryEngine: MacAuditEngine, @unchecked Sendable {
    private let condition = NSCondition()
    private var run: UInt64 = 1
    private var root = "/synthetic/old"
    private var entered = false
    private var released = false
    private var timedOut = false

    var hasEntered: Bool { condition.withLock { entered } }
    var didTimeOut: Bool { condition.withLock { timedOut } }

    func release() {
        condition.withLock {
            released = true
            condition.broadcast()
        }
    }

    private func block() {
        condition.lock()
        defer { condition.unlock() }
        entered = true
        let deadline = Date(timeIntervalSinceNow: 10)
        while !released {
            if !condition.wait(until: deadline), !released {
                timedOut = true
                return
            }
        }
    }

    func selectedRoot() -> String { condition.withLock { root } }
    func startRun(root: String, listener: ScanListener) throws -> UInt64 {
        condition.withLock {
            self.root = root
            run += 1
            return run
        }
    }
    func sessionMetadata() -> SessionMetadata {
        condition.withLock {
            SessionMetadata(runId: run, selectedRoot: root, revision: 1, startedAtMs: 0, queriedAtMs: 0,
                diskComplete: false, diskErrors: 0, diskElapsedMs: 0, auditComplete: false,
                cancelled: false, diskCoverage: "partial", auditCoverage: "partial",
                walkCoverage: WalkCoverage(unreadable: 0, excluded: 0, dataless: 0, aliases: 0,
                    mounts: 0, cancelled: false, resourceLimited: false, summariesTruncated: false,
                    deadline: false, entryLimit: false, unsupportedPaths: 0),
                diskStopReasons: [], auditStopReasons: [], activeScanners: 0, retiringCount: 0,
                retiringRuns: [], queryMemory: nil)
        }
    }
    func liveFilesPage(path: String, limit: UInt32) throws -> LiveFilesPage {
        let metadata = sessionMetadata()
        block()
        return LiveFilesPage(requestId: 1, subjectPath: path, metadata: metadata, observedAtMs: 0,
            coverage: "partial", files: [], dataless: 0, errors: 0, truncated: false, stopReasons: [])
    }
    func dirTopFiles(path: String, n: UInt32) -> [TopFile] { block(); return [] }
    func plan(selection: [Selection]) throws -> Plan {
        block()
        throw MacAuditError.Invalid(message: "synthetic plan unavailable")
    }
    func sections() -> [SectionMeta] { [] }
    func deleteMode() -> DeleteMode { .trash }
    func configPath() -> String { "/synthetic/config" }
    func fullDiskAccess() -> Bool { false }
    func startScan(sections: [SectionId], listener: ScanListener) -> UInt64 { 1 }
    func cancelScan() {}
    func findings(section: SectionId) -> [Finding] { [] }
    func execute(plan: Plan, listener: ExecListener) throws {}
    func cancelCleanup() {}
    func dirRoot() -> DirEntry? { nil }
    func dirEntry(path: String) -> DirEntry? { nil }
    func dirChildren(path: String) -> [DirEntry] { [] }
    func dirSubtree(path: String, depth: UInt32, maxNodes: UInt32) -> [DirEntry] { [] }
    func largestFiles(n: UInt32) -> [TopFile] { [] }
    func dirTreeStats() -> DirTreeStats? { nil }
    func footprint(findingId: UInt64) -> Footprint? { nil }
    func footprintBuckets(axis: Axis) -> FootprintBuckets? { nil }
}

private final class QueryTestListener: ScanListener, Sendable {
    func onEvent(event: ScanEvent) {}
}

private func waitForQuery(_ engine: DelayedQueryEngine) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !engine.hasEntered, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
    #expect(engine.hasEntered)
}

// These tests deliberately block a cooperative worker. Run one at a time so
// small-core machines retain a worker that can drive and release the query.
@Suite(.serialized)
struct QueryActorTests {
    @Test func blockedLiveFilesDoesNotStarveRunAdmissionAndRejectsRetiredResponse() async throws {
        let engine = DelayedQueryEngine()
        let queries = MacAuditQueries(engine: engine)
        defer {
            engine.release()
            #expect(!engine.didTimeOut, "Blocked query exceeded the 10-second safety deadline")
        }
        let listing = Task { try await queries.liveFiles(path: "/synthetic/old") }
        try await waitForQuery(engine)
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { engine.release() }
        let started = ContinuousClock.now
        let metadata = await queries.metadata()
        let run = try await queries.startRun(root: "/synthetic/new", listener: QueryTestListener())
        #expect(started.duration(to: .now) < .seconds(1))
        #expect(metadata.runId == 1)
        #expect(run == 2)
        #expect(await queries.selectedRoot() == "/synthetic/new")
        engine.release()
        do {
            _ = try await listing.value
            Issue.record("Retired live listing was accepted")
        } catch MacAuditError.Invalid(let message) {
            #expect(message.contains("retired"))
        }
    }

    @Test func cancelledLiveFilesDiscardsResponseWithoutBlockingMetadata() async throws {
        let engine = DelayedQueryEngine()
        let queries = MacAuditQueries(engine: engine)
        defer {
            engine.release()
            #expect(!engine.didTimeOut, "Blocked query exceeded the 10-second safety deadline")
        }
        let listing = Task { try await queries.liveFiles(path: "/synthetic/old") }
        try await waitForQuery(engine)
        listing.cancel()
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { engine.release() }
        let started = ContinuousClock.now
        #expect(await queries.metadata().runId == 1)
        #expect(started.duration(to: .now) < .seconds(1))
        engine.release()
        do {
            _ = try await listing.value
            Issue.record("Cancelled listing returned a result")
        } catch is CancellationError {}
    }

    @Test(arguments: [false, true])
    func blockedTopFilesAndPlanLeaveQueryActorRunnable(planning: Bool) async throws {
        let engine = DelayedQueryEngine()
        let queries = MacAuditQueries(engine: engine)
        defer {
            engine.release()
            #expect(!engine.didTimeOut, "Blocked query exceeded the 10-second safety deadline")
        }
        let query = Task {
            if planning { _ = try? await queries.plan(selection: []) }
            else { _ = await queries.topFiles(path: "/synthetic/old", n: 500) }
        }
        try await waitForQuery(engine)
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { engine.release() }
        let started = ContinuousClock.now
        #expect(await queries.metadata().runId == 1)
        #expect(started.duration(to: .now) < .seconds(1))
        engine.release()
        await query.value
    }
}
