import Foundation
import Testing
@testable import MacAuditKit

/// Collects scan events and resolves once every section is terminal.
final class TerminalWaiter: ScanListener, @unchecked Sendable {
    private let lock = NSLock()
    private var terminal = 0
    private var findingIds = Set<UInt64>()
    private var byId: [UInt64: Finding] = [:]
    private let expected: Int
    private var continuation: CheckedContinuation<Void, Never>?

    init(expected: Int) { self.expected = expected }

    func onEvent(event: ScanEvent) {
        lock.lock()
        defer { lock.unlock() }
        switch event {
        case .findings(_, _, let findings):
            for f in findings {
                findingIds.insert(f.id)
                byId[f.id] = f
            }
        case .sectionFinished, .sectionFailed:
            terminal += 1
            if terminal == expected, let c = continuation {
                continuation = nil
                c.resume()
            }
        default:
            break
        }
    }

    func wait() async {
        await withCheckedContinuation { c in
            lock.lock()
            if terminal >= expected {
                lock.unlock()
                c.resume()
            } else {
                continuation = c
                lock.unlock()
            }
        }
    }

    var seen: Set<UInt64> {
        lock.lock(); defer { lock.unlock() }
        return findingIds
    }

    /// Latest version of every finding (re-emits upsert by id).
    var findings: [Finding] {
        lock.lock(); defer { lock.unlock() }
        return Array(byId.values)
    }
}

@Test func fakeScanStreamsEverySection() async throws {
    let home = FileManager.default.temporaryDirectory
        .appendingPathComponent("macaudit-kit-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }

    let engine = try Engine(opts: EngineOptions(
        homeOverride: home.path, fake: true, offline: true, rmMode: false))
    #expect(engine.sections().count == SectionId.allCases.count)
    #expect(engine.sections().map(\.id) == SectionId.allCases)

    let waiter = TerminalWaiter(expected: SectionId.allCases.count)
    engine.startScan(sections: SectionId.allCases, listener: waiter)
    await waiter.wait()

    let apps = engine.findings(section: .apps)
    #expect(!apps.isEmpty)
    #expect(apps.allSatisfy { waiter.seen.contains($0.id) })
    #expect(engine.deleteMode() == .trash)

    #expect(engine.dirRoot()?.path == engine.selectedRoot())
    let children = engine.dirChildren(path: engine.selectedRoot())
    #expect(!children.isEmpty)
    for (a, b) in zip(children, children.dropFirst()) {
        #expect(a.alloc >= b.alloc)
    }
    let stats = try #require(engine.dirTreeStats())
    #expect(stats.complete)
    #expect(stats.directoryEntries != nil)
    #expect(stats.externallyLinkedBytes != nil)
    #expect(stats.files == engine.dirRoot()?.files)

    let page = try engine.dirChildrenPage(path: engine.selectedRoot(), offset: 0, limit: 2)
    #expect(page.requestId > 0)
    #expect(page.subjectPath == engine.selectedRoot())
    #expect(page.metadata.queryMemory != nil)
    let query = " a "
    let search = try engine.nameSearch(query: query, limit: 10, cancellation: QueryCancellation())
    #expect(search.query == query)
    #expect(search.requestId > 0)
    #expect(search.metadata.queryMemory != nil)
    #expect(search.entries.count + search.files.count <= 10)
    #expect(search.observedAtMs > 0)
    #expect(!search.coverage.isEmpty)
    let live = try engine.liveFilesPage(path: engine.selectedRoot(), limit: 2)
    #expect(live.subjectPath == engine.selectedRoot())
    #expect(live.requestId > 0)
    #expect(live.metadata.queryMemory != nil)
}

@Test func findingMetaDistinguishesBooleansFromNumbers() {
    let m = FindingMeta(json: #"{"stale": true, "load_1": 1.0, "cores": 8, "n": null, "name": "x", "pct": 0}"#)
    #expect(m.bool("stale") == true)
    #expect(m.double("stale") == nil)
    #expect(m.double("load_1") == 1.0)
    #expect(m.bool("load_1") == nil)
    #expect(m.uint64("cores") == 8)
    #expect(m.uint64("pct") == 0)
    #expect(m.bool("pct") == nil)
    #expect(m.has("n") == false)
    #expect(m.string("name") == "x")
    #expect(FindingMeta(json: "not json").isEmpty)
}

@Test func iosFixturesExposeTypedStorage() async throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("macaudit-ios-\(UUID())")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let engine = try Engine(opts: EngineOptions(
        homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let waiter = TerminalWaiter(expected: SectionId.allCases.count)
    engine.startScan(sections: [.ios], listener: waiter)
    await waiter.wait()
    let findings = waiter.findings
    let devices = findings.compactMap(IosDeviceStorage.init)
    #expect(devices.count == 1)
    let d = try #require(devices.first)
    // Both tilings cover the whole capacity exactly.
    #expect(d.appsBytes + d.unattributedBytes + d.freeBytes == d.capacityBytes)
    #expect(d.committedBytes + d.purgeableBytes + d.freeBytes == d.capacityBytes)
    let apps = findings.compactMap(IosAppUsage.init)
    #expect(apps.count == d.appCount)
    #expect(apps.contains { $0.bundleId == "com.spotify.client" && $0.dynamicBytes > $0.staticBytes * 4 })
}

@Test func footprintResolvesForAFakeProjectFinding() async throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("macaudit-footprint-\(UUID())")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let engine = try Engine(opts: EngineOptions(
        homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let waiter = TerminalWaiter(expected: SectionId.allCases.count)
    engine.startScan(sections: [.projects], listener: waiter)
    await waiter.wait()

    let project = try #require(waiter.findings.filter { $0.kind == .project }.min { $0.id < $1.id })
    let footprint = engine.footprint(findingId: project.id)
    #expect(footprint != nil)
    #expect(footprint?.finding == project.id)
    #expect(footprint?.owner.kind == .project)

    let buckets = engine.footprintBuckets(axis: .projects)
    #expect(buckets?.axis == .projects)
}

@Test func rootValidationPreservesRunAndQueryHandlesExpire() async throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("macaudit-run-\(UUID())")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let engine = try Engine(opts: EngineOptions(homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let queries = MacAuditQueries(engine: engine)
    let waiter = TerminalWaiter(expected: SectionId.allCases.count)
    let runId = try await queries.startRun(root: home.path, listener: waiter)
    await waiter.wait()
    #expect(await queries.metadata().runId == runId)
    let directory = try #require(await queries.root())
    let directoryPage = try await queries.children(path: directory.path)
    for entry in directoryPage.entries {
        #expect(await queries.entry(path: entry.path)?.nodeRevision == entry.nodeRevision)
    }
    #expect(await queries.entry(path: directory.path)?.nodeRevision == directory.nodeRevision)
    do {
        _ = try await queries.startRun(root: home.appendingPathComponent("missing").path, listener: waiter)
        Issue.record("missing root was accepted")
    } catch {}
    #expect(await queries.metadata().runId == runId)
    do {
        _ = try await queries.findings(section: .fs, limit: 501)
        Issue.record("oversized page was accepted")
    } catch {}
    let cursor = try await queries.openNameQuery(query: "a")
    #expect(try await queries.directoryPage(cursor: cursor).entries.count <= 500)
    let findingsPage = try await queries.findings(section: .apps, runId: runId, limit: 1)
    let findingsCursor = try #require(findingsPage.nextCursor)
    #expect(try await queries.findings(cursor: findingsCursor, limit: 1).findings.count == 1)
    let project = try #require(waiter.findings.filter { $0.kind == .project }.min { $0.id < $1.id })
    let ownerPage = try await queries.footprintEntries(findingId: project.id, runId: runId, limit: 1)
    let ownerCursor = try #require(ownerPage.nextCursor)
    #expect(try await queries.footprintEntries(cursor: ownerCursor, limit: 1).entries.count == 1)
    #expect(try await queries.sectionSummary(section: .apps, runId: runId).total == findingsPage.total)
    do {
        _ = try await queries.footprintEntries(findingId: project.id, runId: runId, offset: 1)
        Issue.record("owner continuation without a stamp was accepted")
    } catch {}
    let replacement = TerminalWaiter(expected: SectionId.allCases.count)
    let newId = try await queries.startRun(root: home.path, listener: replacement)
    await replacement.wait()
    #expect(newId > runId)
    do {
        _ = try await queries.directoryPage(cursor: cursor)
        Issue.record("retired query cursor was accepted")
    } catch {}
    do {
        _ = try await queries.findings(cursor: findingsCursor)
        Issue.record("retired finding cursor was accepted")
    } catch {}
    do {
        _ = try await queries.footprintEntries(cursor: ownerCursor)
        Issue.record("retired owner cursor was accepted")
    } catch {}
    #expect(await queries.footprint(findingId: project.id, runId: runId) == nil)
}

@Test func guiRelativeRootIsResolvedAgainstHome() async throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("macaudit-relative-\(UUID())")
    let selected = home.appendingPathComponent("selected-child")
    try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let engine = try Engine(opts: EngineOptions(homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let queries = MacAuditQueries(engine: engine)
    try await queries.setRoot("selected-child")
    let root = await queries.selectedRoot()
    #expect(URL(fileURLWithPath: root).resolvingSymlinksInPath().path == selected.resolvingSymlinksInPath().path)
    let waiter = TerminalWaiter(expected: SectionId.allCases.count)
    _ = try await queries.startRun(root: "selected-child", listener: waiter)
    await waiter.wait()
    let metadata = await queries.metadata()
    #expect(URL(fileURLWithPath: metadata.selectedRoot).resolvingSymlinksInPath().path == selected.resolvingSymlinksInPath().path)
    #expect(await queries.root()?.path == metadata.selectedRoot)
    #expect(await queries.entry(path: home.path) == nil)
    #expect((try await queries.children(path: metadata.selectedRoot)).entries.allSatisfy {
        $0.path.hasPrefix(metadata.selectedRoot + "/")
    })
}

@Test func liveListingCarriesObservationAndRejectsOutsideRoot() async throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("macaudit-live-\(UUID())")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: home) }
    try Data(repeating: 7, count: 4096).write(to: home.appendingPathComponent("file"))
    let engine = try Engine(opts: EngineOptions(homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let queries = MacAuditQueries(engine: engine)
    try await queries.setRoot(home.path)
    let page = try await queries.liveFiles(path: home.path)
    #expect(page.observedAtMs > 0)
    #expect(page.coverage == "complete")
    #expect(page.files.count == 1)
    do {
        _ = try await queries.liveFiles(path: home.deletingLastPathComponent().path)
        Issue.record("outside-root live listing was accepted")
    } catch {}
}
