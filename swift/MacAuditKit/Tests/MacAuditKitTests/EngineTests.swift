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

    #expect(engine.dirRoot()?.path == "/Users/dev")
    let children = engine.dirChildren(path: "/Users/dev")
    #expect(!children.isEmpty)
    for (a, b) in zip(children, children.dropFirst()) {
        #expect(a.alloc >= b.alloc)
    }
    #expect(engine.dirTreeStats()?.complete == true)
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
    let engine = try Engine(opts: EngineOptions(
        homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let waiter = TerminalWaiter(expected: 1)
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
    let engine = try Engine(opts: EngineOptions(
        homeOverride: home.path, fake: true, offline: true, rmMode: false))
    let waiter = TerminalWaiter(expected: 1)
    engine.startScan(sections: [.projects], listener: waiter)
    await waiter.wait()

    let project = try #require(waiter.findings.first { $0.kind == .project })
    let footprint = engine.footprint(findingId: project.id)
    #expect(footprint != nil)
    #expect(footprint?.finding == project.id)
    #expect(footprint?.owner.kind == .project)

    let buckets = engine.footprintBuckets(axis: .projects)
    #expect(buckets?.axis == .projects)
}
