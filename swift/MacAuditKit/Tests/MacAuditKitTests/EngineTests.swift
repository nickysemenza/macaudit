import Foundation
import Testing
@testable import MacAuditKit

/// Collects scan events and resolves once every section is terminal.
final class TerminalWaiter: ScanListener, @unchecked Sendable {
    private let lock = NSLock()
    private var terminal = 0
    private var findingIds = Set<UInt64>()
    private let expected: Int
    private var continuation: CheckedContinuation<Void, Never>?

    init(expected: Int) { self.expected = expected }

    func onEvent(event: ScanEvent) {
        lock.lock()
        defer { lock.unlock() }
        switch event {
        case .findings(_, _, let findings):
            for f in findings { findingIds.insert(f.id) }
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
}
