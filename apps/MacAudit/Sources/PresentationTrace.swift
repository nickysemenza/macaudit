import Foundation

struct PresentationTraceBudget {
    private var remaining: Int

    init(limit: Int) {
        remaining = max(0, limit)
    }

    mutating func claim() -> Bool {
        guard remaining > 0 else { return false }
        remaining -= 1
        return true
    }
}

enum PresentationTrace {
    private static let enabled = ProcessInfo.processInfo.environment["MACAUDIT_TRACE"] == "1"
    private static let sink = PresentationTraceSink()

    static func start() -> ContinuousClock.Instant? {
        enabled ? ContinuousClock.now : nil
    }

    static func finish(_ event: String, since start: ContinuousClock.Instant?,
                       run: UInt64? = nil, request: UInt64? = nil, generation: UInt64? = nil,
                       revision: UInt64? = nil, rows: Int? = nil, cacheHit: Bool? = nil,
                       mainActor: Bool = false)
    {
        guard let start else { return }
        let duration = start.duration(to: .now).components
        let milliseconds = Double(duration.seconds) * 1000 + Double(duration.attoseconds) / 1e15
        sink.write(record(event, milliseconds: milliseconds, run: run, request: request,
                          generation: generation, revision: revision, rows: rows,
                          cacheHit: cacheHit, mainActor: mainActor))
    }

    static func record(_ event: String, milliseconds: Double, run: UInt64? = nil,
                       request: UInt64? = nil, generation: UInt64? = nil, revision: UInt64? = nil,
                       rows: Int? = nil, cacheHit: Bool? = nil, mainActor: Bool = false) -> String
    {
        var fields = ["[MacAuditTrace]", "event=\(event.prefix(64))",
                      "elapsed_ms=\(String(format: "%.3f", milliseconds))"]
        if let run {
            fields.append("run=\(run)")
        }
        if let request {
            fields.append("request=\(request)")
        }
        if let generation {
            fields.append("generation=\(generation)")
        }
        if let revision {
            fields.append("revision=\(revision)")
        }
        if let rows {
            fields.append("rows=\(rows)")
        }
        if let cacheHit {
            fields.append("cache_hit=\(cacheHit)")
        }
        if mainActor {
            fields.append("work=main_actor")
        }
        return fields.joined(separator: " ") + "\n"
    }
}

private final class PresentationTraceSink: @unchecked Sendable {
    private let lock = NSLock()
    private var budget = PresentationTraceBudget(limit: 512)

    func write(_ record: String) {
        lock.withLock {
            guard budget.claim() else { return }
            try? FileHandle.standardError.write(contentsOf: Data(record.utf8))
        }
    }
}
