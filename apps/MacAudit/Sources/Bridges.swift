import Foundation
import MacAuditKit

/// Engine callbacks arrive on tokio worker threads. Each bridge forwards
/// them into an `AsyncStream` (which preserves order, unlike a burst of
/// independent `Task { @MainActor in … }` hops) that the store consumes on
/// the main actor. A bridge must never call back into the engine: the pump
/// may be holding the session lock while it delivers an event.
final class ScanBridge: ScanListener, Sendable {
    let events: AsyncStream<ScanEvent>
    private let continuation: AsyncStream<ScanEvent>.Continuation

    init() {
        let (stream, continuation) = AsyncStream<ScanEvent>.makeStream()
        self.events = stream
        self.continuation = continuation
    }

    func onEvent(event: ScanEvent) {
        continuation.yield(event)
    }

    func finish() {
        continuation.finish()
    }
}

final class ExecBridge: ExecListener, Sendable {
    let events: AsyncStream<ExecEvent>
    private let continuation: AsyncStream<ExecEvent>.Continuation

    init() {
        let (stream, continuation) = AsyncStream<ExecEvent>.makeStream()
        self.events = stream
        self.continuation = continuation
    }

    func onEvent(event: ExecEvent) {
        continuation.yield(event)
        if case .finished = event {
            continuation.finish()
        }
    }
}
