import Foundation
import MacAuditKit

/// Engine callbacks arrive on tokio worker threads. Each bridge forwards
/// them into an `AsyncStream` (which preserves order, unlike a burst of
/// independent `Task { @MainActor in … }` hops) that the store consumes on
/// the main actor. A bridge must never call back into the engine: the pump
/// may be holding the session lock while it delivers an event.
final class ExecBridge: ExecListener, Sendable {
    let events: AsyncStream<ExecEvent>
    private let continuation: AsyncStream<ExecEvent>.Continuation

    init() {
        let (stream, continuation) = AsyncStream<ExecEvent>.makeStream()
        events = stream
        self.continuation = continuation
    }

    func onEvent(event: ExecEvent) {
        continuation.yield(event)
        if case .finished = event {
            continuation.finish()
        }
    }
}
