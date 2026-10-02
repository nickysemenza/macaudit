import Foundation

@MainActor
final class ApplicationCoordinator {
    let store: AuditStore
    private(set) var didStart = false

    init(store: AuditStore) {
        self.store = store
    }

    static func initialRoot(homeOverride: String?, isTesting: Bool, defaultHome: String) -> String {
        isTesting ? "/fixture" : homeOverride ?? defaultHome
    }

    func start() {
        guard !didStart else { return }
        didStart = true
        store.rescanAll()
    }
}
