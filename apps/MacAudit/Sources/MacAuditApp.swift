import MacAuditKit
import SwiftUI

@main
struct MacAuditApp: App {
    @State private var store: AuditStore
    @State private var startupError: String?

    init() {
        let fake = ProcessInfo.processInfo.environment["MACAUDIT_FAKE"] == "1"
            || UserDefaults.standard.bool(forKey: "useFakeData")
        do {
            let engine = try Engine(opts: EngineOptions(
                homeOverride: ProcessInfo.processInfo.environment["MACAUDIT_HOME"],
                fake: fake,
                offline: UserDefaults.standard.bool(forKey: "offline"),
                rmMode: false))
            _store = State(initialValue: AuditStore(engine: engine, usingFakeData: fake))
        } catch {
            // Without an engine there is nothing to show; surface the reason.
            _store = State(initialValue: AuditStore(engine: UnavailableEngine(), usingFakeData: fake))
            _startupError = State(initialValue: "\(error)")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(store)
                .task { store.rescanAll() }
                .alert("MacAudit could not start", isPresented: .constant(startupError != nil)) {
                    Button("Quit") { NSApplication.shared.terminate(nil) }
                } message: {
                    Text(startupError ?? "")
                }
        }
        .defaultSize(width: 1180, height: 760)
        .commands {
            CommandGroup(after: .toolbar) {
                Button("Rescan All") { store.rescanAll() }
                    .keyboardShortcut("r", modifiers: .command)
                Button("Rescan Section") {
                    if let s = store.selectedSection { store.rescan(s) }
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(store.selectedSection == nil)
                Divider()
                Button("Mark / Unmark") {
                    if let id = store.selectedFinding { store.toggleMark(id) }
                }
                .keyboardShortcut(" ", modifiers: [])
                .disabled(store.selectedFinding == nil)
                Button("Clean Up…") { store.openConfirm() }
                    .keyboardShortcut("x", modifiers: .command)
                    .disabled(store.marked.isEmpty)
            }
        }
        Settings {
            SettingsView().environment(store)
        }
    }
}

/// Stand-in when the real engine failed to construct (bad config, unusable
/// home). Every call is a no-op so the window can still open and show why.
final class UnavailableEngine: MacAuditEngine {
    func sections() -> [SectionMeta] { [] }
    func deleteMode() -> DeleteMode { .trash }
    func configPath() -> String { "" }
    func startScan(sections: [SectionId], listener: ScanListener) -> UInt64 { 0 }
    func cancelScan() {}
    func findings(section: SectionId) -> [Finding] { [] }
    func plan(selection: [Selection]) throws -> Plan { throw MacAuditError.Invalid(message: "engine unavailable") }
    func execute(plan: Plan, listener: ExecListener) throws { throw MacAuditError.Invalid(message: "engine unavailable") }
    func cancelCleanup() {}
    func snapshots() throws -> [SnapshotMeta] { [] }
    func saveSnapshot() throws -> Int64 { throw MacAuditError.Snapshot(message: "engine unavailable") }
    func diffSnapshots(a: Int64, b: Int64) throws -> SnapshotDiff {
        SnapshotDiff(added: [], removed: [], grown: [], changed: [])
    }
    func baselineCounts() -> [SectionBaseline] { [] }
}
