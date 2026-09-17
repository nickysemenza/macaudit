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
            CommandGroup(after: .sidebar) {
                Button("Enclosing Folder") { store.browser.up() }
                    .keyboardShortcut(.upArrow, modifiers: .command)
                    .disabled(store.selectedItem != .folders || !store.browser.canGoUp)
                Button("Back") { store.browser.goBack() }
                    .keyboardShortcut("[", modifiers: .command)
                    .disabled(store.selectedItem != .folders || !store.browser.canGoBack)
            }
        }
        Settings {
            SettingsView().environment(store)
        }
        MenuBarExtra {
            MenuBarContent().environment(store)
        } label: {
            Label(Formatting.bytes(store.totalReclaimableBytes), systemImage: store.isScanning ? "internaldrive.fill" : "internaldrive")
                .labelStyle(.titleAndIcon)
                .monospacedDigit()
        }
        .menuBarExtraStyle(.window)
    }
}

private struct MenuBarContent: View {
    @Environment(AuditStore.self) private var store
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Reclaimable").font(.headline)
                Spacer()
                Text(Formatting.bytes(store.totalReclaimableBytes))
                    .font(.headline).monospacedDigit().contentTransition(.numericText())
            }
            ForEach(store.sections, id: \.id) { meta in
                let bytes = store.reclaimableBytes(in: meta.id)
                if bytes > 0 || { if case .scanning = store.status(of: meta.id) { true } else { false } }() {
                    HStack {
                        Circle().fill(Palette.section(meta.id)).frame(width: 7, height: 7)
                        Text(meta.title).font(.callout)
                        Spacer()
                        if case .scanning = store.status(of: meta.id) {
                            ProgressView().controlSize(.mini)
                        } else {
                            Text(Formatting.bytes(bytes)).font(.callout).monospacedDigit().foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Divider()
            HStack {
                Button(store.isScanning ? "Scanning…" : "Rescan All") { store.rescanAll() }
                    .disabled(store.isScanning)
                Spacer()
                Button("Open MacAudit") {
                    NSApp.activate(ignoringOtherApps: true)
                    NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
                }
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            .controlSize(.small)
        }
        .padding(12)
        .frame(width: 300)
        .animation(.default, value: store.totalReclaimableBytes)
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
    func dirRoot() -> DirEntry? { nil }
    func dirEntry(path: String) -> DirEntry? { nil }
    func dirChildren(path: String) -> [DirEntry] { [] }
    func dirSubtree(path: String, depth: UInt32, maxNodes: UInt32) -> [DirEntry] { [] }
    func dirTopFiles(path: String, n: UInt32) -> [TopFile] { [] }
    func largestFiles(n: UInt32) -> [TopFile] { [] }
    func dirTreeStats() -> DirTreeStats? { nil }
}
