import MacAuditKit
import SwiftUI

@main
struct MacAuditApp: App {
    @State private var store: AuditStore
    @State private var startupError: String?
    private let coordinator: ApplicationCoordinator

    init() {
        let environment = ProcessInfo.processInfo.environment
        let isTesting = environment["XCTestConfigurationFilePath"] != nil || environment["MACAUDIT_APP_TESTS"] == "1"
        let fake = environment["MACAUDIT_FAKE"] == "1" || isTesting
        let initialRoot = ApplicationCoordinator.initialRoot(homeOverride: environment["MACAUDIT_HOME"], isTesting: isTesting,
                                                             defaultHome: FileManager.default.homeDirectoryForCurrentUser.path)
        var initialStore: AuditStore
        do {
            let engine: any MacAuditEngine = isTesting ? UnavailableEngine() : try Engine(opts: EngineOptions(
                homeOverride: environment["MACAUDIT_HOME"],
                fake: fake,
                offline: environment["MACAUDIT_OFFLINE"] == "1",
                rmMode: false
            ))
            initialStore = AuditStore(engine: engine, usingFakeData: fake, initialRoot: initialRoot, homeRoot: initialRoot)
        } catch {
            // Without an engine there is nothing to show; surface the reason.
            initialStore = AuditStore(engine: UnavailableEngine(), usingFakeData: fake, initialRoot: initialRoot, homeRoot: initialRoot)
            _startupError = State(initialValue: "\(error)")
        }
        _store = State(initialValue: initialStore)
        coordinator = ApplicationCoordinator(store: initialStore)
        if !isTesting {
            coordinator.start()
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(store)
                .background(MemoryOnlyWindow())
                .alert("MacAudit could not start", isPresented: .constant(startupError != nil)) {
                    Button("Quit") { NSApplication.shared.terminate(nil) }
                } message: {
                    Text(startupError ?? "")
                }
        }
        .defaultSize(width: 1180, height: 760)
        .commands {
            CommandGroup(after: .toolbar) {
                Button("Refresh All") { store.rescanAll() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(!store.canRefresh)
                Button("Cancel Scan") { store.cancelScan() }
                    .keyboardShortcut(".", modifiers: .command)
                    .disabled(!store.canCancelScan)
                Divider()
                Button("Mark / Unmark") {
                    if let id = store.selectedFinding {
                        store.toggleMark(id)
                    }
                }
                .keyboardShortcut(" ", modifiers: [])
                .disabled(store.selectedFinding == nil)
                Button("Clean Up…") { store.openConfirm() }
                    .keyboardShortcut("x", modifiers: .command)
                    .disabled(store.marked.isEmpty || !store.canRefresh)
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
                .background(MemoryOnlyWindow())
        }
        MenuBarExtra {
            MenuBarContent().environment(store)
                .background(MemoryOnlyWindow())
        } label: {
            Label("Loaded: \(Formatting.bytes(store.totalReclaimableBytes))", systemImage: store.isScanning ? "internaldrive.fill" : "internaldrive")
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
                Text("Loaded-page reclaimable").font(.headline)
                Spacer()
                Text(Formatting.bytes(store.totalReclaimableBytes))
                    .font(.headline).monospacedDigit().contentTransition(.numericText())
            }
            // Projects/App Storage are top-level lenses (Sidebar), not
            // reclaimable-cleanup sections — kept out of this menu the same
            // way they're kept out of the sidebar's Sections list.
            ForEach(store.scanSections, id: \.id) { meta in
                let bytes = store.reclaimableBytes(in: meta.id)
                if bytes > 0 || {
                    if case .scanning = store.status(of: meta.id) {
                        true
                    } else {
                        false
                    }
                }() {
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
                Button(store.isScanning ? "Scanning…" : "Refresh All") { store.rescanAll() }
                    .disabled(store.isScanning || !store.canRefresh)
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
    func sections() -> [SectionMeta] {
        []
    }

    func deleteMode() -> DeleteMode {
        .trash
    }

    func configPath() -> String {
        ""
    }

    func fullDiskAccess() -> Bool {
        true
    }

    func startScan(sections _: [SectionId], listener _: ScanListener) -> UInt64 {
        0
    }

    func cancelScan() {}
    func findings(section _: SectionId) -> [Finding] {
        []
    }

    func plan(selection _: [Selection]) throws -> Plan {
        throw MacAuditError.Invalid(message: "engine unavailable")
    }

    func execute(plan _: Plan, listener _: ExecListener) throws {
        throw MacAuditError.Invalid(message: "engine unavailable")
    }

    func cancelCleanup() {}
    func dirRoot() -> DirEntry? {
        nil
    }

    func dirEntry(path _: String) -> DirEntry? {
        nil
    }

    func dirChildren(path _: String) -> [DirEntry] {
        []
    }

    func dirSubtree(path _: String, depth _: UInt32, maxNodes _: UInt32) -> [DirEntry] {
        []
    }

    func dirTopFiles(path _: String, n _: UInt32) -> [TopFile] {
        []
    }

    func largestFiles(n _: UInt32) -> [TopFile] {
        []
    }

    func dirTreeStats() -> DirTreeStats? {
        nil
    }

    func footprint(findingId _: UInt64) -> Footprint? {
        nil
    }

    func footprintBuckets(axis _: AttributionAxis) -> FootprintBuckets? {
        nil
    }
}
