import MacAuditKit
import MacAuditNavigation
import SwiftUI

struct ContentView: View {
    @Environment(AuditStore.self) private var store
    @State private var showInspector = true

    var body: some View {
        @Bindable var store = store
        NavigationSplitView {
            SectionSidebar()
        } detail: {
            VStack(spacing: 0) {
                if let cancellation = store.scanCancellationStatus {
                    Text(cancellation).font(.caption).foregroundStyle(.orange)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                Group {
                    switch store.selectedItem {
                    case .storage:
                        StorageOverview()
                            .navigationTitle("Storage")
                            .navigationSubtitle("Global Audit · bounded loaded-page sample, not whole-scan totals")
                    case .projects, .apps:
                        if let axis = store.selectedItem?.axis, let section = store.selectedItem?.section {
                            if let owner = store.owners[axis]?.selectedOwner {
                                OwnerDetailView(axis: axis)
                                    .navigationTitle(owner.title)
                                    .navigationSubtitle("\(axis.title) · Global scope, independent of Explore root")
                            } else {
                                LensView(axis: axis)
                                    .navigationTitle(axis.title)
                                    .navigationSubtitle("Global scope · \(subtitle(for: section))")
                            }
                        }
                    case let .section(section):
                        if let meta = store.meta(for: section) {
                            SectionDetail(meta: meta)
                                .navigationTitle(meta.title)
                                .navigationSubtitle("\(section == .fs ? "Selected root + Global Audit targets" : "Global Audit") · \(subtitle(for: section))")
                                .searchable(text: $store.searchText, placement: .toolbar, prompt: "Filter loaded page of \(meta.title)")
                        }
                    case .folders:
                        ExploreView(store: store)
                            .navigationTitle("Explore")
                            .navigationSubtitle(store.browser.current.map { PathDisplay.abbreviateHome($0.path) } ?? "")
                    case nil:
                        ContentUnavailableView("Pick a section", systemImage: "sidebar.left")
                    }
                }
            .navigationSplitViewColumnWidth(min: 360, ideal: 640)
            .stableColumnSize()
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if store.selectedItem == .folders {
                    ExploreInspector(browser: store.browser)
                } else if let axis = store.selectedItem?.axis, let browser = store.owners[axis] {
                    if let entry = browser.selectedEntry {
                        EntryInspector(entry: entry, axis: axis)
                    } else if let owner = browser.selectedOwner ?? store.finding(store.selectedFinding) {
                        OwnerInspector(finding: owner, axis: axis)
                    } else {
                        ContentUnavailableView("No selection", systemImage: "info.circle")
                    }
                } else {
                    FindingInspector(finding: store.finding(store.selectedFinding))
                }
            }
            .inspectorColumnWidth(min: 280, ideal: 340, max: 520)
            .stableColumnSize()
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Menu {
                    Button("Home") { store.changeRoot("~") }
                    Button("Boot Volume") { store.changeRoot("/") }
                    Button("Folder or Path…") { store.sheetRoute = .root }
                } label: { Label("Explore Root", systemImage: "folder.badge.plus") }
                    .disabled(!store.canRefresh)
                Button { store.rescanAll() } label: { Label("Refresh All", systemImage: "arrow.clockwise.circle") }
                    .disabled(!store.canRefresh)
                Button { store.cancelScan() } label: { Label("Cancel Scan", systemImage: "stop.circle") }
                    .disabled(!store.canCancelScan)
                Button {
                    if let id = store.selectedFinding {
                        store.toggleMark(id)
                    }
                } label: {
                    Label(
                        store.selectedFinding.map { store.marked.contains($0) } == true ? "Unmark" : "Mark",
                        systemImage: store.selectedFinding.map { store.marked.contains($0) } == true
                            ? "checkmark.circle.fill" : "checkmark.circle"
                    )
                }
                .disabled(store.selectedFinding == nil)
                .help("Mark the selected finding for cleanup (space)")

                Button {
                    store.openConfirm()
                } label: {
                    Label {
                        Text("Clean Up… (\(store.marked.count))").contentTransition(.numericText())
                    } icon: {
                        Image(systemName: "trash")
                    }
                }
                .animation(.default, value: store.marked.count)
                .disabled(store.marked.isEmpty || !store.canRefresh)
                .help("Plan and confirm the marked cleanup (⌘X)")

                Button {
                    showInspector.toggle()
                } label: {
                    Label("Inspector", systemImage: "sidebar.right")
                }
            }
        }
        .sheet(item: Binding(get: { store.sheetRoute }, set: { route in
            guard store.cleanup == nil || store.cleanup?.phase == .done || route == .cleanup else { return }
            store.sheetRoute = route
        }), id: \.rawValue, onDismiss: {
            if store.pendingPlan != nil {
                store.dismissConfirm()
            }
            store.dismissCleanup()
        }) { (route: SheetRoute) in
            switch route {
            case .root: RootSheet(store: store)
            case .confirm:
                if let summary = store.pendingSummary {
                    ConfirmSheet(summary: summary)
                }
            case .cleanup: CleanupProgressView().interactiveDismissDisabled(store.cleanup?.phase != .done)
            }
        }
        .alert("Could not plan cleanup", isPresented: Binding(get: { store.planError != nil }, set: { _ in store.clearPlanError() })) {
            Button("OK") {}
        } message: {
            Text(store.planError ?? "")
        }
        // Columns no longer contribute a minimum (see stableColumnSize), so the window
        // keeps its own constant floor here.
        .frame(minWidth: 900, minHeight: 520)
    }

    private func subtitle(for section: SectionId) -> String {
        switch store.status(of: section) {
        case .idle: return "not scanned"
        case let .scanning(msg, done, total):
            var s = "scanning"
            if let total, total > 0 {
                s += " \(done)/\(total)"
            } else if done > 0 {
                s += " \(done)"
            }
            if !msg.isEmpty {
                s += " — \(msg)"
            }
            return s
        case let .done(ms):
            let reclaimable = store.reclaimableBytes(in: section)
            var s = "\(store.count(of: section)) loaded findings"
            if let ms {
                s += " in \(Double(ms) / 1000, specifier: "%.1f")s"
            }
            if reclaimable > 0 {
                s += " · \(Formatting.bytes(reclaimable)) reclaimable"
            }
            return s
        case let .failed(error): return "failed: \(error)"
        }
    }
}

extension String.StringInterpolation {
    mutating func appendInterpolation(_ value: Double, specifier: String) {
        appendLiteral(String(format: specifier, value))
    }
}
