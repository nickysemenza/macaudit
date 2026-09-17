import MacAuditKit
import SwiftUI

struct ContentView: View {
    @Environment(AuditStore.self) private var store
    @State private var showInspector = true

    var body: some View {
        @Bindable var store = store
        NavigationSplitView {
            SectionSidebar()
        } detail: {
            Group {
                switch store.selectedItem {
                case .storage:
                    StorageOverview()
                        .navigationTitle("Storage")
                        .navigationSubtitle("\(Formatting.bytes(store.totalReclaimableBytes)) reclaimable across \(store.sections.count) sections")
                case .section(let section):
                    if let meta = store.meta(for: section) {
                        SectionDetail(meta: meta)
                            .navigationTitle(meta.title)
                            .navigationSubtitle(subtitle(for: section))
                            .searchable(text: $store.searchText, placement: .toolbar, prompt: "Filter \(meta.title)")
                    }
                case .folders:
                    FolderBrowserView()
                        .navigationTitle("Folders")
                        .navigationSubtitle(store.browser.current.map { PathDisplay.abbreviateHome($0.path) } ?? "")
                case nil:
                    ContentUnavailableView("Pick a section", systemImage: "sidebar.left")
                }
            }
            .navigationSplitViewColumnWidth(min: 360, ideal: 640)
            .stableColumnSize()
        }
        .onChange(of: store.selectedItem) { _, _ in store.searchText = "" }
        .inspector(isPresented: $showInspector) {
            Group {
                if store.selectedItem == .folders {
                    DirInspector(entry: store.browser.selectedEntry ?? store.browser.current)
                } else {
                    FindingInspector(finding: store.finding(store.selectedFinding))
                }
            }
            .inspectorColumnWidth(min: 280, ideal: 340, max: 520)
            .stableColumnSize()
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    if let s = store.selectedSection { store.rescan(s) }
                } label: {
                    Label("Rescan Section", systemImage: "arrow.clockwise")
                }
                .disabled(store.selectedSection == nil)
                .help("Rescan this section (⇧⌘R)")

                Button {
                    if let id = store.selectedFinding { store.toggleMark(id) }
                } label: {
                    Label(
                        store.selectedFinding.map { store.marked.contains($0) } == true ? "Unmark" : "Mark",
                        systemImage: store.selectedFinding.map { store.marked.contains($0) } == true
                            ? "checkmark.circle.fill" : "checkmark.circle")
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
                .disabled(store.marked.isEmpty)
                .help("Plan and confirm the marked cleanup (⌘X)")

                Button {
                    showInspector.toggle()
                } label: {
                    Label("Inspector", systemImage: "sidebar.right")
                }
            }
        }
        .sheet(isPresented: Binding(get: { store.pendingSummary != nil }, set: { if !$0 { store.dismissConfirm() } })) {
            if let summary = store.pendingSummary {
                ConfirmSheet(summary: summary)
            }
        }
        .sheet(isPresented: Binding(get: { store.cleanup != nil }, set: { if !$0 { store.dismissCleanup() } })) {
            CleanupProgressView()
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
        case .scanning(let msg, let done, let total):
            var s = "scanning"
            if let total, total > 0 { s += " \(done)/\(total)" } else if done > 0 { s += " \(done)" }
            if !msg.isEmpty { s += " — \(msg)" }
            return s
        case .done(let ms):
            let reclaimable = store.reclaimableBytes(in: section)
            var s = "\(store.count(of: section)) findings in \(Double(ms) / 1000, specifier: "%.1f")s"
            if reclaimable > 0 { s += " · \(Formatting.bytes(reclaimable)) reclaimable" }
            return s
        case .failed(let error): return "failed: \(error)"
        }
    }
}

extension String.StringInterpolation {
    mutating func appendInterpolation(_ value: Double, specifier: String) {
        appendLiteral(String(format: specifier, value))
    }
}
