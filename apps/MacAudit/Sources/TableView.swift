import AppKit
import MacAuditKit
import SwiftUI

/// Sortable flat table (Disk, Ports, Tools, …).
struct TableView: View {
    @Environment(AuditStore.self) private var store
    let findings: [Finding]
    @State private var sortOrder: [KeyPathComparator<Finding>] = [
        KeyPathComparator(\Finding.sortBytes, order: .reverse)
    ]

    var body: some View {
        @Bindable var store = store
        Table(findings.sorted(using: sortOrder), selection: $store.selectedFinding, sortOrder: $sortOrder) {
            TableColumn("") { f in MarkToggle(store: store, id: f.id) }
                .width(24)
            TableColumn("Name", value: \.title) { f in
                VStack(alignment: .leading, spacing: 1) {
                    Text(f.title).lineLimit(1)
                    if !f.detail.isEmpty {
                        Text(f.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            .width(min: 200, ideal: 320)
            TableColumn("Size", value: \.sortBytes) { f in
                Text(Formatting.bytes(f.sizeBytes)).monospacedDigit()
            }
            .width(min: 70, ideal: 90)
            TableColumn("Last used", value: \.sortUsed) { f in
                Text(Formatting.age(f.lastUsed)).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 100)
            TableColumn("Severity", value: \.sortSeverity) { f in SeverityBadge(severity: f.severity) }
                .width(min: 80, ideal: 100)
            TableColumn("Path", value: \.sortPath) { f in
                Text(f.path ?? "").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
        .contextMenu(forSelectionType: UInt64.self) { ids in
            if let id = ids.first, let finding = store.finding(id) {
                RowContextMenu(store: store, finding: finding)
            }
        }
    }
}

extension Finding {
    var sortBytes: UInt64 { sizeBytes ?? 0 }
    var sortUsed: Date { lastUsed ?? .distantPast }
    var sortPath: String { path ?? "" }
    var sortSeverity: Int {
        switch severity {
        case .info: 0
        case .attention: 1
        case .reclaimable: 2
        case .warning: 3
        }
    }
}

/// Shared row context menu (Table uses the selection-typed variant).
///
/// `store` is passed in rather than read from the environment for the same
/// reason as `MarkToggle`: menu content built for a `Table` row is hosted
/// outside the main view graph and may not carry the Observable environment.
struct RowContextMenu: View {
    let store: AuditStore
    let finding: Finding

    var body: some View {
        Button(store.marked.contains(finding.id) ? "Unmark" : "Mark for Cleanup") { store.toggleMark(finding.id) }
        if let path = finding.path {
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(path, forType: .string)
            }
        }
        Divider()
        Button("Rescan \(store.meta(for: finding.section)?.title ?? "Section")") { store.rescan(finding.section) }
    }
}
