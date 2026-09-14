import MacAuditKit
import SwiftUI

struct SectionDetail: View {
    @Environment(AuditStore.self) private var store
    let meta: SectionMeta

    var body: some View {
        let all = store.findings(in: meta.id)
        let findings = store.visibleFindings(in: meta.id)
        Group {
            if all.isEmpty {
                emptyState
            } else if findings.isEmpty {
                ContentUnavailableView.search(text: store.searchText)
            } else {
                switch meta.view {
                case .overview:
                    OverviewView(findings: findings)
                case .tree, .table:
                    VStack(spacing: 0) {
                        SectionChartHeader(section: meta.id, findings: all)
                        if meta.view == .tree {
                            TreeView(findings: findings)
                        } else {
                            TableView(findings: findings)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        switch store.status(of: meta.id) {
        case .scanning(let msg, _, _):
            VStack(spacing: 12) {
                ProgressView()
                Text(msg.isEmpty ? "Scanning…" : msg).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let error):
            ContentUnavailableView {
                Label("Scan failed", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            } actions: {
                Button("Retry") { store.rescan(meta.id) }
            }
        case .done:
            ContentUnavailableView("Nothing found", systemImage: "checkmark.circle")
        case .idle:
            ContentUnavailableView {
                Label("Not scanned", systemImage: "magnifyingglass")
            } actions: {
                Button("Scan") { store.rescan(meta.id) }
            }
        }
    }
}

/// Shared row pieces.
struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.label)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private var color: Color {
        switch severity {
        case .info: .secondary
        case .attention: .blue
        case .reclaimable: .orange
        case .warning: .red
        }
    }
}

/// Checkbox that marks a finding for cleanup.
///
/// Takes the store as a parameter instead of reading `@Environment(AuditStore.self)`:
/// this view is placed in `Table` cells, which AppKit hosts in per-cell
/// `NSHostingView`s. On macOS 26 a cell inserted into an already-visible table
/// (rows streaming in from a scan) is built without the Observable environment,
/// and the environment read traps with "No Observable object of type AuditStore
/// found". Observation still tracks `store.marked` through the passed reference.
struct MarkToggle: View {
    let store: AuditStore
    let id: UInt64

    var body: some View {
        Toggle(isOn: Binding(get: { store.marked.contains(id) }, set: { _ in store.toggleMark(id) })) {
            EmptyView()
        }
        .toggleStyle(.checkbox)
        .labelsHidden()
        .help("Mark for cleanup")
    }
}
