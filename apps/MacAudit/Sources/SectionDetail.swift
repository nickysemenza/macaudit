import MacAuditKit
import SwiftUI

struct SectionDetail: View {
    @Environment(AuditStore.self) private var store
    let meta: SectionMeta

    var body: some View {
        let findings = store.findings(in: meta.id)
        Group {
            if findings.isEmpty {
                emptyState
            } else {
                switch meta.view {
                case .overview: OverviewView(findings: findings)
                case .tree: TreeView(findings: findings)
                case .table: TableView(findings: findings)
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

struct MarkToggle: View {
    @Environment(AuditStore.self) private var store
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
