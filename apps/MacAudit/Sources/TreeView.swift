import MacAuditKit
import SwiftUI

/// Collapsible groups (Apps, Brew, Disk): groups ordered by total bytes,
/// biggest first, then by name for size-less sections; items within a
/// group by size then title — the TUI's `tree::build_rows` ordering.
struct TreeView: View {
    @Environment(AuditStore.self) private var store
    let findings: [Finding]
    @State private var collapsed: Set<String> = []

    private struct Group: Identifiable {
        let key: String
        let items: [Finding]
        let bytes: UInt64
        var id: String { key }
    }

    private var groups: [Group] {
        let byKey = Dictionary(grouping: findings, by: \.group)
        return byKey.map { key, items in
            Group(
                key: key,
                items: items.sorted { ($0.sizeBytes ?? 0, $1.title) > ($1.sizeBytes ?? 0, $0.title) },
                bytes: items.reduce(0) { $0 + ($1.sizeBytes ?? 0) })
        }
        .sorted { ($0.bytes, $1.key) > ($1.bytes, $0.key) }
    }

    var body: some View {
        @Bindable var store = store
        List(selection: $store.selectedFinding) {
            ForEach(groups) { group in
                Section {
                    if !collapsed.contains(group.key) {
                        ForEach(group.items) { f in
                            FindingRow(finding: f).tag(f.id)
                        }
                    }
                } header: {
                    HStack {
                        Image(systemName: collapsed.contains(group.key) ? "chevron.right" : "chevron.down")
                            .font(.caption)
                            .frame(width: 12)
                        Text(group.key)
                        Text("\(group.items.count)").foregroundStyle(.secondary)
                        Spacer()
                        if group.bytes > 0 {
                            Text(Formatting.bytes(group.bytes)).monospacedDigit().foregroundStyle(.secondary)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        if collapsed.contains(group.key) { collapsed.remove(group.key) } else { collapsed.insert(group.key) }
                    }
                }
            }
        }
    }
}

struct FindingRow: View {
    @Environment(AuditStore.self) private var store
    let finding: Finding

    var body: some View {
        HStack(spacing: 8) {
            MarkToggle(id: finding.id)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).lineLimit(1)
                if !finding.detail.isEmpty {
                    Text(finding.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer()
            if finding.sizeBytes != nil {
                Text(Formatting.bytes(finding.sizeBytes)).monospacedDigit().foregroundStyle(.secondary)
            }
            SeverityBadge(severity: finding.severity)
        }
        .padding(.vertical, 2)
    }
}
