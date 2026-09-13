import MacAuditKit
import SwiftUI

/// Resource Health: metric cards (CPU, memory, swap, disk) plus the
/// processes worth looking at.
struct OverviewView: View {
    @Environment(AuditStore.self) private var store
    let findings: [Finding]

    private var metrics: [Finding] {
        findings.filter { $0.kind == .systemMetric }.sorted { $0.title < $1.title }
    }

    private var processes: [Finding] {
        findings.filter { $0.kind == .processResource }
            .sorted { ($0.sizeBytes ?? 0) > ($1.sizeBytes ?? 0) }
    }

    var body: some View {
        @Bindable var store = store
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 12)], spacing: 12) {
                    ForEach(metrics) { f in
                        MetricCard(finding: f, selected: store.selectedFinding == f.id)
                            .onTapGesture { store.selectedFinding = f.id }
                    }
                }
                if !processes.isEmpty {
                    Text("Processes").font(.headline)
                    Table(processes, selection: $store.selectedFinding) {
                        TableColumn("Process") { Text($0.title) }
                        TableColumn("Detail") { Text($0.detail).foregroundStyle(.secondary) }
                        TableColumn("Memory") { Text(Formatting.bytes($0.sizeBytes)).monospacedDigit() }
                            .width(min: 80, ideal: 100)
                        TableColumn("Severity") { SeverityBadge(severity: $0.severity) }
                            .width(min: 80, ideal: 100)
                    }
                    .frame(minHeight: 200, idealHeight: CGFloat(processes.count) * 28 + 40)
                }
            }
            .padding()
        }
    }
}

private struct MetricCard: View {
    let finding: Finding
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(finding.title).font(.headline)
                Spacer()
                SeverityBadge(severity: finding.severity)
            }
            Text(finding.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(selected ? Color.accentColor : .clear, lineWidth: 2))
    }
}
