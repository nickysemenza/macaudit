import MacAuditKit
import SwiftUI

struct SnapshotsView: View {
    @Environment(AuditStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<Int64> = []
    @State private var diff: SnapshotDiff?
    @State private var diffError: String?

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Snapshots").font(.title2.weight(.semibold))
                Table(store.snapshots, selection: $selected) {
                    TableColumn("#") { Text("\($0.id)").monospacedDigit() }.width(40)
                    TableColumn("When") { Text($0.createdAt.formatted(date: .abbreviated, time: .shortened)) }
                    TableColumn("Findings") { Text("\($0.findingCount)").monospacedDigit() }.width(70)
                    TableColumn("Size") { Text(Formatting.bytes($0.totalBytes)).monospacedDigit() }.width(90)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                HStack {
                    Button("Save Now") { store.saveSnapshot() }
                        .disabled(store.isScanning)
                        .help("Persist the current findings (refused while a section failed)")
                    Button("Diff Selected") { runDiff() }
                        .disabled(selected.count != 2)
                    Spacer()
                    Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                }
                if let err = store.snapshotError ?? diffError {
                    Text(err).font(.caption).foregroundStyle(.red)
                }
            }
            .padding()
            .frame(minWidth: 380, maxHeight: .infinity, alignment: .top)

            DiffView(diff: diff)
                .frame(minWidth: 320, maxHeight: .infinity)
        }
        .frame(minWidth: 820, idealWidth: 960, minHeight: 380, idealHeight: 560)
        .onAppear { store.refreshSnapshots() }
    }

    private func runDiff() {
        let ids = selected.sorted()
        guard ids.count == 2 else { return }
        switch store.diff(ids[0], ids[1]) {
        case .success(let d):
            diff = d
            diffError = nil
        case .failure(let e):
            diffError = "\(e)"
        }
    }
}

private struct DiffView: View {
    let diff: SnapshotDiff?

    var body: some View {
        if let diff {
            List {
                if !diff.added.isEmpty {
                    Section("Added (\(diff.added.count))") {
                        ForEach(diff.added) { line($0, tint: .green) }
                    }
                }
                if !diff.removed.isEmpty {
                    Section("Removed (\(diff.removed.count))") {
                        ForEach(diff.removed) { line($0, tint: .red) }
                    }
                }
                if !diff.grown.isEmpty {
                    Section("Grown (\(diff.grown.count))") {
                        ForEach(diff.grown, id: \.finding.id) { g in
                            HStack {
                                Text(g.finding.title).lineLimit(1)
                                Spacer()
                                Text("\(Formatting.bytes(g.oldBytes)) → \(Formatting.bytes(g.newBytes))")
                                    .monospacedDigit().foregroundStyle(.orange)
                            }
                        }
                    }
                }
                if !diff.changed.isEmpty {
                    Section("Changed (\(diff.changed.count))") {
                        ForEach(Array(diff.changed.enumerated()), id: \.offset) { _, c in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.finding.title).lineLimit(1)
                                Text("\(c.field): \(c.old) → \(c.new)").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                if diff.added.isEmpty && diff.removed.isEmpty && diff.grown.isEmpty && diff.changed.isEmpty {
                    Text("No differences").foregroundStyle(.secondary)
                }
            }
        } else {
            ContentUnavailableView("Select two snapshots", systemImage: "arrow.left.arrow.right")
        }
    }

    private func line(_ f: Finding, tint: Color) -> some View {
        HStack {
            Circle().fill(tint).frame(width: 6, height: 6)
            Text(f.title).lineLimit(1)
            Spacer()
            if let b = f.sizeBytes { Text(Formatting.bytes(b)).monospacedDigit().foregroundStyle(.secondary) }
        }
    }
}
