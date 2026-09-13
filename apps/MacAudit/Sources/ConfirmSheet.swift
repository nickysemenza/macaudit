import MacAuditKit
import SwiftUI

/// What the batch will run, verbatim, before anything happens.
struct ConfirmSheet: View {
    @Environment(AuditStore.self) private var store
    let summary: PlanSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Confirm cleanup").font(.title2.weight(.semibold))
            Text(headline).foregroundStyle(.secondary)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if !summary.actions.isEmpty {
                        section("Will run, in order") {
                            ForEach(Array(summary.actions.enumerated()), id: \.offset) { i, a in
                                ActionLine(index: i, action: a)
                            }
                        }
                    }
                    if !summary.refused.isEmpty {
                        section("Refused") {
                            ForEach(Array(summary.refused.enumerated()), id: \.offset) { _, r in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(r.action.rendered).font(.caption.monospaced()).strikethrough()
                                    Text(r.reason).font(.caption).foregroundStyle(.red)
                                }
                            }
                        }
                    }
                    if let impact = summary.impact { BrewImpactView(impact: impact) }
                    if !summary.removed.isEmpty { list("Removes", summary.removed) }
                    if !summary.remaining.isEmpty { list("Keeps", summary.remaining) }
                    if !summary.followUp.isEmpty { list("Follow up", summary.followUp) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Text(summary.deleteMode == .rm ? "Deletes permanently (rm mode)" : "Deletions go to the Trash")
                    .font(.caption)
                    .foregroundStyle(summary.deleteMode == .rm ? .red : .secondary)
                Spacer()
                Button("Cancel") { store.dismissConfirm() }
                    .keyboardShortcut(.cancelAction)
                Button(summary.actions.isEmpty ? "Nothing to run" : "Run \(summary.actions.count) action(s)") {
                    store.executePendingPlan()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(summary.actions.isEmpty)
            }
        }
        .padding(20)
        .frame(minWidth: 560, idealWidth: 680, minHeight: 360, idealHeight: 520)
    }

    private var headline: String {
        let bytes = summary.actions.compactMap(\.reclaimsBytes).reduce(0, +)
        var s = "\(summary.actions.count) action(s)"
        if bytes > 0 { s += ", reclaims \(Formatting.bytes(bytes))" }
        if !summary.refused.isEmpty { s += "; \(summary.refused.count) refused" }
        return s
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            content()
        }
    }

    private func list(_ title: String, _ items: [String]) -> some View {
        section(title) {
            ForEach(items, id: \.self) { Text($0).font(.callout) }
        }
    }
}

struct ActionLine: View {
    let index: Int
    let action: PlannedActionView
    var status: (ok: Bool, message: String)? = nil
    var running = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Group {
                if running {
                    ProgressView().controlSize(.small)
                } else if let status {
                    Image(systemName: status.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(status.ok ? .green : .red)
                } else {
                    Text("\(index + 1).").foregroundStyle(.secondary).monospacedDigit()
                }
            }
            .frame(width: 22, alignment: .trailing)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(action.label)
                    if action.destructive {
                        Text("destructive").font(.caption2).foregroundStyle(.red)
                    }
                    if let bytes = action.reclaimsBytes {
                        Text(Formatting.bytes(bytes)).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Text(action.rendered)
                    .font(.caption.monospaced())
                    .foregroundStyle(action.destructive ? .red : .secondary)
                    .textSelection(.enabled)
                if let status, !status.ok {
                    Text(status.message).font(.caption).foregroundStyle(.red)
                }
            }
        }
    }
}

private struct BrewImpactView: View {
    let impact: BrewImpact

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Homebrew impact").font(.headline)
            if !impact.removable.isEmpty {
                row("Removable", impact.removable.joined(separator: ", "))
            }
            ForEach(impact.blocked, id: \.name) { b in
                row("Blocked: \(b.name)", "still needed by \(b.retainedBy.joined(separator: ", "))", tint: .orange)
            }
            if !impact.newlyOrphaned.isEmpty {
                row("Will become orphaned", impact.newlyOrphaned.joined(separator: ", "))
            }
            if !impact.uncertainOrphans.isEmpty {
                row("Maybe orphaned", impact.uncertainOrphans.joined(separator: ", "), tint: .orange)
            }
            if let b = impact.bytesSelected {
                row("Bytes", Formatting.bytes(b) + (impact.bytesWithOrphans.map { " (\(Formatting.bytes($0)) with orphans)" } ?? ""))
            }
            ForEach(impact.caveats, id: \.self) { Text($0).font(.caption).foregroundStyle(.orange) }
        }
    }

    private func row(_ k: String, _ v: String, tint: Color = .secondary) -> some View {
        HStack(alignment: .top) {
            Text(k).foregroundStyle(tint).frame(width: 150, alignment: .leading)
            Text(v).font(.callout)
        }
        .font(.callout)
    }
}
