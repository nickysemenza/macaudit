import AppKit
import MacAuditKit
import SwiftUI

/// Inspector content for a lens's ranked owner (whether merely selected in
/// the table, or fully opened as `OwnerDetailView`): facts grid, this
/// owner's share of the axis, its resource-kind breakdown, and — for
/// Projects — the worktrees/processes/ports strip. Mirrors
/// `FindingInspector`'s structure.
struct OwnerInspector: View {
    @Environment(AuditStore.self) private var store
    let finding: Finding
    let axis: AttributionAxis

    private var sectionId: SectionId { axis == .projects ? .projects : .appStorage }

    var body: some View {
        if let summary = OwnerSummary(finding) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header(summary)
                    facts(summary)
                    if summary.cloneNote {
                        ApfsCloneNote(store: store, compact: true)
                    }
                    shareOfAxis(summary)
                    byKind(summary)
                    if axis == .projects { strip(summary) }
                    if store.owners[axis]?.selectedOwner?.id != finding.id {
                        Button("Open") { store.openOwner(finding, axis: axis) }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "shippingbox")
        }
    }

    private func header(_ s: OwnerSummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Text(finding.title).font(.title3.weight(.semibold)).textSelection(.enabled)
                Spacer()
                if let kind = s.ownerKind {
                    Text(kind.label)
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                        .foregroundStyle(.secondary)
                }
            }
            if let path = finding.path {
                HStack(spacing: 6) {
                    Text(PathDisplay.abbreviateHome(path))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(3)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                    } label: {
                        Image(systemName: "arrow.up.forward.app")
                    }
                    .buttonStyle(.borderless)
                    .help("Reveal in Finder")
                }
            }
        }
    }

    private func facts(_ s: OwnerSummary) -> some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
            GridRow {
                Text("Exclusive").foregroundStyle(.secondary)
                Text(Formatting.bytes(s.exclusive)).monospacedDigit()
            }
            GridRow {
                Text("Shared").foregroundStyle(.secondary)
                Text(Formatting.bytes(s.shared)).monospacedDigit()
            }
            GridRow {
                Text("Reach").foregroundStyle(.secondary)
                Text(Formatting.bytes(s.reach)).monospacedDigit()
            }
            GridRow {
                Text("Baseline share").foregroundStyle(.secondary)
                Text(Formatting.bytes(s.baselineShare)).monospacedDigit()
            }
            if let tier = s.topTier {
                GridRow {
                    Text("Best evidence").foregroundStyle(.secondary)
                    Text(tier.label)
                }
            }
        }
        .font(.callout)
    }

    /// This owner's stacked bar against the axis's largest `reach` — the
    /// same scale/cell the ranked table draws, so the inspector and the
    /// table agree visually.
    @ViewBuilder
    private func shareOfAxis(_ s: OwnerSummary) -> some View {
        let rows = LensModel.rows(store.findings(in: sectionId))
        if let row = rows.first(where: { $0.finding.id == finding.id }) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Share of \(axis == .projects ? "Projects" : "Apps")").font(.headline)
                OwnerBarCell(row: row)
            }
        }
    }

    @ViewBuilder
    private func byKind(_ s: OwnerSummary) -> some View {
        if !s.byKind.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("Breakdown").font(.headline)
                ForEach(Array(s.byKind.enumerated()), id: \.offset) { _, k in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(k.kind.map(Palette.color(for:)) ?? Color.gray)
                            .frame(width: 8, height: 8)
                        Text(k.label).lineLimit(1)
                        Spacer()
                        Text(Formatting.bytes(k.bytes)).monospacedDigit().foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
            }
        }
    }

    private func strip(_ s: OwnerSummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Worktrees").font(.headline)
            if s.worktrees.isEmpty {
                Text("none").font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(s.worktrees, id: \.self) { w in
                    Text(PathDisplay.abbreviateHome(w))
                        .font(.caption)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
            HStack {
                Text("Processes").font(.headline)
                Spacer()
                Text("\(s.processCount)").foregroundStyle(.secondary)
            }
            HStack {
                Text("Ports").font(.headline)
                Spacer()
                Text(s.ports.isEmpty ? "none" : s.ports.map(String.init).joined(separator: ", "))
                    .foregroundStyle(.secondary)
            }
        }
    }
}
