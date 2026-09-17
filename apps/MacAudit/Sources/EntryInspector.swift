import AppKit
import MacAuditKit
import SwiftUI

/// Inspector content for one `FootprintEntry` row inside an owner's entity
/// page (`OwnerDetailView`): path, bytes, every owner it's shared with, its
/// evidence tier/sentence, and — when it links back to a real finding —
/// a `MarkToggle` plus Reveal/Browse actions.
struct EntryInspector: View {
    @Environment(AuditStore.self) private var store
    let entry: FootprintEntry
    let axis: AttributionAxis

    /// The entry's `finding` id resolved against the store's live findings —
    /// `nil` when the id is absent (bucket entries carry none) or stale
    /// (the section rescanned and dropped it).
    private var linkedFinding: Finding? {
        entry.finding.flatMap(store.finding)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                if let finding = linkedFinding {
                    HStack {
                        MarkToggle(store: store, id: finding.id)
                        Text(store.marked.contains(finding.id) ? "Marked for cleanup" : "Mark for cleanup")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                facts
                badges
                if entry.cloneOfStore {
                    ApfsCloneNote(store: store, compact: true)
                }
                evidence
                if !entry.owners.isEmpty { owners }
                if let reason = entry.reason { note("Why unattributed", reason) }
                actions
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(entry.label).font(.title3.weight(.semibold)).textSelection(.enabled)
            Text(PathDisplay.abbreviateHome(entry.path))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private var facts: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
            GridRow {
                Text("Kind").foregroundStyle(.secondary)
                Text(entry.kind.label)
            }
            GridRow {
                Text("Bytes").foregroundStyle(.secondary)
                Text(Formatting.bytes(entry.bytes)).monospacedDigit()
            }
            if entry.rawBytes != entry.bytes {
                GridRow {
                    Text("Raw bytes").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(Formatting.bytes(entry.rawBytes)).monospacedDigit()
                        Text("before subtracting nested/shared bytes").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            GridRow {
                Text("Owners").foregroundStyle(.secondary)
                Text("\(entry.owners.count)")
            }
        }
        .font(.callout)
    }

    @ViewBuilder
    private var badges: some View {
        let items: [(String, String, Color)] = [
            entry.stale ? ("stale", "stale — the project/app it pointed to is gone", .orange) : nil,
            entry.cloneOfStore ? ("clone", "APFS clone of a shared store", .blue) : nil,
            entry.virtualBytes ? ("virtual", "Docker-reported size, not counted in any total", .purple) : nil,
            entry.unsized ? ("unsized", "outside the walked tree — size unknown", .gray) : nil,
        ].compactMap { $0 }
        if !items.isEmpty {
            HStack(spacing: 6) {
                ForEach(items, id: \.0) { label, help, color in
                    Text(label)
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(color.opacity(0.15), in: Capsule())
                        .foregroundStyle(color)
                        .help(help)
                }
            }
        }
    }

    private var evidence: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text("Evidence").font(.headline)
                Text(entry.tier.label)
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
                    .foregroundStyle(.secondary)
                    .help(tierSentence)
            }
            if !entry.evidence.isEmpty {
                Text(entry.evidence).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
    }

    private var tierSentence: String {
        switch entry.tier {
        case .exact: "A manifest or config file names this path directly."
        case .nameMatch: "The project/app name matches this path's name."
        case .observed: "Seen live — an open file or process cwd under this path."
        case .ecosystemDefault: "No owner pins this; it's the ecosystem's shared default."
        case .curated: "Matched against a small built-in table, last resort."
        }
    }

    private var owners: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(entry.owners.count > 1 ? "Shared with" : "Owner").font(.headline)
            ForEach(entry.owners, id: \.self) { key in
                Text(key).font(.callout).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(1)
            }
        }
    }

    private func note(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            Text(body).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }

    private var actions: some View {
        HStack {
            Button("Browse in Folders") { store.browse(path: entry.path) }
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: entry.path)])
            }
        }
        .controlSize(.small)
    }
}
