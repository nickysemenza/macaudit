import AppKit
import MacAuditKit
import SwiftUI

/// Inspector content for the Folders browser: facts about the selected (or
/// current) directory, its largest files, and any findings under it.
/// Mirrors `FindingInspector`'s structure and `facts` grid style.
struct DirInspector: View {
    @Environment(AuditStore.self) private var store
    let entry: DirEntry?

    /// The selected directory's own largest loose files, fetched live
    /// (directories no longer carry a per-node file list).
    @State private var topFiles: [TopFile] = []

    var body: some View {
        if let e = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header(e)
                    facts(e)
                    largestFiles(e)
                    findings(e)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .task(id: entry?.path) {
                await loadTopFiles(for: e.path)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "folder")
        }
    }

    private func loadTopFiles(for path: String) async {
        let engine = store.engine
        let files = await Task.detached { engine.dirTopFiles(path: path, n: 5) }.value
        // The selection may have changed while this awaited; drop a stale
        // result rather than showing files for the wrong directory.
        guard path == entry?.path else { return }
        topFiles = files
    }

    private func header(_ e: DirEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(e.name).font(.title3.weight(.semibold)).textSelection(.enabled)
            HStack(spacing: 6) {
                Text(PathDisplay.abbreviateHome(e.path))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: e.path)])
                } label: {
                    Image(systemName: "arrow.up.forward.app")
                }
                .buttonStyle(.borderless)
                .help("Reveal in Finder")
            }
        }
    }

    private func facts(_ e: DirEntry) -> some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
            GridRow {
                Text("Allocated").foregroundStyle(.secondary)
                Text(Formatting.bytes(e.alloc)).monospacedDigit()
            }
            GridRow {
                Text("Apparent").foregroundStyle(.secondary)
                Text(Formatting.bytes(e.apparent)).monospacedDigit()
            }
            GridRow {
                Text("Files").foregroundStyle(.secondary)
                Text(Formatting.count(e.files))
            }
            GridRow {
                Text("Folders").foregroundStyle(.secondary)
                Text(Formatting.count(e.dirs))
            }
            if e.errors > 0 {
                GridRow {
                    Text("Unreadable").foregroundStyle(.secondary)
                    Text(Formatting.count(e.errors))
                }
            }
        }
        .font(.callout)
    }

    private func largestFiles(_: DirEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Largest files here").font(.headline)
            if topFiles.isEmpty {
                Text("none").font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(topFiles) { f in
                    HStack(spacing: 6) {
                        Text((f.path as NSString).lastPathComponent).lineLimit(1)
                        Spacer()
                        Text(Formatting.bytes(f.alloc)).monospacedDigit().foregroundStyle(.secondary)
                        Button {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: f.path)])
                        } label: {
                            Image(systemName: "arrow.up.forward.app")
                        }
                        .buttonStyle(.borderless)
                        .help("Reveal in Finder")
                    }
                    .font(.callout)
                }
            }
        }
    }

    private func findings(_ e: DirEntry) -> some View {
        let items = store.fsFindings(under: e.path)
        let reclaimable = items.filter { $0.severity == .reclaimable }.reduce(0) { $0 + ($1.sizeBytes ?? 0) }
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Findings in this folder").font(.headline)
                Spacer()
                if reclaimable > 0 {
                    Text("\(Formatting.bytes(reclaimable)) reclaimable")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if items.isEmpty {
                Text("none").font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(items.prefix(50)) { f in
                    HStack(spacing: 8) {
                        MarkToggle(store: store, id: f.id)
                        Text(f.title).lineLimit(1)
                        Spacer()
                        Text(Formatting.bytes(f.sizeBytes ?? 0)).monospacedDigit().foregroundStyle(.secondary)
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { store.selectedFinding = f.id }
                }
                if items.count > 50 {
                    Text("+\(items.count - 50) more").font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
    }
}
