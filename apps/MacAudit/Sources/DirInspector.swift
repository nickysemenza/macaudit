import AppKit
import MacAuditKit
import SwiftUI

/// Inspector content for the Folders browser: facts about the selected (or
/// current) directory, its largest files, and any findings under it.
/// Mirrors `FindingInspector`'s structure and `facts` grid style.
struct DirInspector: View {
    @Environment(AuditStore.self) private var store
    @Environment(\.locale) private var locale
    @Environment(\.timeZone) private var timeZone
    let entry: DirEntry?

    /// The selected directory's own largest loose files, fetched live
    /// (directories no longer carry a per-node file list).
    @State private var liveFiles: LiveFilesPage?
    @State private var liveError: String?
    private var topFiles: [TopFile] {
        liveFiles?.files ?? []
    }

    private var observedAt: Date? {
        guard let milliseconds = liveFiles?.observedAtMs, milliseconds > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
    }

    var body: some View {
        if let e = entry {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if !store.hasFullDiskAccess, e.errors > 0 {
                        FullDiskAccessBanner(store: store, compact: true)
                    }
                    header(e)
                    facts(e)
                    if e.path == store.browser.root?.path {
                        RootAccountingFacts(stats: store.browser.rootStats)
                    } else {
                        Text("Scan allocation is not reclaimable space. Hard links are charged once; external links and shared extents can keep storage allocated after deletion.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    largestFiles(e)
                    findings(e)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .task(id: "\(store.browser.metadata?.runId ?? 0):\(entry?.path ?? "")") {
                await loadTopFiles(for: e.path)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "folder")
        }
    }

    private func loadTopFiles(for path: String) async {
        liveFiles = nil
        liveError = nil
        do {
            let expected = await store.browser.queries.metadata()
            let page = try await store.browser.queries.liveFiles(path: path, limit: 5)
            let latest = await store.browser.queries.metadata()
            guard !Task.isCancelled, path == entry?.path else { return }
            guard page.subjectPath == path, page.metadata.runId == expected.runId, latest.runId == expected.runId,
                  page.metadata.selectedRoot == expected.selectedRoot, latest.selectedRoot == expected.selectedRoot
            else {
                throw MacAuditError.Invalid(message: "The live observation belongs to a changed run or another folder.")
            }
            liveFiles = page
        } catch {
            guard !Task.isCancelled, path == entry?.path else { return }
            liveError = "\(error)"
        }
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
                Text("Scan allocation").foregroundStyle(.secondary)
                Text(Formatting.bytes(e.alloc)).monospacedDigit()
            }
            GridRow {
                Text("Apparent").foregroundStyle(.secondary)
                Text(Formatting.bytes(e.apparent)).monospacedDigit()
            }
            GridRow {
                Text("Unique files").foregroundStyle(.secondary)
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
            Text("Live largest files here").font(.headline)
            Text("Live metadata; not scan allocation.").font(.caption).foregroundStyle(.secondary)
            if let observedAt {
                Text("Observed \(observedAt.formatted(Date.FormatStyle(date: .abbreviated, time: .standard, locale: locale, timeZone: timeZone)))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let liveFiles {
                Text("Live coverage: \(liveFiles.coverage) · \(liveFiles.dataless) dataless skipped · \(liveFiles.errors) errors")
                    .font(.caption).foregroundStyle(.secondary)
                if !liveFiles.stopReasons.isEmpty {
                    Text(liveFiles.stopReasons.joined(separator: ", ")).font(.caption).foregroundStyle(.orange)
                }
            }
            if let liveError {
                Text(liveError).font(.caption).foregroundStyle(.orange)
            }
            if topFiles.isEmpty {
                Text("No live file observations available").font(.callout).foregroundStyle(.secondary)
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
