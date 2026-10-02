import AppKit
import MacAuditKit
import SwiftUI

/// One owner's entity page (iOS "Settings › Storage › App" style): a
/// breadcrumb bar, four stat tiles, a by-kind bar breakdown, and either a
/// grouped table or a treemap of the entries making it up. `ContentView`
/// swaps this in for `LensView` whenever `store.owners[axis].selectedOwner`
/// is non-nil.
struct OwnerDetailView: View {
    @Environment(AuditStore.self) private var store
    let axis: AttributionAxis

    private var browser: OwnerBrowser? {
        store.owners[axis]
    }

    var body: some View {
        if let browser, let owner = browser.selectedOwner {
            VStack(spacing: 0) {
                OwnerBreadcrumbBar(store: store, axis: axis, browser: browser)
                Divider()
                content(browser: browser, owner: owner)
            }
            .toolbar {
                ToolbarItemGroup {
                    if let path = owner.path {
                        Button {
                            store.browse(path: path)
                        } label: {
                            Label("Browse in Folders", systemImage: "folder")
                        }
                        Button {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                        } label: {
                            Label("Reveal in Finder", systemImage: "arrow.up.forward.app")
                        }
                    }
                    Button {
                        store.rescanAll()
                    } label: {
                        Label("Refresh All", systemImage: "arrow.clockwise")
                    }
                    .disabled(!store.canRefresh)
                }
            }
        } else {
            ContentUnavailableView("No owner open", systemImage: "shippingbox")
        }
    }

    @ViewBuilder
    private func content(browser: OwnerBrowser, owner: Finding) -> some View {
        if let footprint = browser.footprint {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if footprint.cloneNote {
                        ApfsCloneNote(compact: false)
                    }
                    StatTiles(footprint: footprint)
                    if axis == .projects {
                        ProjectStrip(footprint: footprint)
                    }
                    if !footprint.groups.isEmpty {
                        ByKindBreakdown(groups: footprint.groups)
                    }
                }
                .padding(20)
                .frame(maxWidth: 900, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .center)
            }
            Divider()
            switch browser.viewMode {
            case .list:
                EntryGroupedTable(store: store, axis: axis, groups: browser.displayedGroups)
                    .frame(maxHeight: .infinity)
            case .treemap:
                EntryTreemap(store: store, axis: axis, groups: browser.displayedGroups)
                    .frame(maxHeight: .infinity)
            }
            HStack {
                Text("\(browser.loadedEntryCount) of \(browser.totalEntries) owner entries loaded · omitted mass stays Other")
                    .font(.caption)
                Spacer()
                if browser.isLoadingEntries {
                    ProgressView().controlSize(.small)
                }
                Button("Load More Entries") { browser.loadMoreEntries() }
                    .disabled(browser.nextEntriesCursor == nil || browser.isLoadingEntries
                        || browser.loadedEntryCount >= OwnerBrowser.entryLimit)
            }.padding(10)
            if let error = browser.entriesError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        } else if browser.isLoading || store.isScanning {
            VStack(spacing: 12) {
                ProgressView()
                Text("Loading \(owner.title)…").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ContentUnavailableView {
                Label("Not resolved yet", systemImage: "hourglass")
            } description: {
                Text("This owner hasn't been resolved by a scan yet. Refresh All to try again.")
            } actions: {
                Button("Refresh All") { store.rescanAll() }.disabled(!store.canRefresh)
            }
        }
    }
}

/// Back/breadcrumb trail + list/treemap toggle, mirroring
/// `FolderBrowserView`'s `BreadcrumbBar`.
private struct OwnerBreadcrumbBar: View {
    let store: AuditStore
    let axis: AttributionAxis
    let browser: OwnerBrowser

    var body: some View {
        HStack(spacing: 4) {
            Button {
                browser.goBack()
            } label: {
                Image(systemName: "chevron.backward")
            }
            .buttonStyle(.borderless)
            .disabled(!browser.canGoBack)
            .help("Back")

            Button(axis.title) {
                browser.closeToLanding()
            }
            .buttonStyle(.borderless)

            let crumbs = browser.breadcrumbs
            ForEach(Array(crumbs.enumerated()), id: \.element.id) { index, owner in
                Text("›").foregroundStyle(.tertiary)
                let isLast = index == crumbs.count - 1
                Button(owner.title) { browser.openBreadcrumb(owner) }
                    .buttonStyle(.borderless)
                    .fontWeight(isLast ? .bold : .regular)
                    .disabled(isLast)
            }

            Spacer()

            ViewModePicker(selection: Binding(get: { browser.viewMode }, set: { browser.viewMode = $0 }))

            if browser.isLoading {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

/// Exclusive / Shared / Reach / Baseline share, each with a one-line
/// definition in `.help` — `FootprintStat` (MacAuditKit) is the single place
/// those four titles/definitions live, shared with `OwnerInspector`'s facts
/// grid.
private struct StatTiles: View {
    let footprint: Footprint

    var body: some View {
        HStack(spacing: 12) {
            ForEach(footprint.stats, id: \.stat) { item in
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.stat.title.uppercased()).font(.caption2).foregroundStyle(.secondary)
                    Text(Formatting.bytes(item.bytes)).font(.title3.weight(.semibold)).monospacedDigit()
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 10))
                .help(item.stat.help)
            }
        }
    }
}

/// `BarBreakdown` needs `@Binding var selected`, so this owns the small bit
/// of highlight state `content(browser:owner:)` (a plain function, not a
/// View) can't hold itself.
private struct ByKindBreakdown: View {
    let groups: [FootprintGroup]
    @State private var selected: String?

    var body: some View {
        BarBreakdown(
            rows: groups.map {
                BarRow(
                    name: $0.kind.label, parts: [(label: $0.kind.label, value: Double($0.bytes))],
                    color: Palette.color(forKindLabel: $0.kind.label)
                )
            },
            title: "By kind",
            format: { Formatting.bytes(UInt64(max(0, $0))) },
            selected: $selected
        )
    }
}

/// Worktrees / processes / ports strip, Projects only.
private struct ProjectStrip: View {
    let footprint: Footprint

    var body: some View {
        Card(title: "Project") {
            if !footprint.worktrees.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Worktrees").font(.subheadline.weight(.semibold))
                    ForEach(footprint.worktrees, id: \.self) { path in
                        Text(PathDisplay.abbreviateHome(path)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            if !footprint.processes.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Processes").font(.subheadline.weight(.semibold))
                    ForEach(footprint.processes, id: \.pid) { p in
                        HStack(spacing: 6) {
                            Text("\(p.pid)").monospacedDigit().foregroundStyle(.secondary)
                            Text(p.name)
                            Text(p.kind.label).font(.caption2).foregroundStyle(.tertiary)
                        }
                        .font(.caption)
                    }
                }
            }
            if !footprint.ports.isEmpty {
                HStack(spacing: 4) {
                    Text("Ports").font(.subheadline.weight(.semibold))
                    Text(footprint.ports.map(String.init).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                }
            }
            if footprint.worktrees.isEmpty, footprint.processes.isEmpty, footprint.ports.isEmpty {
                Text("No worktrees, live processes, or listening ports right now.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// The grouped entries table: one `Section` per `EntryKind`, sorted rows
/// inside carry the label, bytes, evidence tier, and stale/clone/virtual/
/// unsized badges.
private struct EntryGroupedTable: View {
    let store: AuditStore
    let axis: AttributionAxis
    let groups: [FootprintGroup]

    private var browser: OwnerBrowser? {
        store.owners[axis]
    }

    private var allEntries: [FootprintEntry] {
        groups.flatMap(\.entries)
    }

    private var selection: Binding<String?> {
        Binding(
            get: { browser?.selectedEntry?.path },
            set: { path in browser?.selectedEntry = allEntries.first { $0.path == path } }
        )
    }

    var body: some View {
        Table(of: FootprintEntry.self, selection: selection) {
            TableColumn("Label") { e in
                Text(e.label).lineLimit(1)
            }
            .width(min: 160, ideal: 260)
            TableColumn("Bytes") { e in
                Text(Formatting.bytes(e.bytes)).monospacedDigit()
            }
            .width(min: 70, ideal: 90)
            TableColumn("Tier") { e in
                Text(e.tier.label).font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 110)
            TableColumn("Flags") { e in
                HStack(spacing: 4) {
                    ForEach(e.flags, id: \.label) { flag in
                        FlagCapsule(label: flag.label, color: Color(flag.tint), help: flag.help)
                    }
                }
            }
            .width(min: 90, ideal: 140)
            TableColumn("Path") { e in
                Text(PathDisplay.abbreviateHome(e.path)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        } rows: {
            ForEach(groups, id: \.kind) { group in
                Section("\(group.kind.label) · \(Formatting.bytes(group.bytes))") {
                    ForEach(group.entries.sorted { $0.bytes > $1.bytes }) { entry in
                        TableRow(entry)
                    }
                }
            }
        }
        .contextMenu(forSelectionType: String.self) { paths in
            if let path = paths.first, let entry = allEntries.first(where: { $0.path == path }) {
                Button("Browse in Folders") { store.browse(path: entry.path) }
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: entry.path)])
                }
            }
        }
    }
}

/// Squarified treemap of one owner's entries, coloured by `EntryKind`. Leaf
/// cells only — entries don't nest further. Layout-only: `TreemapCanvas`
/// owns drawing, hit-testing, and the hover tooltip.
private struct EntryTreemap: View {
    let store: AuditStore
    let axis: AttributionAxis
    let groups: [FootprintGroup]
    @State private var cells: [TreemapCell] = []
    @State private var byPath: [String: FootprintEntry] = [:]

    private var browser: OwnerBrowser? {
        store.owners[axis]
    }

    private var entries: [FootprintEntry] {
        groups.flatMap(\.entries)
    }

    var body: some View {
        GeometryReader { geo in
            TreemapCanvas(
                cells: cells,
                selected: browser?.selectedEntry?.path,
                onSelect: { cell in
                    browser?.selectedEntry = byPath[cell.id]
                }
            )
            .task(id: EntrySceneRequest(size: geo.size, groups: groups)) {
                cells = []
                byPath = [:]
                let groups = groups
                let size = geo.size
                let result = await Task.detached { Self.layout(groups: groups, size: size) }.value
                guard !Task.isCancelled else { return }
                cells = result.0
                byPath = result.1
            }
        }
    }

    private nonisolated static func layout(groups: [FootprintGroup], size: CGSize) -> ([TreemapCell], [String: FootprintEntry]) {
        let entries = groups.flatMap(\.entries).sorted { $0.bytes > $1.bytes }
        let byPath = Dictionary(entries.prefix(2047).map { ($0.path, $0) }, uniquingKeysWith: { first, _ in first })
        var items = byPath.values.map { Squarify.Item(id: $0.path, value: Double($0.bytes)) }
        let represented = byPath.values.reduce(UInt64(0)) { $0 + $1.bytes }
        let total = groups.reduce(UInt64(0)) { $0 + $1.bytes }
        let residual = Double(total > represented ? total - represented : 0)
        if residual > 0 {
            items.append(Squarify.Item(id: "Other entries", value: residual))
        }
        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: 2, dy: 2)
        let cells = Squarify.layout(items, in: bounds).map { cell in
            let entry = byPath[cell.id]
            return TreemapCell(id: cell.id, title: entry?.label ?? "Other entries", bytes: entry?.bytes ?? UInt64(residual),
                               rect: cell.rect, depth: 0, fill: Palette.color(forKindLabel: entry?.kind.label ?? "Other").opacity(0.4))
        }
        return (cells, byPath)
    }
}

private struct EntrySceneRequest: Equatable {
    let size: CGSize
    let groups: [FootprintGroup]
}
