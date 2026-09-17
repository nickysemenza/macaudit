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

    private var browser: OwnerBrowser? { store.owners[axis] }

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
                        store.rescan(axis == .projects ? .projects : .appStorage)
                    } label: {
                        Label("Rescan", systemImage: "arrow.clockwise")
                    }
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
                        ApfsCloneNote(store: store, compact: false)
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
                EntryGroupedTable(store: store, axis: axis, groups: footprint.groups)
                    .frame(maxHeight: .infinity)
            case .treemap:
                EntryTreemap(store: store, axis: axis, groups: footprint.groups)
                    .frame(maxHeight: .infinity)
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
                Text("This owner hasn't been resolved by a scan yet. Rescan \(axis == .projects ? "Projects" : "Apps") to try again.")
            } actions: {
                Button("Rescan") { store.rescan(axis == .projects ? .projects : .appStorage) }
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

            Button(axis == .projects ? "Projects" : "Apps") {
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

            Picker("", selection: Binding(get: { browser.viewMode }, set: { browser.viewMode = $0 })) {
                Image(systemName: "list.bullet").tag(OwnerBrowser.ViewMode.list)
                Image(systemName: "square.grid.2x2").tag(OwnerBrowser.ViewMode.treemap)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.small)
            .fixedSize()

            if browser.isLoading {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

/// Exclusive / Shared / Reach / Baseline share, each with a one-line
/// definition in `.help` (the four numbers §1 of the plan defines).
private struct StatTiles: View {
    let footprint: Footprint

    private var tiles: [(String, UInt64, String)] {
        [
            ("Exclusive", footprint.exclusive, "Bytes only this owner touches — not shared, not baseline."),
            ("Shared", footprint.shared, "This owner's slice of bytes multiple owners touch together."),
            ("Reach", footprint.reach, "Everything this owner touches, exclusive + shared + baseline share."),
            ("Baseline share", footprint.baselineShare, "This owner's slice of ecosystem-wide resources shared by everyone."),
        ]
    }

    var body: some View {
        HStack(spacing: 12) {
            ForEach(tiles, id: \.0) { title, bytes, definition in
                VStack(alignment: .leading, spacing: 2) {
                    Text(title.uppercased()).font(.caption2).foregroundStyle(.secondary)
                    Text(Formatting.bytes(bytes)).font(.title3.weight(.semibold)).monospacedDigit()
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 10))
                .help(definition)
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
                BarRow(name: $0.kind.label, parts: [(label: $0.kind.label, value: Double($0.bytes))], color: Palette.color(for: $0.kind))
            },
            title: "By kind",
            format: { Formatting.bytes(UInt64(max(0, $0))) },
            selected: $selected)
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
            if footprint.worktrees.isEmpty && footprint.processes.isEmpty && footprint.ports.isEmpty {
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

    private var browser: OwnerBrowser? { store.owners[axis] }
    private var allEntries: [FootprintEntry] { groups.flatMap(\.entries) }

    private var selection: Binding<String?> {
        Binding(
            get: { browser?.selectedEntry?.path },
            set: { path in browser?.selectedEntry = allEntries.first { $0.path == path } })
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
                EntryBadges(entry: e)
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

/// Small inline flag capsules — same idea as `SeverityBadge` but for an
/// entry's boolean flags, several of which can be true at once.
private struct EntryBadges: View {
    let entry: FootprintEntry

    var body: some View {
        let flags: [(String, Color)] = [
            entry.stale ? ("stale", .orange) : nil,
            entry.cloneOfStore ? ("clone", .blue) : nil,
            entry.virtualBytes ? ("virtual", .purple) : nil,
            entry.unsized ? ("unsized", .gray) : nil,
        ].compactMap { $0 }
        HStack(spacing: 4) {
            ForEach(flags, id: \.0) { label, color in
                Text(label)
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(color.opacity(0.15), in: Capsule())
                    .foregroundStyle(color)
            }
        }
    }
}

/// Squarified treemap of one owner's entries, coloured by `EntryKind`. Leaf
/// cells only — entries don't nest further.
private struct EntryTreemap: View {
    let store: AuditStore
    let axis: AttributionAxis
    let groups: [FootprintGroup]

    private var browser: OwnerBrowser? { store.owners[axis] }
    private var entries: [FootprintEntry] { groups.flatMap(\.entries) }

    @State private var hover: CGPoint?

    var body: some View {
        GeometryReader { geo in
            let bounds = CGRect(origin: .zero, size: geo.size).insetBy(dx: 2, dy: 2)
            let items = entries.map { Squarify.Item(id: $0.path, value: Double($0.bytes)) }
            let cells = Squarify.layout(items, in: bounds)
            let byPath = Dictionary(uniqueKeysWithValues: entries.map { ($0.path, $0) })

            Canvas { ctx, _ in
                for cell in cells {
                    guard let entry = byPath[cell.id] else { continue }
                    let path = Path(cell.rect)
                    ctx.fill(path, with: .color(Palette.color(for: entry.kind).opacity(0.4)))
                    ctx.stroke(path, with: .color(Color(nsColor: .windowBackgroundColor)), lineWidth: 1)
                    if browser?.selectedEntry?.path == entry.path {
                        ctx.stroke(path, with: .color(.accentColor), lineWidth: 2)
                    }
                    guard cell.rect.width > 48, cell.rect.height > 16 else { continue }
                    let text = ctx.resolve(Text(entry.label).font(.caption2))
                    ctx.drawLayer { layer in
                        layer.clip(to: Path(cell.rect))
                        layer.draw(text, at: CGPoint(x: cell.rect.minX + 4, y: cell.rect.minY + 2), anchor: .topLeading)
                    }
                }
            }
            .contentShape(Rectangle())
            .onContinuousHover { phase in
                switch phase {
                case .active(let location): hover = location
                case .ended: hover = nil
                }
            }
            .onTapGesture { point in
                guard let cell = cells.last(where: { $0.rect.contains(point) }), let entry = byPath[cell.id]
                else { return }
                browser?.selectedEntry = entry
            }
            .overlay(alignment: .topLeading) {
                if let point = hover, let cell = cells.last(where: { $0.rect.contains(point) }),
                    let entry = byPath[cell.id]
                {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.label).font(.caption).fontWeight(.semibold).lineLimit(1)
                        Text(Formatting.bytes(entry.bytes)).font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(6)
                    .background(Color(nsColor: .windowBackgroundColor).opacity(0.9), in: RoundedRectangle(cornerRadius: 6))
                    .shadow(radius: 2)
                    .fixedSize()
                    .position(x: min(point.x + 80, geo.size.width - 80), y: min(point.y + 30, geo.size.height - 20))
                }
            }
        }
    }
}
