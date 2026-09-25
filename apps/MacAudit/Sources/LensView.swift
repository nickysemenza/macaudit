import AppKit
import MacAuditKit
import SwiftUI

/// The Projects/Apps lens landing page: a coverage header
/// (`SegmentedBar` over attributed/baseline/unattributed/rest-of-disk), then
/// either a ranked table or a treemap of owners. Once an owner is opened
/// (`store.owners[axis].selectedOwner`), `ContentView` swaps this out for
/// `OwnerDetailView` — this view only ever shows the landing page.
struct LensView: View {
    @Environment(AuditStore.self) private var store
    let axis: AttributionAxis

    private var sectionId: SectionId { axis.sectionId }

    var body: some View {
        let browser = store.owners[axis]
        let rows = LensModel.rows(store.findings(in: sectionId))
        VStack(spacing: 0) {
            LensHeaderCard(store: store, axis: axis, browser: browser)
                .padding([.horizontal, .top], 14)
            Divider().padding(.top, 10)
            if store.findings(in: sectionId).isEmpty {
                emptyState
            } else if let browser {
                switch browser.viewMode {
                case .list:
                    LensTable(store: store, axis: axis, rows: rows)
                case .treemap:
                    LensTreemap(store: store, axis: axis, rows: rows, buckets: browser.buckets)
                }
            }
        }
        .task { browser?.refreshBuckets() }
    }

    @ViewBuilder
    private var emptyState: some View {
        switch store.status(of: sectionId) {
        case .scanning(let msg, _, _):
            VStack(spacing: 12) {
                ProgressView()
                Text(msg.isEmpty ? "Scanning…" : msg).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let error):
            ContentUnavailableView {
                Label("Scan failed", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            } actions: {
                Button("Retry") { store.rescan(sectionId) }
            }
        case .idle:
            ContentUnavailableView {
                Label("Not scanned", systemImage: "magnifyingglass")
            } actions: {
                Button("Scan") { store.rescan(sectionId) }
            }
        case .done:
            ContentUnavailableView("Nothing found", systemImage: "checkmark.circle")
        }
    }
}

/// Coverage bar + list/treemap toggle. `store`/`browser` are stored
/// properties, matching `DirTable`/`BreadcrumbBar`'s convention.
private struct LensHeaderCard: View {
    let store: AuditStore
    let axis: AttributionAxis
    let browser: OwnerBrowser?

    var body: some View {
        Card {
            HStack(alignment: .firstTextBaseline) {
                Text(axis.title).font(.headline)
                Spacer()
                if let browser {
                    ViewModePicker(selection: Binding(get: { browser.viewMode }, set: { browser.viewMode = $0 }))
                }
            }
            if let coverage = LensModel.coverage(browser?.buckets) {
                SegmentedBar(
                    segments: [
                        BarSegment(name: "Attributed", bytes: coverage.attributed),
                        BarSegment(name: "Baseline", bytes: coverage.baseline),
                        BarSegment(name: "Unattributed", bytes: coverage.unattributed),
                    ],
                    capacity: coverage.diskTotal,
                    trailingLabel: coverage.restOfDisk > 0
                        ? "\(Formatting.bytes(coverage.restOfDisk)) rest of disk" : nil)
                Text(
                    "\(Formatting.bytes(coverage.attributed)) attributed · \(Formatting.bytes(coverage.baseline)) baseline · \(Formatting.bytes(coverage.unattributed)) unattributed"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                if !coverage.missingDeps.isEmpty {
                    Label(
                        "Not yet scanned, so this coverage is partial: \(coverage.missingDeps.map { store.meta(for: $0)?.title ?? $0.slug }.joined(separator: ", "))",
                        systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text(store.isScanning ? "Coverage fills in as the scan completes…" : "Coverage not available yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// The ranked owners table: name, stacked exclusive/shared/baseline bar,
/// byte columns, and axis-specific extras (Worktrees/Procs/Ports for
/// Projects, Kind for Apps).
///
/// Two fixed column sets rather than one `Table` with an `if axis == …`
/// inside the column builder: a conditional `TableColumn` needs macOS 14.4
/// (`_ConditionalContent`'s `TableColumnContent` conformance), and this
/// target's floor is 14.0 (`project.yml`).
private struct LensTable: View {
    let store: AuditStore
    let axis: AttributionAxis
    let rows: [LensModel.Row]

    var body: some View {
        switch axis {
        case .projects: ProjectsLensTable(store: store, rows: rows)
        case .appStorage: AppsLensTable(store: store, rows: rows)
        }
    }
}

private struct ProjectsLensTable: View {
    let store: AuditStore
    let rows: [LensModel.Row]
    @State private var sortOrder: [KeyPathComparator<LensModel.Row>] = [
        KeyPathComparator(\.summary.exclusive, order: .reverse)
    ]

    var body: some View {
        @Bindable var store = store
        Table(rows.sorted(using: sortOrder), selection: $store.selectedFinding, sortOrder: $sortOrder) {
            lensSharedColumns()
            TableColumn("Worktrees", value: \.worktreeCount) { row in
                Text("\(row.summary.worktrees.count)").foregroundStyle(.secondary)
            }
            .width(76)
            TableColumn("Procs", value: \.processCount) { row in
                Text("\(row.summary.processCount)").foregroundStyle(.secondary)
            }
            .width(56)
            TableColumn("Ports", value: \.portCount) { row in
                Text(row.summary.ports.isEmpty ? "–" : row.summary.ports.map(String.init).joined(separator: ", "))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 60, ideal: 110)
        }
        .lensRowActions(store: store, axis: .projects, rows: rows)
    }
}

private struct AppsLensTable: View {
    let store: AuditStore
    let rows: [LensModel.Row]
    @State private var sortOrder: [KeyPathComparator<LensModel.Row>] = [
        KeyPathComparator(\.summary.exclusive, order: .reverse)
    ]

    var body: some View {
        @Bindable var store = store
        Table(rows.sorted(using: sortOrder), selection: $store.selectedFinding, sortOrder: $sortOrder) {
            lensSharedColumns()
            TableColumn("Kind", value: \.ownerKindLabel) { row in
                Text(row.summary.ownerKind ?? "–").foregroundStyle(.secondary)
            }
            .width(90)
        }
        .lensRowActions(store: store, axis: .appStorage, rows: rows)
    }
}

/// The five columns every lens table shows (Name/Share/Exclusive/Shared/
/// Reach), shared by `ProjectsLensTable` and `AppsLensTable` — each of which
/// appends its own axis-specific columns after this. A `@TableColumnBuilder`
/// free function rather than one `Table` with an `if axis == …` inside the
/// column builder: this target's floor is macOS 14.0 (`project.yml`), and a
/// *conditional* `TableColumn` needs 14.4 (`_ConditionalContent`'s
/// `TableColumnContent` conformance) — a plain, unconditional group of
/// columns like this one has no such requirement.
@TableColumnBuilder<LensModel.Row, KeyPathComparator<LensModel.Row>>
private func lensSharedColumns() -> some TableColumnContent<LensModel.Row, KeyPathComparator<LensModel.Row>> {
    TableColumn("Name", value: \.finding.title) { row in
        Text(row.finding.title).lineLimit(1)
    }
    .width(min: 160, ideal: 240)
    TableColumn("Share") { row in OwnerBarCell(row: row) }
        .width(min: 130, ideal: 190)
    TableColumn("Exclusive", value: \.summary.exclusive) { row in
        Text(Formatting.bytes(row.summary.exclusive)).monospacedDigit()
    }
    .width(min: 70, ideal: 90)
    TableColumn("Shared", value: \.summary.shared) { row in
        Text(Formatting.bytes(row.summary.shared)).monospacedDigit().foregroundStyle(.secondary)
    }
    .width(min: 70, ideal: 90)
    TableColumn("Reach", value: \.summary.reach) { row in
        Text(Formatting.bytes(row.summary.reach)).monospacedDigit().foregroundStyle(.secondary)
    }
    .width(min: 70, ideal: 90)
}

extension View {
    /// The lens table's shared row context menu + primary (double-click/
    /// Return) open action — identical between the two tables apart from
    /// `axis`.
    fileprivate func lensRowActions(store: AuditStore, axis: AttributionAxis, rows: [LensModel.Row]) -> some View {
        contextMenu(forSelectionType: UInt64.self) { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                LensRowContextMenu(store: store, axis: axis, row: row)
            }
        } primaryAction: { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                store.owners[axis]?.open(row.finding)
            }
        }
    }
}

extension LensModel.Row {
    fileprivate var worktreeCount: Int { summary.worktrees.count }
    fileprivate var processCount: Int { summary.processCount }
    fileprivate var portCount: Int { summary.ports.count }
    fileprivate var ownerKindLabel: String { summary.ownerKind ?? "" }
}

/// A small stacked capsule bar: exclusive (solid accent), shared (faded
/// accent), baseline share (orange) — the fractions `LensModel.rows`
/// already scaled to the axis's largest `reach`. Same drawn-only-in-cell
/// discipline as `ShareBar` (`FolderBrowserView.swift`).
struct OwnerBarCell: View {
    let row: LensModel.Row

    var body: some View {
        GeometryReader { geo in
            HStack(spacing: 1) {
                Capsule().fill(Color.accentColor)
                    .frame(width: max(0, CGFloat(row.exclusiveFraction)) * geo.size.width)
                Capsule().fill(Color.accentColor.opacity(0.4))
                    .frame(width: max(0, CGFloat(row.sharedFraction)) * geo.size.width)
                Capsule().fill(Color.orange.opacity(0.55))
                    .frame(width: max(0, CGFloat(row.baselineFraction)) * geo.size.width)
                Spacer(minLength: 0)
            }
        }
        .frame(height: 10)
        .help(
            "\(Formatting.bytes(row.summary.exclusive)) exclusive · \(Formatting.bytes(row.summary.shared)) shared · \(Formatting.bytes(row.summary.baselineShare)) baseline share"
        )
    }
}

/// Squarified treemap of owners (area = exclusive + shared), with a
/// synthetic Baseline cell, and each owner's `by_kind` breakdown nested one
/// level inside its cell. Layout-only: `TreemapCanvas` owns drawing,
/// hit-testing, and the hover tooltip.
private struct LensTreemap: View {
    let store: AuditStore
    let axis: AttributionAxis
    let rows: [LensModel.Row]
    let buckets: FootprintBuckets?

    var body: some View {
        GeometryReader { geo in
            let (cells, rowById) = layout(size: geo.size)
            TreemapCanvas(
                cells: cells,
                // No treemap-level selection highlight here (never drawn
                // before this consolidation either) — only depth-0 owner
                // cells select/open, and they do so via `store.selectedFinding`.
                selected: nil,
                onSelect: { cell in
                    guard cell.depth == 0 else { return }
                    store.selectedFinding = rowById[cell.id]?.finding.id
                },
                onOpen: { cell in
                    guard cell.depth == 0, let row = rowById[cell.id] else { return }
                    store.owners[axis]?.open(row.finding)
                })
        }
    }

    // MARK: - Layout

    private func layout(size: CGSize) -> ([TreemapCell], [String: LensModel.Row]) {
        guard size.width > 0, size.height > 0 else { return ([], [:]) }
        let items = LensModel.treemapItems(rows, buckets: buckets)
        let rowById = Dictionary(uniqueKeysWithValues: rows.map { (LensModel.treemapOwnerId($0), $0) })
        let itemValueById = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0.value) })

        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: 2, dy: 2)
        var cells: [TreemapCell] = []
        for cell in Squarify.layout(items, in: bounds) {
            let isBaseline = cell.id == LensModel.treemapBaselineId
            let row = rowById[cell.id]
            let title = isBaseline ? "Baseline" : (row?.finding.title ?? cell.id)
            let bytes = UInt64(itemValueById[cell.id] ?? 0)
            let fill: Color =
                if isBaseline {
                    .gray.opacity(0.35)
                } else {
                    Palette.color(for: title).opacity(0.35)
                }
            cells.append(TreemapCell(id: cell.id, title: title, bytes: bytes, rect: cell.rect, depth: 0, fill: fill))

            guard let row, cell.rect.width >= 60, cell.rect.height >= 40 else { continue }
            let kindItems = LensModel.kindItems(row)
            guard !kindItems.isEmpty else { continue }
            let inner = cell.rect.insetBy(dx: 3, dy: 3)
            let content = CGRect(x: inner.minX, y: inner.minY + 16, width: inner.width, height: inner.height - 16)
            guard content.width > 0, content.height > 0 else { continue }
            let kindByCellId = Dictionary(
                uniqueKeysWithValues: kindItems.enumerated().map { i, item in (item.id, row.summary.byKind[i]) })
            for kindCell in Squarify.layout(kindItems, in: content) {
                guard let k = kindByCellId[kindCell.id] else { continue }
                cells.append(
                    TreemapCell(
                        id: kindCell.id, title: k.label, bytes: k.bytes, rect: kindCell.rect, depth: 1,
                        fill: Palette.color(for: k.label).opacity(0.55)))
            }
        }
        return (cells, rowById)
    }
}

/// Row context menu, mirroring `RowContextMenu` (`TableView.swift`).
private struct LensRowContextMenu: View {
    let store: AuditStore
    let axis: AttributionAxis
    let row: LensModel.Row

    var body: some View {
        Button("Open") { store.owners[axis]?.open(row.finding) }
        if let path = row.finding.path {
            Button("Browse in Folders") { store.browse(path: path) }
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            }
        }
        Divider()
        Button("Rescan \(axis.title)") {
            store.rescan(axis.sectionId)
        }
    }
}
