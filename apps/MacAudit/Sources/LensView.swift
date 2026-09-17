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

    private var sectionId: SectionId { axis == .projects ? .projects : .appStorage }

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
                Text(axis == .projects ? "Projects" : "Apps").font(.headline)
                Spacer()
                if let browser {
                    Picker(
                        "", selection: Binding(get: { browser.viewMode }, set: { browser.viewMode = $0 })
                    ) {
                        Image(systemName: "list.bullet").tag(OwnerBrowser.ViewMode.list)
                        Image(systemName: "square.grid.2x2").tag(OwnerBrowser.ViewMode.treemap)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .controlSize(.small)
                    .fixedSize()
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
            TableColumn("Name", value: \.summary.ownerKey) { row in
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
        .contextMenu(forSelectionType: UInt64.self) { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                LensRowContextMenu(store: store, axis: .projects, row: row)
            }
        } primaryAction: { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                store.owners[.projects]?.open(row.finding)
            }
        }
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
            TableColumn("Name", value: \.summary.ownerKey) { row in
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
            TableColumn("Kind", value: \.ownerKindLabel) { row in
                Text(row.summary.ownerKind?.label ?? "–").foregroundStyle(.secondary)
            }
            .width(90)
        }
        .contextMenu(forSelectionType: UInt64.self) { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                LensRowContextMenu(store: store, axis: .appStorage, row: row)
            }
        } primaryAction: { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                store.owners[.appStorage]?.open(row.finding)
            }
        }
    }
}

extension LensModel.Row {
    fileprivate var worktreeCount: Int { summary.worktrees.count }
    fileprivate var processCount: Int { summary.processCount }
    fileprivate var portCount: Int { summary.ports.count }
    fileprivate var ownerKindLabel: String { summary.ownerKind?.label ?? "" }
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
/// level inside its cell. Drawing approach mirrors `TreemapView`.
private struct LensTreemap: View {
    let store: AuditStore
    let axis: AttributionAxis
    let rows: [LensModel.Row]
    let buckets: FootprintBuckets?

    struct Placed {
        let id: String
        let title: String
        let bytes: UInt64
        let rect: CGRect
        let depth: Int
        let isBaseline: Bool
        let row: LensModel.Row?
    }

    @State private var hover: CGPoint?

    var body: some View {
        GeometryReader { geo in
            let placed = layout(size: geo.size)
            Canvas { ctx, _ in
                draw(placed, into: &ctx)
            }
            .contentShape(Rectangle())
            .onContinuousHover { phase in
                switch phase {
                case .active(let location): hover = location
                case .ended: hover = nil
                }
            }
            .onTapGesture(count: 2) { point in
                guard let hit = placed.last(where: { $0.rect.contains(point) }), hit.depth == 0,
                    let row = hit.row
                else { return }
                store.owners[axis]?.open(row.finding)
            }
            .onTapGesture(count: 1) { point in
                guard let hit = placed.last(where: { $0.rect.contains(point) }), hit.depth == 0
                else { return }
                store.selectedFinding = hit.row?.finding.id
            }
            .overlay(alignment: .topLeading) {
                if let point = hover, let hit = placed.last(where: { $0.rect.contains(point) }) {
                    tooltip(for: hit).position(tooltipCenter(for: point, in: geo.size))
                }
            }
        }
    }

    // MARK: - Layout

    private func layout(size: CGSize) -> [Placed] {
        guard size.width > 0, size.height > 0 else { return [] }
        let items = LensModel.treemapItems(rows, buckets: buckets)
        let rowById = Dictionary(uniqueKeysWithValues: rows.map { (LensModel.treemapOwnerId($0), $0) })
        let itemValueById = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0.value) })

        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: 2, dy: 2)
        var placed: [Placed] = []
        for cell in Squarify.layout(items, in: bounds) {
            let isBaseline = cell.id == LensModel.treemapBaselineId
            let row = rowById[cell.id]
            let title = isBaseline ? "Baseline" : (row?.finding.title ?? cell.id)
            let bytes = UInt64(itemValueById[cell.id] ?? 0)
            placed.append(
                Placed(id: cell.id, title: title, bytes: bytes, rect: cell.rect, depth: 0, isBaseline: isBaseline, row: row))

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
                placed.append(
                    Placed(id: kindCell.id, title: k.label, bytes: k.bytes, rect: kindCell.rect, depth: 1, isBaseline: false, row: row))
            }
        }
        return placed
    }

    // MARK: - Drawing

    private func draw(_ placed: [Placed], into ctx: inout GraphicsContext) {
        let separator = Color(nsColor: .windowBackgroundColor)
        for p in placed {
            let path = Path(p.rect)
            let fill: Color =
                if p.isBaseline {
                    .gray.opacity(0.35)
                } else if p.depth == 0 {
                    Palette.color(for: p.title).opacity(0.35)
                } else {
                    Palette.color(for: p.title).opacity(0.55)
                }
            ctx.fill(path, with: .color(fill))
            ctx.stroke(path, with: .color(separator), lineWidth: 1)

            guard p.rect.width > 48, p.rect.height > 16 else { continue }
            let font: Font = p.depth == 0 ? .caption : .caption2
            let nameText = ctx.resolve(Text(p.title).font(font))
            ctx.drawLayer { layer in
                layer.clip(to: Path(p.rect))
                layer.draw(nameText, at: CGPoint(x: p.rect.minX + 4, y: p.rect.minY + 2), anchor: .topLeading)
            }
            if p.rect.height > 32 {
                let bytesText = ctx.resolve(
                    Text(Formatting.bytes(p.bytes)).font(.caption2).foregroundStyle(.secondary))
                ctx.drawLayer { layer in
                    layer.clip(to: Path(p.rect))
                    layer.draw(bytesText, at: CGPoint(x: p.rect.minX + 4, y: p.rect.minY + 18), anchor: .topLeading)
                }
            }
        }
    }

    // MARK: - Tooltip

    @ViewBuilder
    private func tooltip(for p: Placed) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(p.title).font(.caption).fontWeight(.semibold).lineLimit(1)
            Text(Formatting.bytes(p.bytes)).font(.caption2).foregroundStyle(.secondary)
        }
        .padding(6)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.9), in: RoundedRectangle(cornerRadius: 6))
        .shadow(radius: 2)
        .fixedSize()
    }

    private func tooltipCenter(for point: CGPoint, in bounds: CGSize) -> CGPoint {
        let estimated = CGSize(width: 160, height: 56)
        var origin = CGPoint(x: point.x + 12, y: point.y + 12)
        if origin.x + estimated.width > bounds.width {
            origin.x = point.x - estimated.width - 12
        }
        if origin.y + estimated.height > bounds.height {
            origin.y = point.y - estimated.height - 12
        }
        origin.x = max(estimated.width / 2, origin.x)
        origin.y = max(estimated.height / 2, origin.y)
        return CGPoint(x: origin.x + estimated.width / 2, y: origin.y + estimated.height / 2)
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
        Button("Rescan \(axis == .projects ? "Projects" : "Apps")") {
            store.rescan(axis == .projects ? .projects : .appStorage)
        }
    }
}
