import AppKit
import Foundation
import MacAuditKit
import SwiftUI

/// One drawn/hit-testable treemap cell, generic across every treemap in the
/// app (the Folders drill-down, the Projects/Apps lens, one owner's
/// entries): each caller owns its own layout (squarify + nesting rules
/// differ) and coloring (domain-specific palette), and only hands
/// `TreemapCanvas` what it needs to draw and hit-test.
struct TreemapCell: Identifiable {
    let id: String
    let title: String
    let bytes: UInt64
    let rect: CGRect
    let depth: Int
    let fill: Color
    /// An optional third tooltip line under the name/bytes — only the
    /// Folders treemap uses this (share of the current directory).
    var subtitle: String?

    init(id: String, title: String, bytes: UInt64, rect: CGRect, depth: Int, fill: Color, subtitle: String? = nil) {
        self.id = id
        self.title = title
        self.bytes = bytes
        self.rect = rect
        self.depth = depth
        self.fill = fill
        self.subtitle = subtitle
    }
}

/// Draws squarified `cells` with name/byte labels, a hover tooltip, and
/// single/double-click hit-testing — the shared drawing engine behind the
/// Folders drill-down (`TreemapView`), the Projects/Apps lens
/// (`LensTreemap`), and one owner's entries (`EntryTreemap`). Callers supply
/// already-laid-out cells (their own `Squarify.layout` + nesting) and react
/// to hits via `onSelect`/`onOpen`, which hand back the whole matched cell so
/// the caller can map its `id` back to its own domain object.
struct TreemapCanvas: View {
    let cells: [TreemapCell]
    /// The currently selected cell's `id`, drawn with an accent border.
    /// `nil` (or an id no cell carries) draws no highlight — callers that
    /// don't track a treemap-level selection just pass `nil`.
    let selected: String?
    var onSelect: (TreemapCell) -> Void
    /// Double-click handler. `nil` disables the double-tap gesture entirely
    /// (rather than attaching a no-op one), matching each caller's own
    /// interaction: a `nil` double-tap gesture never competes with the
    /// single-tap one, so callers without an "open" action keep every rapid
    /// click selecting.
    var onOpen: ((TreemapCell) -> Void)?

    @State private var hover: CGPoint?

    var body: some View {
        GeometryReader { geo in
            withOpenGesture(
                Canvas { ctx, _ in
                    draw(into: &ctx)
                }
                .contentShape(Rectangle())
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let location): hover = location
                    case .ended: hover = nil
                    }
                }
            )
            // Location-aware taps (macOS 14+): the click point comes with the
            // gesture, so this works without a preceding hover. The optional
            // double-tap gesture above is declared first so a double click
            // wins the race instead of firing both a select and an open.
            .onTapGesture(count: 1) { point in
                guard let hit = cells.last(where: { $0.rect.contains(point) }) else { return }
                onSelect(hit)
            }
            .overlay(alignment: .topLeading) {
                if let point = hover, let hit = cells.last(where: { $0.rect.contains(point) }) {
                    tooltip(for: hit).position(tooltipCenter(for: point, in: geo.size))
                }
            }
        }
    }

    @ViewBuilder
    private func withOpenGesture<V: View>(_ view: V) -> some View {
        if let onOpen {
            view.onTapGesture(count: 2) { point in
                guard let hit = cells.last(where: { $0.rect.contains(point) }) else { return }
                onOpen(hit)
            }
        } else {
            view
        }
    }

    // MARK: - Drawing

    private func draw(into ctx: inout GraphicsContext) {
        let separator = Color(nsColor: .windowBackgroundColor)
        for cell in cells {
            let path = Path(cell.rect)
            ctx.fill(path, with: .color(cell.fill))
            ctx.stroke(path, with: .color(separator), lineWidth: 1)

            if let selected, cell.id == selected {
                ctx.stroke(path, with: .color(.accentColor), lineWidth: 2)
            }

            guard cell.rect.width > 48, cell.rect.height > 16 else { continue }
            let font: Font = cell.depth == 0 ? .caption : .caption2
            let nameText = ctx.resolve(Text(cell.title).font(font))
            ctx.drawLayer { layer in
                layer.clip(to: Path(cell.rect))
                layer.draw(
                    nameText, at: CGPoint(x: cell.rect.minX + 4, y: cell.rect.minY + 2), anchor: .topLeading)
            }

            if cell.rect.height > 32 {
                let bytesText = ctx.resolve(
                    Text(Formatting.bytes(cell.bytes)).font(.caption2).foregroundStyle(.secondary))
                ctx.drawLayer { layer in
                    layer.clip(to: Path(cell.rect))
                    layer.draw(
                        bytesText, at: CGPoint(x: cell.rect.minX + 4, y: cell.rect.minY + 18),
                        anchor: .topLeading)
                }
            }
        }
    }

    // MARK: - Tooltip

    @ViewBuilder
    private func tooltip(for cell: TreemapCell) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(cell.title).font(.caption).fontWeight(.semibold).lineLimit(1)
            Text(Formatting.bytes(cell.bytes)).font(.caption2).foregroundStyle(.secondary)
            if let subtitle = cell.subtitle {
                Text(subtitle).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(6)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.9), in: RoundedRectangle(cornerRadius: 6))
        .shadow(radius: 2)
        .fixedSize()
    }

    /// A `.position(...)` centre for the tooltip near `point`, nudged so an
    /// (estimated) tooltip footprint stays inside `bounds`.
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

/// A squarified treemap for the Folders drill-down: the current directory's
/// children (top level) plus one nested level of grandchildren, with the
/// current directory's own loose files drawn as leaves alongside its
/// subfolders. Fills whatever space it is given (`GeometryReader` +
/// `TreemapCanvas`, no data-driven `.frame` — see `ColumnSizing.swift`).
/// Stored properties only, no `@Environment` reads, matching
/// `FolderBrowserView`'s table cells. Layout-only: `TreemapCanvas` owns
/// drawing, hit-testing, and the hover tooltip.
struct TreemapView: View {
    let browser: DirBrowser
    let store: AuditStore
    let engine: any MacAuditEngine

    /// One depth-0 (direct child, or a loose file) or depth-1 (grandchild
    /// nested inside a depth-0 directory cell) source item, keyed by the
    /// squarify cell id that identifies it (see `layout(size:)`).
    private struct Source {
        let path: String
        let name: String
        let alloc: UInt64
        let isFile: Bool
        let hasChildren: Bool
    }

    /// Grandchildren keyed by their immediate parent's path, fetched two
    /// levels deep from the current directory. Refetched whenever the
    /// current directory changes.
    @State private var nested: [String: [DirEntry]] = [:]
    /// The current directory's own largest loose files, fetched live
    /// alongside `nested` (directories no longer carry a per-node file list).
    @State private var topFiles: [TopFile] = []

    var body: some View {
        GeometryReader { geo in
            let (cells, sources) = layout(size: geo.size)
            TreemapCanvas(
                cells: cells,
                selected: browser.selectedPath,
                onSelect: { cell in
                    guard let source = sources[cell.id], !source.isFile else { return }
                    browser.selectedPath = source.path
                },
                onOpen: { cell in
                    guard let source = sources[cell.id], !source.isFile else { return }
                    browser.navigate(to: source.path)
                })
        }
        .task(id: browser.current?.path) {
            await loadNested()
        }
    }

    // MARK: - Layout

    /// Pure geometry + coloring, independent of drawing: called from the
    /// body so the canvas and the tap/hover handlers it hosts all agree on
    /// where every cell is. Never mutates state. Returns the cells alongside
    /// the `Source` each cell's id resolves to, so `onSelect`/`onOpen` can
    /// recover the real filesystem path (and whether it's a file).
    private func layout(size: CGSize) -> ([TreemapCell], [String: Source]) {
        guard let current = browser.current, size.width > 0, size.height > 0 else { return ([], [:]) }

        var sources: [String: Source] = [:]
        var items: [Squarify.Item] = []
        for entry in browser.entries {
            sources[entry.path] = Source(
                path: entry.path, name: entry.name, alloc: entry.alloc,
                isFile: false, hasChildren: entry.hasChildren)
            items.append(Squarify.Item(id: entry.path, value: Double(entry.alloc)))
        }
        for file in topFiles {
            let id = "file:\(file.path)"
            sources[id] = Source(
                path: file.path, name: (file.path as NSString).lastPathComponent,
                alloc: file.alloc, isFile: true, hasChildren: false)
            items.append(Squarify.Item(id: id, value: Double(file.alloc)))
        }

        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: 2, dy: 2)
        var cells: [TreemapCell] = []
        for cell in Squarify.layout(items, in: bounds) {
            guard let source = sources[cell.id] else { continue }
            cells.append(makeCell(id: cell.id, source: source, rect: cell.rect, depth: 0, current: current))

            guard !source.isFile, source.hasChildren,
                let children = nested[source.path], !children.isEmpty,
                cell.rect.width >= 60, cell.rect.height >= 40
            else { continue }

            let inner = cell.rect.insetBy(dx: 3, dy: 3)
            let content = CGRect(
                x: inner.minX, y: inner.minY + 16, width: inner.width, height: inner.height - 16)
            guard content.width > 0, content.height > 0 else { continue }

            let childItems = children.map { Squarify.Item(id: $0.path, value: Double($0.alloc)) }
            let childByPath = Dictionary(uniqueKeysWithValues: children.map { ($0.path, $0) })
            for childCell in Squarify.layout(childItems, in: content) {
                guard let child = childByPath[childCell.id] else { continue }
                let childSource = Source(
                    path: child.path, name: child.name, alloc: child.alloc,
                    isFile: false, hasChildren: child.hasChildren)
                sources[childCell.id] = childSource
                cells.append(
                    makeCell(id: childCell.id, source: childSource, rect: childCell.rect, depth: 1, current: current))
            }
        }
        return (cells, sources)
    }

    private func makeCell(id: String, source: Source, rect: CGRect, depth: Int, current: DirEntry) -> TreemapCell {
        let fill: Color =
            if source.isFile {
                .secondary.opacity(0.3)
            } else if depth == 0 {
                Palette.color(for: source.name).opacity(0.35)
            } else {
                Palette.color(for: source.name).opacity(0.55)
            }
        return TreemapCell(
            id: id, title: source.name, bytes: source.alloc, rect: rect, depth: depth, fill: fill,
            subtitle: Formatting.share(source.alloc, of: current.alloc))
    }

    // MARK: - Data

    /// Refetches the current directory's grandchildren (two levels deep) and
    /// its own largest loose files, off-main — same pattern as
    /// `DirBrowser.navigate`'s child load. Fetched together so both land (or
    /// are both dropped as stale) from the same snapshot of `path`.
    private func loadNested() async {
        guard let path = browser.current?.path else {
            nested = [:]
            topFiles = []
            return
        }
        let engine = self.engine
        let (flat, files) = await Task.detached {
            (
                engine.dirSubtree(path: path, depth: 2, maxNodes: 400),
                engine.dirTopFiles(path: path, n: 5)
            )
        }.value
        // The current directory may have changed while this awaited; drop a
        // stale result rather than attributing it to the wrong parent.
        guard path == browser.current?.path else { return }

        var grouped: [String: [DirEntry]] = [:]
        for entry in flat where entry.path != path {
            let parentPath = (entry.path as NSString).deletingLastPathComponent
            grouped[parentPath, default: []].append(entry)
        }
        nested = grouped
        topFiles = files
    }
}
