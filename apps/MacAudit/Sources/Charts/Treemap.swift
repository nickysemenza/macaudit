import AppKit
import Foundation
import MacAuditKit
import SwiftUI

/// A squarified treemap for the Folders drill-down: the current directory's
/// children (top level) plus one nested level of grandchildren, with the
/// current directory's own loose files drawn as leaves alongside its
/// subfolders. Fills whatever space it is given (`GeometryReader` + `Canvas`,
/// no data-driven `.frame` — see `ColumnSizing.swift`). Stored properties
/// only, no `@Environment` reads, matching `FolderBrowserView`'s table cells.
struct TreemapView: View {
    let browser: DirBrowser
    let store: AuditStore
    let engine: any MacAuditEngine

    /// One drawn/hit-testable cell. `depth` 0 is a direct child of the
    /// current directory (or one of its loose files); `depth` 1 is a
    /// grandchild nested inside a depth-0 directory cell.
    struct Placed {
        let id: String
        let path: String
        let name: String
        let alloc: UInt64
        let rect: CGRect
        let depth: Int
        let isFile: Bool
    }

    /// Grandchildren keyed by their immediate parent's path, fetched two
    /// levels deep from the current directory. Refetched whenever the
    /// current directory changes.
    @State private var nested: [String: [DirEntry]] = [:]
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
            // Location-aware taps (macOS 14+): the click point comes with the
            // gesture, so this works without a preceding hover. Declared
            // before the single-tap gesture so a double click wins the race
            // instead of firing both a select and a navigate.
            .onTapGesture(count: 2) { point in
                guard let hit = placed.last(where: { $0.rect.contains(point) }), !hit.isFile
                else { return }
                browser.navigate(to: hit.path)
            }
            .onTapGesture(count: 1) { point in
                guard let hit = placed.last(where: { $0.rect.contains(point) }), !hit.isFile
                else { return }
                browser.selectedPath = hit.path
            }
            .overlay(alignment: .topLeading) {
                if let point = hover, let hit = placed.last(where: { $0.rect.contains(point) }) {
                    tooltip(for: hit)
                        .position(tooltipCenter(for: point, in: geo.size))
                }
            }
        }
        .task(id: browser.current?.path) {
            await loadNested()
        }
    }

    // MARK: - Layout

    /// Pure geometry, independent of drawing: called from the `Canvas`
    /// closure and from the tap/hover handlers so both agree on where every
    /// cell is. Never mutates state.
    private func layout(size: CGSize) -> [Placed] {
        guard let current = browser.current, size.width > 0, size.height > 0 else { return [] }

        struct Source {
            let path: String
            let name: String
            let alloc: UInt64
            let isFile: Bool
            let hasChildren: Bool
        }

        var sources: [String: Source] = [:]
        var items: [Squarify.Item] = []
        for entry in browser.entries {
            sources[entry.path] = Source(
                path: entry.path, name: entry.name, alloc: entry.alloc,
                isFile: false, hasChildren: entry.hasChildren)
            items.append(Squarify.Item(id: entry.path, value: Double(entry.alloc)))
        }
        for file in current.topFiles {
            let id = "file:\(file.path)"
            sources[id] = Source(
                path: file.path, name: (file.path as NSString).lastPathComponent,
                alloc: file.alloc, isFile: true, hasChildren: false)
            items.append(Squarify.Item(id: id, value: Double(file.alloc)))
        }

        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: 2, dy: 2)
        var placed: [Placed] = []
        for cell in Squarify.layout(items, in: bounds) {
            guard let source = sources[cell.id] else { continue }
            placed.append(
                Placed(
                    id: cell.id, path: source.path, name: source.name, alloc: source.alloc,
                    rect: cell.rect, depth: 0, isFile: source.isFile))

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
                placed.append(
                    Placed(
                        id: child.path, path: child.path, name: child.name, alloc: child.alloc,
                        rect: childCell.rect, depth: 1, isFile: false))
            }
        }
        return placed
    }

    // MARK: - Drawing

    private func draw(_ placed: [Placed], into ctx: inout GraphicsContext) {
        let separator = Color(nsColor: .windowBackgroundColor)
        for p in placed {
            let path = Path(p.rect)
            let fill: Color
            if p.isFile {
                fill = Color.secondary.opacity(0.3)
            } else if p.depth == 0 {
                fill = Palette.color(for: p.name).opacity(0.35)
            } else {
                fill = Palette.color(for: p.name).opacity(0.55)
            }
            ctx.fill(path, with: .color(fill))
            ctx.stroke(path, with: .color(separator), lineWidth: 1)

            if p.path == browser.selectedPath {
                ctx.stroke(path, with: .color(.accentColor), lineWidth: 2)
            }

            guard p.rect.width > 48, p.rect.height > 16 else { continue }
            let font: Font = p.depth == 0 ? .caption : .caption2
            let nameText = ctx.resolve(Text(p.name).font(font))
            ctx.drawLayer { layer in
                layer.clip(to: Path(p.rect))
                layer.draw(
                    nameText, at: CGPoint(x: p.rect.minX + 4, y: p.rect.minY + 2), anchor: .topLeading)
            }

            if p.rect.height > 32 {
                let bytesText = ctx.resolve(
                    Text(Formatting.bytes(p.alloc)).font(.caption2).foregroundStyle(.secondary))
                ctx.drawLayer { layer in
                    layer.clip(to: Path(p.rect))
                    layer.draw(
                        bytesText, at: CGPoint(x: p.rect.minX + 4, y: p.rect.minY + 18),
                        anchor: .topLeading)
                }
            }
        }
    }

    // MARK: - Tooltip

    @ViewBuilder
    private func tooltip(for placed: Placed) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(placed.name).font(.caption).fontWeight(.semibold).lineLimit(1)
            Text(Formatting.bytes(placed.alloc)).font(.caption2).foregroundStyle(.secondary)
            if let current = browser.current {
                Text(Formatting.share(placed.alloc, of: current.alloc))
                    .font(.caption2).foregroundStyle(.secondary)
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

    // MARK: - Data

    /// Refetches the current directory's grandchildren, two levels deep,
    /// off-main — same pattern as `DirBrowser.navigate`'s child load.
    private func loadNested() async {
        guard let path = browser.current?.path else {
            nested = [:]
            return
        }
        let engine = self.engine
        let flat = await Task.detached { engine.dirSubtree(path: path, depth: 2, maxNodes: 400) }.value
        // The current directory may have changed while this awaited; drop a
        // stale result rather than attributing it to the wrong parent.
        guard path == browser.current?.path else { return }

        var grouped: [String: [DirEntry]] = [:]
        for entry in flat where entry.path != path {
            let parentPath = (entry.path as NSString).deletingLastPathComponent
            grouped[parentPath, default: []].append(entry)
        }
        nested = grouped
    }
}
