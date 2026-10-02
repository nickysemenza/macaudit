import AppKit
import Foundation
import MacAuditKit
import SwiftUI

/// One drawn/hit-testable treemap cell, generic across every treemap in the
/// app (the Folders drill-down, the Projects/Apps lens, one owner's
/// entries): each caller owns its own layout (squarify + nesting rules
/// differ) and coloring (domain-specific palette), and only hands
/// `TreemapCanvas` what it needs to draw and hit-test.
struct TreemapCell: Identifiable, Sendable {
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
                    case let .active(location): hover = location
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
            .overlay {
                if let selected, let cell = cells.first(where: { $0.id == selected }) {
                    Path(cell.rect).stroke(Color.accentColor, lineWidth: 2).allowsHitTesting(false)
                }
            }
            .accessibilityLabel("Space treemap")
            .accessibilityChildren {
                ForEach(cells.prefix(128)) { cell in
                    Button("\(cell.title), \(Formatting.bytes(cell.bytes))") { onSelect(cell) }
                        .accessibilityAction(named: Text("Open")) { onOpen?(cell) }
                }
            }
            .focusable()
            .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
                guard !cells.isEmpty else { return .ignored }
                let index = cells.firstIndex { $0.id == selected }
                let delta = press.key == .leftArrow || press.key == .upArrow ? -1 : 1
                let next = min(cells.count - 1, max(0, (index ?? -1) + delta))
                onSelect(cells[next])
                return .handled
            }
            .onKeyPress(.return) {
                guard let onOpen, let cell = cells.first(where: { $0.id == selected }) else { return .ignored }
                onOpen(cell)
                return .handled
            }
        }
    }

    @ViewBuilder
    private func withOpenGesture(_ view: some View) -> some View {
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
        var labelCount = 0
        for cell in cells.prefix(2048) {
            let path = Path(cell.rect)
            ctx.fill(path, with: .color(cell.fill))
            ctx.stroke(path, with: .color(separator), lineWidth: 1)

            guard labelCount < 128, cell.rect.width > 48, cell.rect.height > 16 else { continue }
            labelCount += 1
            let font: Font = cell.depth == 0 ? .caption : .caption2
            let nameText = ctx.resolve(Text(cell.title).font(font))
            ctx.drawLayer { layer in
                layer.clip(to: Path(cell.rect))
                layer.draw(
                    nameText, at: CGPoint(x: cell.rect.minX + 4, y: cell.rect.minY + 2), anchor: .topLeading
                )
            }

            if cell.rect.height > 32 {
                let bytesText = ctx.resolve(
                    Text(Formatting.bytes(cell.bytes)).font(.caption2).foregroundStyle(.secondary)
                )
                ctx.drawLayer { layer in
                    layer.clip(to: Path(cell.rect))
                    layer.draw(
                        bytesText, at: CGPoint(x: cell.rect.minX + 4, y: cell.rect.minY + 18),
                        anchor: .topLeading
                    )
                }
            }
        }
    }

    // MARK: - Tooltip

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
