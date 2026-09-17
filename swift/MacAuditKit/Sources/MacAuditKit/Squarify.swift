import CoreGraphics

/// Squarified treemap layout (Bruls, Huizing, van Wijk 1999). Pure geometry —
/// no SwiftUI, no engine types — so it is exercised directly by
/// `SquarifyTests` and reused by `TreemapView` for both drawing and hit
/// testing.
public enum Squarify {
    public struct Item: Equatable {
        public let id: String
        public let value: Double

        public init(id: String, value: Double) {
            self.id = id
            self.value = value
        }
    }

    public struct Cell: Equatable {
        public let id: String
        public let rect: CGRect

        public init(id: String, rect: CGRect) {
            self.id = id
            self.rect = rect
        }
    }

    /// Lays `items` out to exactly tile `bounds`. `items` may be given in any
    /// order (sorted descending internally); zero/negative values are
    /// dropped. Returns one cell per remaining item; empty input or a
    /// zero-area `bounds` yields `[]`.
    public static func layout(_ items: [Item], in bounds: CGRect) -> [Cell] {
        let positive = items.filter { $0.value > 0 }
        guard !positive.isEmpty, bounds.width > 0, bounds.height > 0 else { return [] }

        let sorted = positive.sorted { $0.value > $1.value }
        let totalValue = sorted.reduce(0.0) { $0 + $1.value }
        guard totalValue > 0 else { return [] }

        // Normalise so that Σ area == bounds area; from here on we work
        // purely in area units, which is what the worst-aspect-ratio
        // formula and the row layout both need.
        let totalArea = Double(bounds.width) * Double(bounds.height)
        let scale = totalArea / totalValue
        let scaled = sorted.map { (id: $0.id, area: $0.value * scale) }

        var cells: [Cell] = []
        var remaining = bounds
        var row: [(id: String, area: Double)] = []
        var index = 0

        while index < scaled.count {
            let next = scaled[index]
            let w = shortSide(remaining)
            let candidate = row + [next]
            if row.isEmpty || worst(row, w) >= worst(candidate, w) {
                row = candidate
                index += 1
            } else {
                let (rowCells, rest) = layoutRow(row, into: remaining)
                cells.append(contentsOf: rowCells)
                remaining = rest
                row = []
            }
        }
        if !row.isEmpty {
            let (rowCells, _) = layoutRow(row, into: remaining)
            cells.append(contentsOf: rowCells)
        }
        return cells
    }

    private static func shortSide(_ rect: CGRect) -> Double {
        Double(min(rect.width, rect.height))
    }

    /// Worst aspect ratio the row would have if laid out at fixed width `w`
    /// (the short side of the remaining rect): `max` over the row of
    /// `max(w²·r/s², s²/(w²·r))`, which — since the first term is increasing
    /// in `r` and the second decreasing — reduces to comparing the row's max
    /// and min areas against the row sum `s`.
    private static func worst(_ row: [(id: String, area: Double)], _ w: Double) -> Double {
        guard !row.isEmpty, w > 0 else { return .infinity }
        let s = row.reduce(0.0) { $0 + $1.area }
        guard s > 0 else { return .infinity }
        let maxArea = row.map(\.area).max()!
        let minArea = row.map(\.area).min()!
        let a = (w * w * maxArea) / (s * s)
        let b = (s * s) / (w * w * minArea)
        return max(a, b)
    }

    /// Places `row` as a band along the short side of `rect`, then returns
    /// the leftover rect after removing that band.
    private static func layoutRow(
        _ row: [(id: String, area: Double)], into rect: CGRect
    ) -> (cells: [Cell], remaining: CGRect) {
        let s = row.reduce(0.0) { $0 + $1.area }
        guard s > 0, rect.width > 0, rect.height > 0 else { return ([], rect) }

        var cells: [Cell] = []
        if rect.width <= rect.height {
            // Short side is width: band spans the full width at the top,
            // with items placed left-to-right inside it.
            let bandHeight = min(s / Double(rect.width), Double(rect.height))
            var x = rect.minX
            for item in row {
                let w = CGFloat(item.area / s) * rect.width
                cells.append(Cell(id: item.id, rect: CGRect(x: x, y: rect.minY, width: w, height: CGFloat(bandHeight))))
                x += w
            }
            let remaining = CGRect(
                x: rect.minX, y: rect.minY + CGFloat(bandHeight),
                width: rect.width, height: rect.height - CGFloat(bandHeight))
            return (cells, remaining)
        } else {
            // Short side is height: band spans the full height at the left,
            // with items stacked top-to-bottom inside it.
            let bandWidth = min(s / Double(rect.height), Double(rect.width))
            var y = rect.minY
            for item in row {
                let h = CGFloat(item.area / s) * rect.height
                cells.append(Cell(id: item.id, rect: CGRect(x: rect.minX, y: y, width: CGFloat(bandWidth), height: h)))
                y += h
            }
            let remaining = CGRect(
                x: rect.minX + CGFloat(bandWidth), y: rect.minY,
                width: rect.width - CGFloat(bandWidth), height: rect.height)
            return (cells, remaining)
        }
    }
}
