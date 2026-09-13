import Charts
import SwiftUI

struct BarRow: Identifiable, Hashable {
    let name: String
    /// Stacked parts in draw order, e.g. ("stale", bytes), ("fresh", bytes).
    let parts: [(label: String, value: Double)]
    var color: Color? = nil
    var id: String { name }
    var total: Double { parts.reduce(0) { $0 + $1.value } }

    static func == (a: BarRow, b: BarRow) -> Bool { a.name == b.name && a.total == b.total }
    func hash(into h: inout Hasher) { h.combine(name); h.combine(total) }
}

/// Horizontal bars, biggest first, optionally stacked (the reclaimable
/// share in the accent colour). Hover highlights; click selects.
struct BarBreakdown: View {
    let rows: [BarRow]
    let title: String
    var format: (Double) -> String
    var partColor: (String, BarRow) -> Color = { label, row in
        label == "stale" || label == "reclaimable" ? Palette.reclaimable : (row.color ?? Palette.color(for: row.name))
    }
    @Binding var selected: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            Chart {
                ForEach(rows) { row in
                    ForEach(Array(row.parts.enumerated()), id: \.offset) { _, part in
                        BarMark(
                            x: .value("Value", part.value),
                            y: .value("Name", row.name)
                        )
                        .foregroundStyle(partColor(part.label, row))
                        .opacity(selected == nil || selected == row.name ? 1 : 0.35)
                        .cornerRadius(3)
                    }
                    .annotation(position: .trailing, alignment: .leading) {
                        Text(format(row.total)).font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            }
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks(preset: .extended, position: .leading) { _ in
                    AxisValueLabel(centered: true).font(.caption)
                }
            }
            .chartYSelection(value: $selected)
            .chartXScale(domain: 0...(max(rows.map(\.total).max() ?? 1, 1) * 1.3))
            .chartPlotStyle { $0.frame(height: CGFloat(rows.count) * 26) }
            .frame(height: CGFloat(rows.count) * 26 + 8)
        }
    }
}
