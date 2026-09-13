import Charts
import MacAuditKit
import SwiftUI

/// Reclaimable bytes per section across saved snapshots.
struct HistoryChart: View {
    let points: [SectionHistoryPoint]
    @State private var hidden: Set<SectionId> = []
    @State private var hoverDate: Date?

    private var visible: [SectionHistoryPoint] {
        points.filter { sections.contains($0.section) && !hidden.contains($0.section) }
    }
    private var sections: [SectionId] {
        SectionId.allCases.filter { id in points.contains { $0.section == id && $0.reclaimableBytes > 0 } }
    }
    private var hoveredSnapshot: [SectionHistoryPoint] {
        guard let hoverDate else { return [] }
        let nearest = points.min { abs($0.createdAt.timeIntervalSince(hoverDate)) < abs($1.createdAt.timeIntervalSince(hoverDate)) }
        guard let nearest else { return [] }
        return points.filter { $0.snapshotId == nearest.snapshotId && !hidden.contains($0.section) }
    }

    var body: some View {
        if sections.isEmpty {
            ContentUnavailableView {
                Label("No history yet", systemImage: "chart.xyaxis.line")
            } description: {
                Text("Snapshots are saved after every full scan; reclaimable space per section shows up here.")
            }
            .frame(height: 160)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Chart {
                    ForEach(visible, id: \.self) { p in
                        AreaMark(
                            x: .value("When", p.createdAt),
                            y: .value("Reclaimable", Double(p.reclaimableBytes)),
                            series: .value("Section", p.section.slug),
                            stacking: .standard
                        )
                        .foregroundStyle(Palette.section(p.section).opacity(0.25))
                        LineMark(
                            x: .value("When", p.createdAt),
                            y: .value("Reclaimable", Double(p.reclaimableBytes)),
                            series: .value("Section", p.section.slug)
                        )
                        .foregroundStyle(Palette.section(p.section))
                        .lineStyle(StrokeStyle(lineWidth: 1.5))
                        .symbol(Circle().strokeBorder(lineWidth: 1))
                        .symbolSize(20)
                    }
                    if let first = hoveredSnapshot.first {
                        RuleMark(x: .value("When", first.createdAt))
                            .foregroundStyle(.secondary.opacity(0.5))
                            .annotation(position: .top, alignment: .leading, overflowResolution: .init(x: .fit, y: .disabled)) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(first.createdAt.formatted(date: .abbreviated, time: .shortened)).font(.caption2).foregroundStyle(.secondary)
                                    ForEach(hoveredSnapshot.filter { $0.reclaimableBytes > 0 }, id: \.self) { p in
                                        HStack(spacing: 4) {
                                            Circle().fill(Palette.section(p.section)).frame(width: 6, height: 6)
                                            Text(p.section.slug)
                                            Text(Formatting.bytes(p.reclaimableBytes)).monospacedDigit().foregroundStyle(.secondary)
                                        }
                                        .font(.caption2)
                                    }
                                }
                                .padding(6)
                                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
                            }
                    }
                }
                .chartYAxis {
                    AxisMarks { v in
                        AxisGridLine()
                        AxisValueLabel {
                            if let d = v.as(Double.self) { Text(Formatting.bytes(UInt64(d))).font(.caption2) }
                        }
                    }
                }
                .chartXSelection(value: $hoverDate)
                .chartLegend(.hidden)
                .frame(height: 180)

                FlowLegend(
                    items: sections.map { ($0.slug, Palette.section($0).opacity(hidden.contains($0) ? 0.3 : 1), "") },
                    onTap: { name in
                        guard let id = sections.first(where: { $0.slug == name }) else { return }
                        if hidden.contains(id) { hidden.remove(id) } else { hidden.insert(id) }
                    })
            }
        }
    }
}
