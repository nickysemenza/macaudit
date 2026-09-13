import Charts
import SwiftUI

struct Slice: Identifiable, Hashable {
    let name: String
    let value: Double
    var count: Int = 0
    var id: String { name }
}

/// Sector donut with a centred total and hover/click selection. `format`
/// renders a slice value (bytes or a count).
struct DonutChart: View {
    let slices: [Slice]
    let title: String
    var format: (Double) -> String = { String(Int($0)) }
    @Binding var selected: String?

    private var total: Double { slices.reduce(0) { $0 + $1.value } }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            HStack(spacing: 12) {
                Chart(slices) { s in
                    SectorMark(
                        angle: .value("Value", s.value),
                        innerRadius: .ratio(0.62),
                        angularInset: 1.5
                    )
                    .cornerRadius(3)
                    .foregroundStyle(Palette.color(for: s.name))
                    .opacity(selected == nil || selected == s.name ? 1 : 0.35)
                }
                .chartLegend(.hidden)
                .chartAngleSelection(value: Binding(
                    get: { nil as Double? },
                    set: { angle in
                        guard let angle else { selected = nil; return }
                        var acc = 0.0
                        selected = slices.first { s in acc += s.value; return angle <= acc }?.name
                    }))
                .chartBackground { _ in
                    VStack(spacing: 0) {
                        let s = slices.first { $0.name == selected }
                        Text(format(s?.value ?? total)).font(.callout.weight(.semibold)).monospacedDigit()
                        Text(s?.name ?? "total").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .frame(width: 120, height: 120)

                VStack(alignment: .leading, spacing: 3) {
                    ForEach(slices) { s in
                        Button {
                            selected = selected == s.name ? nil : s.name
                        } label: {
                            HStack(spacing: 6) {
                                Circle().fill(Palette.color(for: s.name)).frame(width: 8, height: 8)
                                Text(s.name).lineLimit(1)
                                Spacer(minLength: 8)
                                Text(format(s.value)).foregroundStyle(.secondary).monospacedDigit()
                            }
                            .font(.caption)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .opacity(selected == nil || selected == s.name ? 1 : 0.5)
                    }
                }
                .frame(width: 190)
            }
        }
    }
}
