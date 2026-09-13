import Charts
import MacAuditKit
import SwiftUI

struct BarSegment: Identifiable, Hashable {
    let name: String
    let bytes: UInt64
    var color: Color { Palette.color(for: name) }
    var id: String { name }
}

/// The System Settings › Storage bar: one horizontal stacked bar of named
/// segments over a fixed capacity, with a hover readout and a legend.
struct SegmentedBar: View {
    let segments: [BarSegment]
    let capacity: UInt64
    /// Trailing label drawn on the unfilled remainder (e.g. free space).
    var trailingLabel: String?
    @State private var hovered: String?

    private var filled: UInt64 { segments.reduce(0) { $0 + $1.bytes } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            GeometryReader { geo in
                let width = geo.size.width
                let scale = capacity > 0 ? width / CGFloat(capacity) : 0
                let spacing: CGFloat = 1
                // Explicit widths so gaps and minimum widths come out of the
                // remainder instead of pushing the bar past its container.
                let widths = segments.map { max(CGFloat($0.bytes) * scale, $0.bytes > 0 ? 2 : 0) }
                let usedWidth = widths.reduce(0, +) + spacing * CGFloat(widths.filter { $0 > 0 }.count)
                HStack(spacing: spacing) {
                    ForEach(Array(zip(segments, widths)), id: \.0.id) { seg, w in
                        if w > 0 {
                            Rectangle()
                                .fill(seg.color.opacity(hovered == nil || hovered == seg.name ? 1 : 0.35))
                                .frame(width: w)
                                .onHover { hovered = $0 ? seg.name : nil }
                                .help("\(seg.name): \(Formatting.bytes(seg.bytes))")
                        }
                    }
                    ZStack(alignment: .trailing) {
                        Rectangle().fill(.quaternary)
                        if let trailingLabel {
                            Text(trailingLabel)
                                .font(.caption.weight(.medium))
                                .padding(.horizontal, 8)
                                .lineLimit(1)
                        }
                    }
                    .frame(width: max(0, width - usedWidth))
                }
                .frame(width: width)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .animation(.easeOut(duration: 0.4), value: segments)
            }
            .frame(height: 26)

            FlowLegend(items: segments.filter { $0.bytes > 0 }.map { ($0.name, $0.color, Formatting.bytes($0.bytes)) },
                       highlighted: hovered)
        }
    }
}

/// Wrapping legend of coloured dots. Shows the value of the highlighted item.
struct FlowLegend: View {
    let items: [(name: String, color: Color, value: String)]
    var highlighted: String? = nil
    var onTap: ((String) -> Void)? = nil

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 130), alignment: .leading)], alignment: .leading, spacing: 4) {
            ForEach(items, id: \.name) { item in
                HStack(spacing: 5) {
                    Circle().fill(item.color).frame(width: 8, height: 8)
                    Text(item.name).lineLimit(1)
                    if highlighted == item.name {
                        Text(item.value).foregroundStyle(.secondary).monospacedDigit()
                    }
                }
                .font(.caption)
                .foregroundStyle(highlighted == nil || highlighted == item.name ? .primary : .secondary)
                .contentShape(Rectangle())
                .onTapGesture { onTap?(item.name) }
            }
        }
    }
}
