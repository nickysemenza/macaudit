import Charts
import MacAuditKit
import SwiftUI

/// Resource Health: gauges for memory / swap / root disk, a load-vs-cores
/// chart, and the processes worth looking at.
struct OverviewView: View {
    @Environment(AuditStore.self) private var store
    let findings: [Finding]

    private var processes: [Finding] {
        findings.filter { $0.kind == .processResource }
            .sorted { (ProcessMetric($0)?.cpuPercent ?? 0) > (ProcessMetric($1)?.cpuPercent ?? 0) }
    }

    var body: some View {
        @Bindable var store = store
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12)], spacing: 12) {
                    ForEach(findings.filter { $0.kind == .systemMetric }.sorted(by: metricOrder)) { f in
                        MetricCard(finding: f, selected: store.selectedFinding == f.id)
                            .onTapGesture { store.selectedFinding = f.id }
                    }
                }
                if !processes.isEmpty {
                    Text("Processes").font(.headline)
                    Table(processes, selection: $store.selectedFinding) {
                        TableColumn("Process") { f in
                            Text(ProcessMetric(f)?.command ?? f.title).lineLimit(1).truncationMode(.middle)
                        }
                        TableColumn("CPU") { f in
                            let cpu = ProcessMetric(f)?.cpuPercent ?? 0
                            HStack(spacing: 6) {
                                ProgressView(value: min(cpu, 100), total: 100)
                                    .tint(cpu > 50 ? .red : cpu > 20 ? .orange : .accentColor)
                                    .frame(width: 60)
                                Text(String(format: "%.1f%%", cpu)).monospacedDigit().frame(width: 52, alignment: .trailing)
                            }
                        }
                        .width(min: 120, ideal: 130)
                        TableColumn("Memory") { f in
                            let m = ProcessMetric(f)
                            Text(m?.rssBytes.map(Formatting.bytes) ?? "–").monospacedDigit()
                                + Text(m.map { String(format: "  %.1f%%", $0.memoryPercent) } ?? "").foregroundStyle(.secondary)
                        }
                        .width(min: 110, ideal: 130)
                        TableColumn("PID") { f in
                            Text(ProcessMetric(f)?.pid.map(String.init) ?? "").monospacedDigit().foregroundStyle(.secondary)
                        }
                        .width(60)
                        TableColumn("Severity") { SeverityBadge(severity: $0.severity) }
                            .width(min: 80, ideal: 100)
                    }
                    .frame(minHeight: 200, idealHeight: CGFloat(processes.count) * 28 + 40)
                }
            }
            .padding()
        }
    }

    private func metricOrder(_ a: Finding, _ b: Finding) -> Bool {
        let order = ["cpu", "memory", "swap", "disk"]
        return (order.firstIndex(of: a.role ?? "") ?? 99) < (order.firstIndex(of: b.role ?? "") ?? 99)
    }
}

private struct MetricCard: View {
    let finding: Finding
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(finding.title).font(.headline)
                Spacer()
                SeverityBadge(severity: finding.severity)
            }
            visual
            Text(finding.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(selected ? Color.accentColor : .clear, lineWidth: 2))
    }

    @ViewBuilder
    private var visual: some View {
        if let m = MemoryMetric(finding) {
            CapacityGauge(
                fraction: m.fraction ?? 0,
                secondary: m.totalBytes.map { Double(m.compressedBytes) / Double(max($0, 1)) },
                tint: finding.severity.color,
                leading: Formatting.bytes(m.usedBytes) + " used",
                trailing: m.totalBytes.map { "of " + Formatting.bytes($0) } ?? "",
                note: m.pressurePercent.map { "\($0)% pressure" } ?? m.freePercent.map { "\($0)% free" }
                    ?? "\(Formatting.bytes(m.compressedBytes)) compressed")
        } else if let s = SwapMetric(finding) {
            CapacityGauge(
                fraction: s.fraction, secondary: nil, tint: finding.severity.color,
                leading: Formatting.bytes(s.usedBytes) + " used",
                trailing: "of " + Formatting.bytes(s.totalBytes), note: nil)
        } else if let d = DiskMetric(finding) {
            CapacityGauge(
                fraction: Double(d.usedBytes) / Double(max(d.capacityBytes, 1)),
                secondary: d.purgeableBytes.map { Double($0) / Double(max(d.capacityBytes, 1)) },
                tint: finding.severity.color,
                leading: Formatting.bytes(d.usedBytes) + " used",
                trailing: Formatting.bytes(d.apfsFreeBytes) + " free",
                note: d.purgeableBytes.map { "+ \(Formatting.bytes($0)) purgeable" })
        } else if let c = CpuMetric(finding) {
            LoadChart(cpu: c)
        }
    }
}

/// Linear capacity gauge with an optional thin secondary share (compressed
/// memory, purgeable disk) drawn on top.
private struct CapacityGauge: View {
    let fraction: Double
    let secondary: Double?
    let tint: Color
    let leading: String
    let trailing: String
    let note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    Capsule().fill(tint.opacity(0.85))
                        .frame(width: geo.size.width * CGFloat(min(max(fraction, 0), 1)))
                    if let secondary, secondary > 0 {
                        Capsule().fill(.white.opacity(0.35))
                            .frame(width: geo.size.width * CGFloat(min(secondary, 1)), height: 4)
                            .padding(.leading, 3)
                    }
                }
            }
            .frame(height: 12)
            .animation(.easeOut(duration: 0.5), value: fraction)
            HStack {
                Text(leading).monospacedDigit()
                Spacer()
                if let note { Text(note).foregroundStyle(.secondary) }
                Text(trailing).foregroundStyle(.secondary).monospacedDigit()
            }
            .font(.caption)
        }
    }
}

/// 1 / 5 / 15-minute load averages against the core count.
private struct LoadChart: View {
    let cpu: CpuMetric

    private var bars: [(String, Double)] { [("1m", cpu.load1), ("5m", cpu.load5), ("15m", cpu.load15)] }
    private var top: Double { max(bars.map(\.1).max() ?? 1, Double(cpu.cores)) * 1.15 }

    var body: some View {
        Chart {
            ForEach(bars, id: \.0) { label, value in
                BarMark(x: .value("Window", label), y: .value("Load", value))
                    .foregroundStyle(value > Double(cpu.cores) && cpu.cores > 0 ? Color.red : Color.accentColor)
                    .cornerRadius(3)
                    .annotation(position: .top) {
                        Text(String(format: "%.1f", value)).font(.caption2).monospacedDigit()
                    }
            }
            if cpu.cores > 0 {
                RuleMark(y: .value("Cores", Double(cpu.cores)))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                    .foregroundStyle(.secondary)
                    .annotation(position: .top, alignment: .trailing, spacing: 1) {
                        Text("\(cpu.cores) cores").font(.caption2).foregroundStyle(.secondary)
                    }
            }
        }
        .chartYScale(domain: 0...top)
        .chartYAxis(.hidden)
        .frame(height: 90)
    }
}
