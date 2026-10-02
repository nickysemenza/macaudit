import MacAuditKit
import SwiftUI

private struct SectionCharts: Sendable {
    var slices: [Slice] = []
    var bars: [BarRow] = []
    var devices: [IosDeviceStorage] = []
    var intelOnly = 0
    var selection: [String: UInt64] = [:]

    nonisolated static func build(section: SectionId, findings: [Finding]) -> Self {
        var result = Self()
        for finding in findings {
            let key: String = switch section {
            case .fs: finding.diskCategory ?? finding.group
            case .brew: finding.brewInstallReason ?? finding.group
            case .apps: finding.appClassification ?? finding.group
            case .ios: finding.kind == .iosApp ? finding.title : finding.group
            default: finding.group
            }
            if result.selection[key] == nil {
                result.selection[key] = finding.id
            }
        }
        switch section {
        case .fs:
            result.slices = findings.compactMap { finding in
                finding.diskCategory.map { Slice(name: $0, value: Double(finding.sizeBytes ?? 0)) }
            }.filter { $0.value > 0 }.sorted { $0.value > $1.value }
            result.bars = Dictionary(grouping: findings.filter { $0.kind == .buildArtifact }, by: \.group)
                .map { name, items in
                    let stale = items.filter(\.isStaleArtifact).reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
                    let fresh = items.filter { !$0.isStaleArtifact }.reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
                    return BarRow(name: name, parts: [("stale", stale), ("fresh", fresh)], color: .secondary)
                }
            for (kind, name) in [(FindingKind.cacheDir, "Caches"), (.iosBackup, "iOS Backups"), (.largeFile, "Large files")] {
                let items = findings.filter { $0.kind == kind }
                let bytes = items.reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
                if bytes > 0 {
                    let reclaimable = items.filter { $0.severity == .reclaimable }
                        .reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
                    result.bars.append(BarRow(name: name, parts: [("reclaimable", reclaimable), ("other", bytes - reclaimable)], color: .secondary))
                }
            }
            result.bars = Array(result.bars.sorted { $0.total > $1.total }.prefix(10))
        case .brew:
            let formulas = findings.filter { $0.kind == .brewFormula && !$0.isBrewSummaryRow }
            let reasons = Dictionary(grouping: formulas) {
                $0.isBrewAutoremoveCandidate ? "autoremove" : ($0.brewInstallReason ?? "unknown")
            }
            result.slices = ["requested", "dependency", "autoremove", "unknown"].compactMap { key in
                guard let count = reasons[key]?.count, count > 0 else { return nil }
                return Slice(name: key, value: Double(count), count: count)
            }
            result.bars = formulas.filter { ($0.sizeBytes ?? 0) > 0 }
                .sorted { ($0.sizeBytes ?? 0) > ($1.sizeBytes ?? 0) }.prefix(10).map { finding in
                    BarRow(name: finding.title, parts: [("size", Double(finding.sizeBytes ?? 0))],
                           color: Palette.color(for: finding.isBrewAutoremoveCandidate ? "autoremove" : (finding.brewInstallReason ?? "unknown")))
                }
        case .apps:
            let apps = findings.filter { $0.kind == .app }
            let classes = Dictionary(grouping: apps) { $0.appClassification ?? "unknown" }
            result.slices = ["app_store", "cask", "system", "user", "unmanaged", "unknown"].compactMap { key in
                guard let count = classes[key]?.count, count > 0 else { return nil }
                return Slice(name: key, value: Double(count), count: count)
            }
            result.intelOnly = apps.filter(\.isIntelOnlyApp).count
        case .ios:
            result.devices = findings.compactMap(IosDeviceStorage.init).sorted { $0.name < $1.name }
            let apps = findings.compactMap { finding in IosAppUsage(finding).map { (finding, $0) } }
            let titles = Dictionary(grouping: apps) { $0.0.title }
            result.bars = apps.sorted { $0.1.staticBytes + $0.1.dynamicBytes > $1.1.staticBytes + $1.1.dynamicBytes }
                .prefix(12).map { finding, usage in
                    let name = (titles[finding.title]?.count ?? 1) > 1 ? "\(finding.title) (\(usage.bundleId))" : finding.title
                    result.selection[name] = finding.id
                    return BarRow(name: name, parts: [("app", Double(usage.staticBytes)), ("data", Double(usage.dynamicBytes))])
                }
        default: break
        }
        return result
    }
}

struct SectionChartHeader: View {
    @Environment(AuditStore.self) private var store
    let section: SectionId
    let findings: [Finding]
    @State private var expanded = true
    @State private var selectedGroup: String?
    @State private var presentation: SectionCharts?
    @State private var source: [Finding] = []

    var body: some View {
        Group {
            if let presentation, source == findings,
               [.fs, .brew, .apps, .ios].contains(section)
            {
                VStack(alignment: .leading, spacing: 0) {
                    DisclosureGroup(isExpanded: $expanded) {
                        charts(presentation).padding(.top, 8)
                    } label: {
                        Text("Loaded-page breakdown").font(.subheadline).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
                .onChange(of: selectedGroup) { _, group in
                    guard let group else { return }
                    store.selectedFinding = presentation.selection[group]
                }
            }
        }
        .task(id: findings) {
            let input = findings
            let selectedSection = section
            let prepared = await Task.detached { SectionCharts.build(section: selectedSection, findings: input) }.value
            guard !Task.isCancelled else { return }
            presentation = prepared
            source = input
        }
    }

    private func charts(_ data: SectionCharts) -> some View {
        HStack(alignment: .top, spacing: 24) {
            if !data.slices.isEmpty {
                DonutChart(slices: data.slices, title: section == .fs ? "Allocation" : "By source",
                           format: { section == .fs ? Formatting.bytes(UInt64($0)) : "\(Int($0))" }, selected: $selectedGroup)
            }
            if !data.bars.isEmpty {
                BarBreakdown(rows: data.bars, title: "Largest loaded findings",
                             format: { Formatting.bytes(UInt64($0)) }, selected: $selectedGroup)
                    .frame(maxWidth: .infinity)
            }
            if data.intelOnly > 0 {
                Label("\(data.intelOnly) Intel-only apps on this page", systemImage: "cpu")
            }
            if !data.devices.isEmpty {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(data.devices, id: \.udid) { device in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(device.name) · \(Formatting.bytes(device.capacityBytes)) · \(Formatting.bytes(device.freeBytes)) free")
                            Text("Where it is").font(.caption).foregroundStyle(.secondary)
                            SegmentedBar(segments: [BarSegment(name: "Apps", bytes: device.appsBytes),
                                                    BarSegment(name: "Not attributed", bytes: device.unattributedBytes)],
                                         capacity: device.capacityBytes, trailingLabel: "\(Formatting.bytes(device.freeBytes)) free")
                            Text("What iOS can free on its own").font(.caption).foregroundStyle(.secondary)
                            SegmentedBar(segments: [BarSegment(name: "Committed", bytes: device.committedBytes),
                                                    BarSegment(name: "Purgeable", bytes: device.purgeableBytes)],
                                         capacity: device.capacityBytes, trailingLabel: "\(Formatting.bytes(device.freeBytes)) free")
                        }
                    }
                }.frame(maxWidth: 420)
            }
        }
    }
}
