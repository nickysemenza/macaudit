import MacAuditKit
import SwiftUI

/// Collapsible breakdown charts above the Disk, Brew and Apps lists.
/// Selecting a chart element highlights it and jumps the list to that group.
struct SectionChartHeader: View {
    @Environment(AuditStore.self) private var store
    let section: SectionId
    let findings: [Finding]
    @AppStorage("chartHeaderExpanded") private var expanded = true
    @State private var selectedGroup: String?

    var body: some View {
        if let content = chartContent {
            VStack(alignment: .leading, spacing: 0) {
                DisclosureGroup(isExpanded: $expanded) {
                    content.padding(.top, 8)
                } label: {
                    Text("Breakdown").font(.subheadline).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                Divider()
            }
            .onChange(of: selectedGroup) { _, group in
                guard let group else { return }
                // Jump the list to the first finding of the chosen group.
                if let f = findings.first(where: { groupKey($0) == group }) {
                    store.selectedFinding = f.id
                }
            }
        }
    }

    /// How a finding maps onto the chart categories for this section.
    private func groupKey(_ f: Finding) -> String {
        switch section {
        case .fs: f.diskCategory ?? f.group
        case .brew: f.brewInstallReason ?? f.group
        case .apps: f.appClassification ?? f.group
        // Bars are per app, so a click must land on that app, not the device.
        case .ios: f.kind == .iosApp ? f.title : f.group
        default: f.group
        }
    }

    @ViewBuilder
    private var chartContent: (some View)? {
        switch section {
        case .fs: AnyView(diskCharts)
        case .brew: AnyView(brewCharts)
        case .apps: AnyView(appsCharts)
        case .ios: iosCharts
        default: nil as AnyView?
        }
    }

    // MARK: Disk

    private var diskCharts: some View {
        let categories = findings.compactMap { f in f.diskCategory.map { Slice(name: $0, value: Double(f.sizeBytes ?? 0)) } }
            .filter { $0.value > 0 }
            .sorted { $0.value > $1.value }
        let artifacts = Dictionary(grouping: findings.filter { $0.kind == .buildArtifact }, by: \.group)
        var rows: [BarRow] = artifacts.map { name, items in
            let stale = items.filter(\.isStaleArtifact).reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
            let fresh = items.filter { !$0.isStaleArtifact }.reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
            return BarRow(name: name, parts: [("stale", stale), ("fresh", fresh)], color: .secondary)
        }
        for (kind, name) in [(FindingKind.cacheDir, "Caches"), (.iosBackup, "iOS Backups"), (.largeFile, "Large files")] {
            let items = findings.filter { $0.kind == kind }
            let bytes = items.reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
            if bytes > 0 {
                let reclaimable = items.filter { $0.severity == .reclaimable }.reduce(0.0) { $0 + Double($1.sizeBytes ?? 0) }
                rows.append(BarRow(name: name, parts: [("reclaimable", reclaimable), ("other", bytes - reclaimable)], color: .secondary))
            }
        }
        rows.sort { $0.total > $1.total }
        return HStack(alignment: .top, spacing: 24) {
            if !categories.isEmpty {
                DonutChart(slices: categories, title: "Allocation", format: { Formatting.bytes(UInt64($0)) }, selected: $selectedGroup)
            }
            if !rows.isEmpty {
                BarBreakdown(rows: Array(rows.prefix(10)), title: "Reclaimable by kind (stale / reclaimable in orange)",
                             format: { Formatting.bytes(UInt64($0)) }, selected: $selectedGroup)
                    .frame(maxWidth: .infinity)
            }
        }
    }

    // MARK: Brew

    private var brewCharts: some View {
        let formulas = findings.filter { $0.kind == .brewFormula && !$0.isBrewSummaryRow }
        let reasons = Dictionary(grouping: formulas) { $0.isBrewAutoremoveCandidate ? "autoremove" : ($0.brewInstallReason ?? "unknown") }
        let slices = ["requested", "dependency", "autoremove", "unknown"].compactMap { key -> Slice? in
            guard let n = reasons[key]?.count, n > 0 else { return nil }
            return Slice(name: key, value: Double(n), count: n)
        }
        let top = formulas.filter { ($0.sizeBytes ?? 0) > 0 }
            .sorted { ($0.sizeBytes ?? 0) > ($1.sizeBytes ?? 0) }
            .prefix(10)
            .map { f in
                BarRow(name: f.title, parts: [("size", Double(f.sizeBytes ?? 0))],
                       color: Palette.color(for: f.isBrewAutoremoveCandidate ? "autoremove" : (f.brewInstallReason ?? "unknown")))
            }
        return HStack(alignment: .top, spacing: 24) {
            if !slices.isEmpty {
                DonutChart(slices: slices, title: "Packages by origin", format: { "\(Int($0))" }, selected: $selectedGroup)
            }
            if !top.isEmpty {
                BarBreakdown(rows: Array(top), title: "Largest kegs (colour = origin)",
                             format: { Formatting.bytes(UInt64($0)) },
                             partColor: { _, row in row.color ?? .gray },
                             selected: $selectedGroup)
                    .frame(maxWidth: .infinity)
            }
        }
    }

    // MARK: Apps

    private var appsCharts: some View {
        let apps = findings.filter { $0.kind == .app }
        let byClass = Dictionary(grouping: apps) { $0.appClassification ?? "unknown" }
        let slices = ["app_store", "cask", "system", "user", "unmanaged", "unknown"].compactMap { key -> Slice? in
            guard let n = byClass[key]?.count, n > 0 else { return nil }
            return Slice(name: key, value: Double(n), count: n)
        }
        let intel = apps.filter(\.isIntelOnlyApp).count
        return HStack(alignment: .top, spacing: 24) {
            if !slices.isEmpty {
                DonutChart(slices: slices, title: "Apps by source", format: { "\(Int($0))" }, selected: $selectedGroup)
            }
            if intel > 0 {
                VStack(alignment: .leading, spacing: 4) {
                    Label("\(intel) Intel-only app\(intel == 1 ? "" : "s")", systemImage: "cpu")
                        .font(.headline)
                    Text("Running under Rosetta on this Apple silicon Mac. Check the developer for a native build.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(12)
                .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
            Spacer()
        }
    }

    // MARK: iOS Devices

    /// Nil when the section holds only status rows (no device, tools
    /// missing) — the table row already says why.
    private var iosCharts: AnyView? {
        let devices = findings.compactMap(IosDeviceStorage.init).sorted { $0.name < $1.name }
        guard !devices.isEmpty else { return nil }
        let apps = findings.compactMap { f in IosAppUsage(f).map { (finding: f, usage: $0) } }
        let titles = Dictionary(grouping: apps, by: \.finding.title)
        let top = apps
            .sorted { $0.usage.staticBytes + $0.usage.dynamicBytes > $1.usage.staticBytes + $1.usage.dynamicBytes }
            .prefix(12)
            .map { app -> BarRow in
                // BarRow is keyed by name; two apps with one display name
                // (e.g. across devices) would collapse into a single bar.
                let name = (titles[app.finding.title]?.count ?? 1) > 1
                    ? "\(app.finding.title) (\(app.usage.bundleId))" : app.finding.title
                return BarRow(name: name, parts: [("app", Double(app.usage.staticBytes)), ("data", Double(app.usage.dynamicBytes))])
            }
        return AnyView(HStack(alignment: .top, spacing: 24) {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(devices, id: \.udid) { d in
                    VStack(alignment: .leading, spacing: 6) {
                        // The trailing "free" label vanishes when free space is
                        // a sliver of the bar, so the number lives up here too.
                        Text("\(d.name) · \(Formatting.bytes(d.capacityBytes)) · \(Formatting.bytes(d.freeBytes)) free")
                            .font(.subheadline.weight(.semibold))
                        // Two exact tilings of the capacity. Apps and purgeable
                        // never share a bar: app data overlaps purgeable.
                        Text("Where it is").font(.caption).foregroundStyle(.secondary)
                        SegmentedBar(
                            segments: [BarSegment(name: "Apps", bytes: d.appsBytes),
                                       BarSegment(name: "Not attributed", bytes: d.unattributedBytes)],
                            capacity: d.capacityBytes,
                            trailingLabel: "\(Formatting.bytes(d.freeBytes)) free")
                        Text("What iOS can free on its own").font(.caption).foregroundStyle(.secondary)
                        SegmentedBar(
                            segments: [BarSegment(name: "Committed", bytes: d.committedBytes),
                                       BarSegment(name: "Purgeable", bytes: d.purgeableBytes)],
                            capacity: d.capacityBytes,
                            trailingLabel: "\(Formatting.bytes(d.freeBytes)) free")
                    }
                }
            }
            .frame(maxWidth: 420)
            if !top.isEmpty {
                BarBreakdown(rows: Array(top), title: "Largest apps (light = app, dark = data)",
                             format: { Formatting.bytes(UInt64($0)) },
                             partColor: { label, _ in Palette.color(for: label) },
                             selected: $selectedGroup)
                    .frame(maxWidth: .infinity)
            }
        })
    }
}
