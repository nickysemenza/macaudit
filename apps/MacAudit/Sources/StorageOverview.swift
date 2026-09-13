import MacAuditKit
import SwiftUI

/// System Settings › Storage, but measured by macaudit's own scanners and
/// aware of what is reclaimable inside each category.
struct StorageOverview: View {
    @Environment(AuditStore.self) private var store
    @State private var history: [SectionHistoryPoint] = []

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                DiskHeaderCard()
                RecommendationsCard()
                CategoriesCard()
                Card(title: "History") {
                    HistoryChart(points: history)
                }
            }
            .padding(20)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .center)
        }
        .task(id: store.snapshots.count) { history = store.loadHistory() }
    }
}

// MARK: - Header

/// One measured bucket of the used space.
struct CategoryStat: Identifiable, Hashable {
    let name: String
    /// Measured bytes, raised to `reclaimable` when the measurement was
    /// partial — a bounded walk can report less than the reclaimable items
    /// it contains, so the number shown is a lower bound.
    let bytes: UInt64
    let complete: Bool
    let reclaimable: UInt64
    let reclaimableCount: Int
    let section: SectionId
    let icon: String
    var id: String { name }
    var segment: BarSegment { BarSegment(name: name, bytes: bytes) }
}

/// Disjoint, measured buckets that tile the used space: disk-allocation
/// categories (distinct roots under ~), Homebrew kegs (/opt/homebrew),
/// Docker data (~/Library/Containers) and simulators. Artifacts, caches,
/// backups and unused runtimes live *inside* these, so they never become
/// segments of their own — they show as "reclaimable within" on the rows.
@MainActor
struct StorageModel {
    let disk: DiskMetric?
    let categories: [CategoryStat]

    init(store: AuditStore) {
        disk = store.findings(in: .system).lazy.compactMap(DiskMetric.init).first
        let fs = store.findings(in: .fs)
        let reclaimableFs = fs.filter { $0.severity == .reclaimable && $0.kind != .diskCategory }
        var out: [CategoryStat] = fs.compactMap { f in
            guard let name = f.diskCategory else { return nil }
            let root = f.path.map { $0.hasSuffix("/") ? $0 : $0 + "/" }
            let within = reclaimableFs.filter { r in
                guard let root, let p = r.path else { return false }
                return p.hasPrefix(root)
            }
            let reclaimable = within.reduce(0) { $0 + ($1.sizeBytes ?? 0) }
            let complete = f.meta.bool("complete") ?? true
            let measured = f.sizeBytes ?? 0
            return CategoryStat(
                name: name, bytes: complete ? measured : max(measured, reclaimable), complete: complete,
                reclaimable: reclaimable, reclaimableCount: within.count, section: .fs,
                icon: Self.icon(for: name))
        }
        func whole(_ name: String, _ section: SectionId, _ icon: String, _ items: [Finding]) {
            let bytes = items.reduce(0) { $0 + ($1.sizeBytes ?? 0) }
            guard bytes > 0 else { return }
            let r = items.filter { $0.severity == .reclaimable }
            out.append(CategoryStat(
                name: name, bytes: bytes, complete: true,
                reclaimable: r.reduce(0) { $0 + ($1.sizeBytes ?? 0) }, reclaimableCount: r.count,
                section: section, icon: icon))
        }
        whole("Homebrew", .brew, "mug", store.findings(in: .brew).filter { !$0.isBrewSummaryRow })
        whole("Docker", .docker, "shippingbox", store.findings(in: .docker))
        whole("Simulators", .simulator, "iphone", store.findings(in: .simulator))
        categories = out.sorted { $0.bytes > $1.bytes }
    }

    var measuredBytes: UInt64 { categories.reduce(0) { $0 + $1.bytes } }

    /// Used space the scanners did not attribute (macOS, other users, apps…).
    var other: UInt64 {
        guard let disk else { return 0 }
        return disk.usedBytes > measuredBytes ? disk.usedBytes - measuredBytes : 0
    }

    var segments: [BarSegment] {
        var out = categories.map(\.segment)
        if other > 0 { out.append(BarSegment(name: "Other", bytes: other)) }
        return out
    }

    var hasPartial: Bool { categories.contains { !$0.complete } }

    static func icon(for category: String) -> String {
        switch category {
        case "Development": "chevron.left.forwardslash.chevron.right"
        case "Agent worktrees": "arrow.triangle.branch"
        case "Developer caches", "App caches": "archivebox"
        case "Application Support": "square.stack.3d.up"
        case "iCloud Drive": "icloud"
        case "Documents": "doc"
        case "Pictures": "photo"
        case "Apple developer data": "hammer"
        default: "folder"
        }
    }
}

private struct DiskHeaderCard: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        let model = StorageModel(store: store)
        Card {
            HStack(alignment: .firstTextBaseline) {
                Text("Macintosh HD").font(.headline)
                Spacer()
                if let d = model.disk {
                    Text("\(Formatting.bytes(d.usedBytes)) of \(Formatting.bytes(d.capacityBytes)) used")
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                        .contentTransition(.numericText())
                } else if store.isScanning {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Root disk not measured").foregroundStyle(.secondary)
                }
            }
            if let d = model.disk {
                SegmentedBar(
                    segments: model.segments,
                    capacity: d.capacityBytes,
                    trailingLabel: "\(Formatting.bytes(d.apfsFreeBytes)) free")
                if let purgeable = d.purgeableBytes, purgeable > 0 {
                    Text("macOS reports another \(Formatting.bytes(purgeable)) as purgeable (\(Formatting.bytes(d.macosAvailableBytes ?? 0)) available); local Time Machine snapshots\(d.timeMachineSnapshots.map { ": \($0)" } ?? "") and caches the system frees on demand.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if store.status(of: .fs) == .idle || { if case .scanning = store.status(of: .fs) { true } else { false } }() {
                    Label("Disk still scanning — categories fill in as they are sized.", systemImage: "hourglass")
                        .font(.caption).foregroundStyle(.secondary)
                } else if model.hasPartial {
                    Label("Categories marked ≥ hit the scanner's 5 s sizing budget; their number is a lower bound.", systemImage: "ruler")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - Categories

private struct CategoryRow: Identifiable {
    let name: String
    let icon: String
    let bytes: UInt64
    let complete: Bool
    let reclaimable: UInt64
    let reclaimableCount: Int
    let section: SectionId?
    let muted: Bool
    var id: String { name }
}

private struct CategoriesCard: View {
    @Environment(AuditStore.self) private var store

    private var rows: [CategoryRow] {
        let model = StorageModel(store: store)
        var out: [CategoryRow] = model.categories.map {
            CategoryRow(name: $0.name, icon: $0.icon, bytes: $0.bytes, complete: $0.complete,
                        reclaimable: $0.reclaimable, reclaimableCount: $0.reclaimableCount,
                        section: $0.section, muted: false)
        }
        if model.other > 0 {
            out.append(CategoryRow(name: "Other (macOS, apps, unscanned)", icon: "ellipsis.circle", bytes: model.other,
                                   complete: true, reclaimable: 0, reclaimableCount: 0, section: nil, muted: true))
        }
        if let d = model.disk {
            out.append(CategoryRow(name: "Free", icon: "circle.dashed", bytes: d.apfsFreeBytes,
                                   complete: true, reclaimable: 0, reclaimableCount: 0, section: nil, muted: true))
        }
        return out
    }

    var body: some View {
        let rows = rows
        if !rows.isEmpty {
            Card(title: "Categories") {
                ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                    if i > 0 { Divider() }
                    HStack(spacing: 12) {
                        Image(systemName: row.icon)
                            .frame(width: 26, height: 26)
                            .background((row.muted ? Color.gray : Palette.color(for: row.name)).opacity(0.2), in: RoundedRectangle(cornerRadius: 6))
                            .foregroundStyle(row.muted ? Color.secondary : Palette.color(for: row.name))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.name).foregroundStyle(row.muted ? .secondary : .primary)
                            if row.reclaimable > 0 {
                                Text("of which \(Formatting.bytes(row.reclaimable)) reclaimable · \(row.reclaimableCount) item\(row.reclaimableCount == 1 ? "" : "s")")
                                    .font(.caption)
                                    .foregroundStyle(Palette.reclaimable)
                            }
                        }
                        Spacer()
                        Text((row.complete ? "" : "≥ ") + Formatting.bytes(row.bytes))
                            .monospacedDigit()
                            .foregroundStyle(row.muted ? .secondary : .primary)
                            .contentTransition(.numericText())
                            .help(row.complete ? "" : "Partial measurement: the scanner's sizing budget ran out in this folder.")
                        if let section = row.section {
                            Button {
                                store.selectedItem = .section(section)
                            } label: {
                                Image(systemName: "info.circle")
                            }
                            .buttonStyle(.borderless)
                            .help("Show in \(store.meta(for: section)?.title ?? section.slug)")
                        } else {
                            Image(systemName: "info.circle").opacity(0)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }
}
