import MacAuditKit
import SwiftUI

/// System Settings › Storage, but measured by macaudit's own scanners and
/// aware of what is reclaimable inside each category.
struct StorageOverview: View {
    @Environment(AuditStore.self) private var store
    @State private var prepared = StorageModel(findings: [:])
    @State private var preparedSource: [SectionId: [Finding]] = [:]

    var body: some View {
        let source = Dictionary(grouping: store.auditPages.cachedRows, by: \.section)
        let model = preparedSource == source ? prepared : StorageModel(findings: [:])
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Loaded-page sample only. Categories and recommendations exclude unloaded Audit pages; they are not whole-scan totals.")
                    .font(.callout).foregroundStyle(.secondary)
                DiskHeaderCard(model: model)
                if !store.hasFullDiskAccess {
                    FullDiskAccessBanner(store: store)
                }
                RecommendationsCard()
                if !store.findings(in: .projects).isEmpty || !store.findings(in: .appStorage).isEmpty {
                    HStack(alignment: .top, spacing: 16) {
                        LargestOwnersCard(axis: .projects, title: "Largest projects", icon: "folder.badge.gearshape")
                        LargestOwnersCard(axis: .appStorage, title: "Largest apps", icon: "app.badge")
                    }
                }
                CategoriesCard(model: model)
            }
            .padding(20)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .center)
        }
        .task(id: source) {
            let model = await Task.detached {
                let started = PresentationTrace.start()
                let model = StorageModel(findings: source)
                PresentationTrace.finish("audit.overview.decode", since: started,
                                         rows: source.values.reduce(0) { $0 + $1.count })
                return model
            }.value
            guard !Task.isCancelled else { return }
            prepared = model
            preparedSource = source
        }
    }
}

// MARK: - Header

/// One measured bucket of the used space.
struct CategoryStat: Identifiable, Hashable, Sendable {
    let name: String
    let bytes: UInt64
    let reclaimable: UInt64
    let reclaimableCount: Int
    let section: SectionId
    let icon: String
    /// The path to browse into (Folders drill-down); nil for categories that
    /// aren't a filesystem root (Homebrew, Docker, Simulators).
    let path: String?
    var id: String {
        name
    }

    var segment: BarSegment {
        BarSegment(name: name, bytes: bytes)
    }
}

struct StorageModel: Sendable {
    let disk: DiskMetric?
    let categories: [CategoryStat]
    init(findings: [SectionId: [Finding]]) {
        disk = findings[.system, default: []].lazy.compactMap(DiskMetric.init).first
        let fs = findings[.fs, default: []]
        let reclaimableFs = fs.filter { $0.severity == .reclaimable && $0.kind != .diskCategory }
        var out: [CategoryStat] = fs.compactMap { f in
            guard let name = f.diskCategory else { return nil }
            let root = f.path.map { $0.hasSuffix("/") ? $0 : $0 + "/" }
            let within = reclaimableFs.filter { r in
                guard let root, let p = r.path else { return false }
                return p.hasPrefix(root)
            }
            let reclaimable = within.reduce(0) { $0 + ($1.sizeBytes ?? 0) }
            return CategoryStat(
                name: name, bytes: f.sizeBytes ?? 0,
                reclaimable: reclaimable, reclaimableCount: within.count, section: .fs,
                icon: Self.icon(for: name), path: f.path
            )
        }
        func whole(_ name: String, _ section: SectionId, _ icon: String, _ items: [Finding]) {
            let bytes = items.reduce(0) { $0 + ($1.sizeBytes ?? 0) }
            guard bytes > 0 else { return }
            let r = items.filter { $0.severity == .reclaimable }
            out.append(CategoryStat(
                name: name, bytes: bytes,
                reclaimable: r.reduce(0) { $0 + ($1.sizeBytes ?? 0) }, reclaimableCount: r.count,
                section: section, icon: icon, path: nil
            ))
        }
        whole("Homebrew", .brew, "mug", findings[.brew, default: []].filter { !$0.isBrewSummaryRow })
        whole("Docker", .docker, "shippingbox", findings[.docker, default: []])
        whole("Simulators", .simulator, "iphone", findings[.simulator, default: []])
        categories = out.sorted { $0.bytes > $1.bytes }
    }

    var measuredBytes: UInt64 {
        categories.reduce(0) { $0 + $1.bytes }
    }

    var otherScanned: UInt64? {
        nil
    }

    /// Used space outside the walked tree entirely.
    var unscanned: UInt64? {
        nil
    }

    /// Fallback single bucket used before the first Disk scan.
    var other: UInt64? {
        nil
    }

    var segments: [BarSegment] {
        guard let disk else { return [] }
        return [BarSegment(name: "Used · Global Audit", bytes: disk.usedBytes)]
    }

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
        case "Package caches": "shippingbox.circle"
        case "Applications": "app.badge"
        case "macOS": "apple.logo"
        case "System Library": "building.columns"
        case "System data": "internaldrive"
        default: "folder"
        }
    }
}

private struct DiskHeaderCard: View {
    @Environment(AuditStore.self) private var store
    let model: StorageModel

    var body: some View {
        Card {
            HStack(alignment: .firstTextBaseline) {
                Text("Macintosh HD · Global Audit").font(.headline)
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
                if let root = store.browser.root {
                    Button("Browse Folders…") { store.browse(path: root.path) }
                        .buttonStyle(.borderless)
                }
            }
            if let d = model.disk {
                SegmentedBar(
                    segments: model.segments,
                    capacity: d.capacityBytes,
                    trailingLabel: "\(Formatting.bytes(d.apfsFreeBytes)) free"
                )
                if let purgeable = d.purgeableBytes, purgeable > 0 {
                    Text("macOS reports another \(Formatting.bytes(purgeable)) as purgeable (\(Formatting.bytes(d.macosAvailableBytes ?? 0)) available); local Time Machine snapshots\(d.timeMachineSnapshots.map { ": \($0)" } ?? "") and caches the system frees on demand.\((model.unscanned ?? 0) > 0 ? " Unscanned space is other APFS volumes, local snapshots and folders only root can read." : "")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if store.status(of: .fs) == .idle || {
                    if case .scanning = store.status(of: .fs) {
                        true
                    } else {
                        false
                    }
                }() {
                    Label("Disk still scanning — categories fill in as they are sized.", systemImage: "hourglass")
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
    let reclaimable: UInt64
    let reclaimableCount: Int
    let section: SectionId?
    let path: String?
    let muted: Bool
    var id: String {
        name
    }
}

private struct CategoriesCard: View {
    @Environment(AuditStore.self) private var store
    let model: StorageModel

    private var rows: [CategoryRow] {
        var out: [CategoryRow] = model.categories.map {
            CategoryRow(name: $0.name, icon: $0.icon, bytes: $0.bytes,
                        reclaimable: $0.reclaimable, reclaimableCount: $0.reclaimableCount,
                        section: $0.section, path: $0.path, muted: false)
        }
        if let d = model.disk {
            out.append(CategoryRow(name: "Free", icon: "circle.dashed", bytes: d.apfsFreeBytes,
                                   reclaimable: 0, reclaimableCount: 0, section: nil, path: nil, muted: true))
        }
        return out
    }

    var body: some View {
        let rows = rows
        if !rows.isEmpty {
            Card(title: "Loaded category samples · scopes may overlap") {
                ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                    if i > 0 {
                        Divider()
                    }
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
                        Text(Formatting.bytes(row.bytes))
                            .monospacedDigit()
                            .foregroundStyle(row.muted ? .secondary : .primary)
                            .contentTransition(.numericText())
                        if let path = row.path {
                            Button {
                                store.browse(path: path)
                            } label: {
                                Image(systemName: "folder")
                            }
                            .buttonStyle(.borderless)
                            .help("Browse \(row.name)")
                        }
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

// MARK: - Largest owners (Projects / App Storage)

/// Top 5 owners by exclusive bytes for one attribution axis. Hidden by the
/// caller when that axis hasn't produced any findings yet; empty once
/// scanned-but-no-owners is still shown so the "nothing found" case reads
/// clearly rather than the card just vanishing.
private struct LargestOwnersCard: View {
    @Environment(AuditStore.self) private var store
    let axis: AttributionAxis
    let title: String
    let icon: String
    @State private var prepared: [LensModel.Row] = []
    @State private var preparedSource: [Finding] = []

    private var sectionId: SectionId {
        axis.sectionId
    }

    private var top5: [LensModel.Row] {
        preparedSource == store.findings(in: sectionId) ? prepared : []
    }

    var body: some View {
        Group {
            if !store.findings(in: sectionId).isEmpty {
                Card(title: title) {
                    let rows = top5
                    if rows.isEmpty {
                        Text("Nothing attributed yet.").foregroundStyle(.secondary).padding(.vertical, 4)
                    } else {
                        let maxExclusive = max(rows.map(\.summary.exclusive).max() ?? 1, 1)
                        ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                            if i > 0 {
                                Divider()
                            }
                            Button {
                                store.openOwner(row.finding, axis: axis)
                            } label: {
                                HStack(spacing: 10) {
                                    Image(systemName: icon)
                                        .frame(width: 22, height: 22)
                                        .foregroundStyle(.secondary)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(row.finding.title).lineLimit(1)
                                        GeometryReader { geo in
                                            Capsule()
                                                .fill(Color.accentColor)
                                                .frame(width: max(2, geo.size.width * CGFloat(row.summary.exclusive) / CGFloat(maxExclusive)), height: 5)
                                        }
                                        .frame(height: 5)
                                    }
                                    Spacer()
                                    Text(Formatting.bytes(row.summary.exclusive)).monospacedDigit().foregroundStyle(.secondary)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .padding(.vertical, 4)
                        }
                    }
                }
            }
        }
        .task(id: store.findings(in: sectionId)) {
            let source = store.findings(in: sectionId)
            let rows = await Task.detached { Array(LensModel.rows(source).prefix(5)) }.value
            guard !Task.isCancelled else { return }
            prepared = rows
            preparedSource = source
        }
    }
}
