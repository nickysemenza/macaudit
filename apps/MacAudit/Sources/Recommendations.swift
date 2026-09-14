import MacAuditKit
import SwiftUI

/// One actionable opportunity derived from the current findings — the
/// "Recommendations" block of the Storage overview. `markable` rows can be
/// marked wholesale; every row can be reviewed in its section.
struct Recommendation: Identifiable {
    let id: String
    let title: String
    let detail: String
    let icon: String
    let section: SectionId
    let findings: [Finding]
    let markable: Bool

    var bytes: UInt64 { findings.reduce(0) { $0 + ($1.sizeBytes ?? 0) } }
}

extension AuditStore {
    /// Rules in display order; a rule contributes a row only when it matches.
    var recommendations: [Recommendation] {
        let fs = findings(in: .fs)
        let brew = findings(in: .brew).filter { !$0.isBrewSummaryRow }
        let reclaimable = { (f: Finding) in f.severity == .reclaimable }
        var out: [Recommendation] = []
        func add(_ id: String, _ title: String, _ detail: String, _ icon: String, _ section: SectionId,
                 _ items: [Finding], markable: Bool = true) {
            guard !items.isEmpty else { return }
            out.append(Recommendation(id: id, title: title, detail: detail, icon: icon, section: section,
                                      findings: items, markable: markable))
        }

        let stale = fs.filter(\.isStaleArtifact)
        add("stale-artifacts", "Stale build artifacts",
            "\(stale.count) build directories not touched within the staleness window (node_modules, target, .venv, …). Rebuilds recreate them.",
            "hammer", .fs, stale)
        let fresh = fs.filter { $0.kind == .buildArtifact && !$0.isStaleArtifact }
        add("fresh-artifacts", "Recent build artifacts",
            "\(fresh.count) build directories in active projects. Safe to remove, but the next build recreates them.",
            "hammer.circle", .fs, fresh)
        add("caches", "Developer caches",
            "Package-manager and tool caches that are re-downloaded on demand.",
            "shippingbox.circle", .fs, fs.filter { $0.kind == .cacheDir && reclaimable($0) })
        add("ios-backups", "iOS backups",
            "Device backups kept by Finder; each one is a full copy.",
            "iphone.and.arrow.forward", .fs, fs.filter { $0.kind == .iosBackup })
        add("large-files", "Large files",
            "Loose files over the configured size threshold. Review before deleting.",
            "doc.zipper", .fs, fs.filter { $0.kind == .largeFile && !$0.isDataLibraryPackage }, markable: false)
        add("brew-autoremove", "Homebrew autoremove candidates",
            "Formulae installed only as dependencies that nothing needs any more (`brew autoremove`).",
            "mug", .brew, brew.filter(\.isBrewAutoremoveCandidate))
        add("brew-outdated", "Outdated Homebrew packages",
            "Newer versions are available; upgrading also drops old kegs.",
            "arrow.up.circle", .brew, brew.filter(\.isBrewOutdated), markable: false)
        add("docker", "Docker leftovers",
            "Unused images, dangling layers, stopped containers and volumes.",
            "shippingbox", .docker, findings(in: .docker).filter(reclaimable))
        add("simulators", "Unused simulators",
            "Unavailable runtimes and devices Xcode no longer uses.",
            "iphone", .simulator, findings(in: .simulator).filter(reclaimable))
        add("tm-snapshots", "Local Time Machine snapshots",
            "APFS snapshots macOS keeps on the internal disk between backups.",
            "clock.arrow.2.circlepath", .tmSnapshots, findings(in: .tmSnapshots).filter(reclaimable))
        add("intel-apps", "Intel-only apps",
            "Run under Rosetta on this Mac; check for Apple silicon builds.",
            "cpu", .apps, findings(in: .apps).filter(\.isIntelOnlyApp), markable: false)
        return out
    }

    /// Mark every finding of a recommendation that has a runnable remedy.
    func markAll(_ rec: Recommendation) {
        for f in rec.findings where f.remedies.contains(where: { !$0.alternative }) {
            marked.insert(f.id)
        }
    }

    func review(_ rec: Recommendation) {
        selectedItem = .section(rec.section)
        selectedFinding = rec.findings.first?.id
    }
}

struct RecommendationsCard: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        let recs = store.recommendations
        Card(title: "Recommendations") {
            ReclaimableBreakdown()
            if recs.isEmpty {
                Text(store.isScanning ? "Looking for reclaimable space…" : "Nothing to reclaim right now.")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                ForEach(Array(recs.enumerated()), id: \.element.id) { i, rec in
                    if i > 0 { Divider() }
                    RecommendationRow(rec: rec)
                }
            }
        }
    }
}

private struct RecommendationRow: View {
    @Environment(AuditStore.self) private var store
    let rec: Recommendation

    private var allMarked: Bool {
        rec.findings.allSatisfy { store.marked.contains($0.id) || !$0.remedies.contains { !$0.alternative } }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: rec.icon)
                .font(.title3)
                .frame(width: 30, height: 30)
                .background(Palette.section(rec.section).opacity(0.18), in: RoundedRectangle(cornerRadius: 7))
                .foregroundStyle(Palette.section(rec.section))
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(rec.title).font(.headline)
                    Text("\(rec.findings.count)").foregroundStyle(.secondary).monospacedDigit()
                    Spacer()
                    if rec.bytes > 0 {
                        Text(Formatting.bytes(rec.bytes))
                            .font(.headline)
                            .monospacedDigit()
                            .contentTransition(.numericText())
                    }
                }
                Text(rec.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Review") { store.review(rec) }
                    if rec.markable {
                        Button(allMarked ? "Marked" : "Mark all") { store.markAll(rec) }
                            .disabled(allMarked)
                    }
                }
                .controlSize(.small)
                .padding(.top, 2)
            }
        }
        .padding(.vertical, 6)
    }
}

/// What the headline reclaimable number is made of, as one full-width bar.
private struct ReclaimableBreakdown: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        let total = store.totalReclaimableBytes
        let segments = store.reclaimableBreakdown
        let skipped = store.attentionNotCounted
        if total > 0 {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    Text(Formatting.bytes(total))
                        .font(.title2.weight(.semibold))
                        .monospacedDigit()
                        .contentTransition(.numericText())
                    Text("reclaimable").foregroundStyle(.secondary)
                    Spacer()
                    if store.isScanning { ProgressView().controlSize(.small) }
                }
                SegmentedBar(segments: segments, capacity: total)
                if skipped.bytes > 0 {
                    Text("Not counted: \(Formatting.bytes(skipped.bytes)) in \(skipped.count) large files and iOS backups — they need a look before anything is deleted.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.bottom, 6)
            .animation(.default, value: total)
            Divider()
        }
    }
}

/// Grouped card, like the reference's rounded groups.
struct Card<Content: View>: View {
    let title: String?
    @ViewBuilder let content: Content

    init(title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let title { Text(title).font(.title3.weight(.semibold)) }
            VStack(alignment: .leading, spacing: 6) { content }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
        }
    }
}
