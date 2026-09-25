import Foundation

/// SwiftUI also declares `Axis` (`.horizontal`/`.vertical`); files that
/// import both frameworks spell the attribution one `MacAuditKit.Axis`.
/// This alias reads better at call sites that don't need the disambiguation.
public typealias AttributionAxis = Axis

extension AttributionAxis {
    /// Display name for this lens — the header, the navigation title/
    /// subtitle, and every "Rescan Projects/Apps" string.
    public var title: String {
        switch self {
        case .projects: "Projects"
        case .appStorage: "Apps"
        }
    }

    /// The scanner section backing this lens.
    public var sectionId: SectionId {
        switch self {
        case .projects: .projects
        case .appStorage: .appStorage
        }
    }
}

/// Pure ranking / coverage / treemap logic for one attribution lens
/// (Projects or App Storage). Takes plain `[Finding]` + an optional
/// `FootprintBuckets` — no engine calls — so `LensView` can drive it
/// directly from `AuditStore.findings(in:)` and it is exercised standalone
/// by `LensModelTests`.
public enum LensModel {
    /// One ranked row: the owner Finding, its typed summary, and the
    /// stacked-bar fractions the row's cell draws.
    public struct Row: Identifiable, Sendable, Equatable {
        public let finding: Finding
        public let summary: OwnerSummary
        /// `exclusive` / `shared` / `baselineShare` as a fraction of `scale`
        /// — see `rows(_:)`. Always in `[0, 1]`.
        public let exclusiveFraction: Double
        public let sharedFraction: Double
        public let baselineFraction: Double

        public var id: UInt64 { finding.id }
    }

    /// Ranked rows, exclusive bytes descending. Bucket rows
    /// (`isAttributionBucket`) and any finding whose meta doesn't parse as
    /// an `OwnerSummary` (a stale/foreign finding) are excluded.
    ///
    /// Each row's bar fractions are `exclusive`/`shared`/`baselineShare`
    /// divided by the *largest `reach` across all rows* — one shared scale
    /// so every row's bar is comparable at a glance, per the plan's "stacked
    /// bar per row" design.
    public static func rows(_ findings: [Finding]) -> [Row] {
        let owners: [(Finding, OwnerSummary)] = findings.compactMap { f in
            guard !f.isAttributionBucket, let summary = OwnerSummary(f) else { return nil }
            return (f, summary)
        }
        let scale = Double(max(owners.map { $0.1.reach }.max() ?? 0, 1))
        return owners
            .sorted { $0.1.exclusive > $1.1.exclusive }
            .map { finding, summary in
                Row(
                    finding: finding, summary: summary,
                    exclusiveFraction: Double(summary.exclusive) / scale,
                    sharedFraction: Double(summary.shared) / scale,
                    baselineFraction: Double(summary.baselineShare) / scale)
            }
    }

    /// The lens header's coverage split: attributed / baseline /
    /// unattributed / rest-of-disk, all summing to `diskTotal` (clamped at 0
    /// throughout — a stale or racing read must never go negative, same
    /// discipline as `StorageSplit`).
    public struct Coverage: Sendable, Equatable {
        public let attributed: UInt64
        public let baseline: UInt64
        public let unattributed: UInt64
        /// Everything on disk this axis doesn't (yet) account for at all.
        public let restOfDisk: UInt64
        public let diskTotal: UInt64
        public let missingDeps: [SectionId]
    }

    /// `nil` until the axis has produced a `FootprintBuckets` at least once
    /// (`Engine.footprintBuckets(axis:)` — see `OwnerBrowser`).
    public static func coverage(_ buckets: FootprintBuckets?) -> Coverage? {
        guard let buckets else { return nil }
        let baseline = buckets.baseline.reduce(UInt64(0)) { $0 + $1.bytes }
        let unattributed = buckets.unattributed.reduce(UInt64(0)) { $0 + $1.bytes }
        let known = baseline + unattributed
        let attributed = buckets.attributedTotal > known ? buckets.attributedTotal - known : 0
        let accounted = attributed + known
        let restOfDisk = buckets.diskTotal > accounted ? buckets.diskTotal - accounted : 0
        return Coverage(
            attributed: attributed, baseline: baseline, unattributed: unattributed,
            restOfDisk: restOfDisk, diskTotal: buckets.diskTotal, missingDeps: buckets.missingDeps)
    }

    /// Top-level treemap items: one per owner (area = `exclusive + shared`,
    /// i.e. the owner Finding's own `sizeBytes` — `footprint_finding` always
    /// sets it to that sum) plus one synthetic "Baseline" item summing every
    /// baseline entry's bytes. `Squarify.layout` itself drops zero-area
    /// items, so an axis with no baseline simply omits the cell.
    public static func treemapItems(_ rows: [Row], buckets: FootprintBuckets?) -> [Squarify.Item] {
        var items = rows.map {
            Squarify.Item(id: treemapOwnerId($0), value: Double($0.finding.sizeBytes ?? 0))
        }
        let baselineTotal = buckets?.baseline.reduce(UInt64(0)) { $0 + $1.bytes } ?? 0
        items.append(Squarify.Item(id: treemapBaselineId, value: Double(baselineTotal)))
        return items
    }

    /// The stable id `treemapItems` gives an owner's cell — a `Row`'s
    /// `finding.id` round-tripped through `Squarify.Item.id`'s `String`
    /// requirement, so the view can map a hit cell back to its `Row`.
    public static func treemapOwnerId(_ row: Row) -> String { "owner:\(row.finding.id)" }

    /// The stable id of the synthetic Baseline cell `treemapItems` appends.
    public static let treemapBaselineId = "baseline"

    /// Nested items for one owner's `by_kind` breakdown — the inner cells a
    /// treemap draws inside that owner's outer cell (same two-level nesting
    /// as `TreemapView`'s depth 0/1 folders).
    public static func kindItems(_ row: Row) -> [Squarify.Item] {
        row.summary.byKind.enumerated().map { index, k in
            Squarify.Item(id: "kind:\(row.finding.id):\(index)", value: Double(k.bytes))
        }
    }
}
