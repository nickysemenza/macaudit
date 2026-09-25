import CoreGraphics
import Foundation
import Testing

@testable import MacAuditKit

/// Builds an owner Finding (`.project`/`.appOwner`) with the exact meta keys
/// `footprint_finding` (`src/attribution/mod.rs`) writes — enough for
/// `OwnerSummary`/`LensModel` to parse. `ownerKey` names the Finding itself
/// (`title`/`path`) — `OwnerSummary` no longer carries its own copy, so
/// tests identify a row via `.finding.title` instead of `.summary.ownerKey`.
private func ownerFinding(
    id: UInt64, kind: FindingKind = .project, ownerKey: String, exclusive: UInt64, shared: UInt64,
    reach: UInt64, baselineShare: UInt64 = 0, byKind: [(String, UInt64)] = []
) -> Finding {
    let byKindJSON = byKind.map { "{\"kind\":\"\($0.0)\",\"bytes\":\($0.1)}" }.joined(separator: ",")
    let json = """
        {"owner_kind":"Project","exclusive":\(exclusive),"shared":\(shared),\
        "reach":\(reach),"baseline_share":\(baselineShare),"by_kind":[\(byKindJSON)],\
        "worktrees":[],"process_count":0,"ports":[],"top_tier":"exact","clone_note":false}
        """
    return Finding(
        id: id, kind: kind, section: .projects, group: "Project", title: ownerKey, detail: "",
        path: ownerKey, sizeBytes: exclusive + shared, lastUsed: nil, severity: .info, remedies: [],
        provenance: nil, coverage: nil, metaJson: json)
}

private func bucketFinding(id: UInt64, title: String, bytes: UInt64) -> Finding {
    Finding(
        id: id, kind: .projectBucket, section: .projects, group: "Coverage", title: title, detail: "",
        path: nil, sizeBytes: bytes, lastUsed: nil, severity: .info, remedies: [], provenance: nil,
        coverage: nil, metaJson: "{\"group\":\"Coverage\"}")
}

private func entry(bytes: UInt64) -> FootprintEntry {
    FootprintEntry(
        path: "/x", kind: .other, bytes: bytes, rawBytes: bytes, owners: [], tier: .ecosystemDefault,
        evidence: "", label: "x", baseline: true, cloneOfStore: false, virtualBytes: false, unsized: false,
        stale: false, finding: nil, reason: nil)
}

// MARK: - rows

@Test func rowsRanksByExclusiveDescendingAndExcludesBuckets() {
    let findings = [
        ownerFinding(id: 1, ownerKey: "small", exclusive: 10, shared: 0, reach: 10),
        ownerFinding(id: 2, ownerKey: "big", exclusive: 100, shared: 0, reach: 100),
        bucketFinding(id: 3, title: "Baseline", bytes: 999),
    ]
    let rows = LensModel.rows(findings)
    #expect(rows.map(\.finding.title) == ["big", "small"])
}

@Test func rowsFractionsAreScaledByTheLargestReachAcrossRows() {
    let findings = [
        ownerFinding(id: 1, ownerKey: "a", exclusive: 50, shared: 25, reach: 100, baselineShare: 25),
        ownerFinding(id: 2, ownerKey: "b", exclusive: 10, shared: 0, reach: 200),
    ]
    let rows = LensModel.rows(findings)
    let a = try! #require(rows.first { $0.finding.title == "a" })
    // Scale is 200 (the larger of the two reaches), not "a"'s own reach.
    #expect(a.exclusiveFraction == 50.0 / 200.0)
    #expect(a.sharedFraction == 25.0 / 200.0)
    #expect(a.baselineFraction == 25.0 / 200.0)
}

// MARK: - coverage

@Test func coverageSplitsAttributedBaselineUnattributedAndRestOfDisk() {
    let buckets = FootprintBuckets(
        axis: .projects,
        baseline: [entry(bytes: 20), entry(bytes: 10)],
        unattributed: [entry(bytes: 5)],
        diskTotal: 1000,
        attributedTotal: 100,  // includes the 30 baseline + 5 unattributed bytes
        missingDeps: [.docker])
    let coverage = try! #require(LensModel.coverage(buckets))
    #expect(coverage.baseline == 30)
    #expect(coverage.unattributed == 5)
    #expect(coverage.attributed == 65)  // 100 - 30 - 5
    #expect(coverage.restOfDisk == 900)  // 1000 - (65 + 30 + 5)
    #expect(coverage.missingDeps == [.docker])
}

@Test func coverageClampsWhenBucketsExceedAttributedTotal() {
    // Racy/stale read: baseline+unattributed alone outweigh attributedTotal.
    let buckets = FootprintBuckets(
        axis: .appStorage, baseline: [entry(bytes: 80)], unattributed: [entry(bytes: 40)],
        diskTotal: 100, attributedTotal: 50, missingDeps: [])
    let coverage = try! #require(LensModel.coverage(buckets))
    #expect(coverage.attributed == 0)
    #expect(coverage.restOfDisk == 0)  // accounted (120) already exceeds diskTotal (100)
}

@Test func coverageIsNilWithoutBuckets() {
    #expect(LensModel.coverage(nil) == nil)
}

// MARK: - treemap items

@Test func treemapItemsSumOwnersPlusBaseline() {
    let findings = [
        ownerFinding(id: 1, ownerKey: "a", exclusive: 60, shared: 10, reach: 70),
        ownerFinding(id: 2, ownerKey: "b", exclusive: 20, shared: 0, reach: 20),
    ]
    let rows = LensModel.rows(findings)
    let buckets = FootprintBuckets(
        axis: .projects, baseline: [entry(bytes: 15), entry(bytes: 5)], unattributed: [],
        diskTotal: 1000, attributedTotal: 90, missingDeps: [])
    let items = LensModel.treemapItems(rows, buckets: buckets)

    let byId = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0.value) })
    #expect(byId[LensModel.treemapOwnerId(rows[0])] == 70)  // exclusive + shared for "a"
    #expect(byId[LensModel.treemapOwnerId(rows[1])] == 20)
    #expect(byId[LensModel.treemapBaselineId] == 20)  // 15 + 5
    #expect(items.count == 3)
}

@Test func treemapItemsOmitZeroBaselineCellFromLayout() {
    // Squarify.layout drops non-positive values, so a zero-bytes Baseline
    // item (no buckets fetched yet) never produces a visible cell.
    let rows = LensModel.rows([ownerFinding(id: 1, ownerKey: "a", exclusive: 10, shared: 0, reach: 10)])
    let items = LensModel.treemapItems(rows, buckets: nil)
    #expect(items.first { $0.id == LensModel.treemapBaselineId }?.value == 0)
    let cells = Squarify.layout(items, in: CGRect(x: 0, y: 0, width: 100, height: 100))
    #expect(cells.map(\.id) == [LensModel.treemapOwnerId(rows[0])])
}

@Test func kindItemsCarryEachByKindBucketsBytes() {
    let rows = LensModel.rows([
        ownerFinding(
            id: 1, ownerKey: "a", exclusive: 30, shared: 0, reach: 30,
            byKind: [("Working tree", 20), ("Artifacts", 10)])
    ])
    let items = LensModel.kindItems(rows[0])
    #expect(items.map(\.value) == [20, 10])
}
