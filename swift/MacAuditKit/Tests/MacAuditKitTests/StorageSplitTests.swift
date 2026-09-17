import Testing
@testable import MacAuditKit

@Test func computeSplitsScannedAndUnscannedWhenRootIsKnown() {
    let r = StorageSplit.compute(used: 100, rootAlloc: 80, categoryBytes: 50)
    #expect(r.otherScanned == 30)
    #expect(r.unscanned == 20)
    #expect(r.other == nil)
}

@Test func computeClampsOtherScannedWhenCategoriesExceedRoot() {
    // Racy read: categories summed to more than the root's own alloc.
    let r = StorageSplit.compute(used: 100, rootAlloc: 40, categoryBytes: 50)
    #expect(r.otherScanned == 0)
    #expect(r.unscanned == 60)
}

@Test func computeClampsUnscannedWhenRootExceedsUsed() {
    // Racy read: the walked root looks bigger than the volume's used bytes.
    let r = StorageSplit.compute(used: 40, rootAlloc: 50, categoryBytes: 10)
    #expect(r.otherScanned == 40)
    #expect(r.unscanned == 0)
}

@Test func computeFallsBackToSingleOtherWhenRootIsNil() {
    let r = StorageSplit.compute(used: 100, rootAlloc: nil, categoryBytes: 60)
    #expect(r.other == 40)
    #expect(r.otherScanned == nil)
    #expect(r.unscanned == nil)
}

@Test func computeFallbackClampsOtherAtZero() {
    let r = StorageSplit.compute(used: 30, rootAlloc: nil, categoryBytes: 60)
    #expect(r.other == 0)
}
