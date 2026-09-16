import Testing
@testable import MacAuditKit

@Test func shareFormatsAsWholePercent() {
    #expect(Formatting.share(42, of: 100) == "42%")
    #expect(Formatting.share(1, of: 3) == "33%")
    #expect(Formatting.share(0, of: 0) == "0%")
    #expect(Formatting.share(5, of: 5) == "100%")
}

@Test func countGroupsDigits() {
    #expect(Formatting.count(1_234_567) == "1,234,567")
    #expect(Formatting.count(42) == "42")
}
