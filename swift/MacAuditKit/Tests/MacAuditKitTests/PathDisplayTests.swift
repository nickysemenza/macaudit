import Foundation
import Testing
@testable import MacAuditKit

@Test func abbreviateHomeShortensPathsUnderHome() {
    #expect(PathDisplay.abbreviateHome("/Users/dev/dev", home: "/Users/dev") == "~/dev")
    #expect(PathDisplay.abbreviateHome("/Users/dev", home: "/Users/dev") == "~")
    #expect(PathDisplay.abbreviateHome("/Volumes/External/dev", home: "/Users/dev") == "/Volumes/External/dev")
    // A sibling that merely shares the home directory as a string prefix is
    // not "under" it and must not be abbreviated.
    #expect(PathDisplay.abbreviateHome("/Users/devious", home: "/Users/dev") == "/Users/devious")
}

@Test func componentsBuildsBreadcrumbTrailFromRoot() {
    let home = NSHomeDirectory()
    let crumbs = PathDisplay.components("\(home)/dev/macaudit", root: home)
    #expect(crumbs.map(\.label) == ["~", "dev", "macaudit"])
    #expect(crumbs.map(\.path) == [home, "\(home)/dev", "\(home)/dev/macaudit"])
}

@Test func componentsAtRootIsJustTheRoot() {
    let home = NSHomeDirectory()
    let crumbs = PathDisplay.components(home, root: home)
    #expect(crumbs.count == 1)
    #expect(crumbs[0].label == "~")
    #expect(crumbs[0].path == home)
}

@Test func componentsUsesLastComponentWhenRootIsNotHome() {
    let crumbs = PathDisplay.components("/Volumes/External/dev/movies", root: "/Volumes/External/dev")
    #expect(crumbs.map(\.label) == ["dev", "movies"])
}

@Test func componentsOutsideRootFallsBackToLastComponentOnly() {
    let crumbs = PathDisplay.components("/Library/Caches", root: "/Users/dev")
    #expect(crumbs.count == 1)
    #expect(crumbs[0].label == "Caches")
    #expect(crumbs[0].path == "/Library/Caches")
}
