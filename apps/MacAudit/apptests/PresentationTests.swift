import AppKit
@testable import MacAudit
import MacAuditKit
import SnapshotTesting
import SwiftUI
import XCTest

@MainActor
final class PresentationTests: XCTestCase {
    func testStartupRootHonorsHomeOverrideWithoutScanning() {
        XCTAssertEqual(ApplicationCoordinator.initialRoot(homeOverride: "/fixture/temporary-home", isTesting: false,
                                                          defaultHome: "/not-the-selected-home"), "/fixture/temporary-home")
        XCTAssertEqual(ApplicationCoordinator.initialRoot(homeOverride: nil, isTesting: false,
                                                          defaultHome: "/fixture/default-home"), "/fixture/default-home")
        XCTAssertEqual(ApplicationCoordinator.initialRoot(homeOverride: "/ignored", isTesting: true,
                                                          defaultHome: "/ignored-home"), "/fixture")
    }

    func testWindowStatePersistenceIsDisabled() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.close() }
        WindowMemoryPolicy.apply(to: window)
        XCTAssertFalse(window.isRestorable)
        XCTAssertNil(window.restorationClass)
        XCTAssertEqual(window.frameAutosaveName, "")
    }

    func testRootPathExpansion() {
        XCTAssertEqual(AuditStore.expandedRoot("~/cf-repos", home: "/fixture/home"), "/fixture/home/cf-repos")
        XCTAssertEqual(AuditStore.expandedRoot("cf-repos/../projects", home: "/fixture/home"), "/fixture/home/projects")
        XCTAssertEqual(AuditStore.expandedRoot(" / "), "/")
        XCTAssertNil(AuditStore.expandedRoot(" \n "))
    }

    func testAuditNavigationRevealsOutsideRootWithoutChangingRun() async throws {
        var revealed: [String] = []
        let engine = FakeAppEngine()
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture/A",
                               revealLocation: { revealed.append($0) })
        store.browse(path: "/fixture/A/child")
        try await eventually { store.browser.current?.path == "/fixture/A/child" }
        store.browse(path: "/fixture/AB/child")
        store.browse(path: "/fixture/A/../outside")
        XCTAssertEqual(revealed, ["/fixture/AB/child", "/fixture/A/../outside"])
        XCTAssertEqual(store.browser.current?.path, "/fixture/A/child")
        XCTAssertEqual(store.selectedRoot, "/fixture/A")
        XCTAssertEqual(engine.runCount, 0)
        XCTAssertTrue(AuditStore.containsLocation("/fixture/A", under: "/fixture/A/"))
        XCTAssertTrue(AuditStore.containsLocation("/fixture/A/file", under: "/"))
        XCTAssertFalse(AuditStore.containsLocation("relative/file", under: "/fixture"))
    }

    func testLocationFilterQueriesBeyondLoadedPagesAndKeepsBoundaries() async throws {
        let engine = FakeAppEngine()
        let outside = (0..<600).map { index in
            fixtureFinding(UInt64(index), path: "/fixture/AB/\(index)", detail: "/fixture/A")
        }
        let inside = (600..<1120).map { index in
            fixtureFinding(UInt64(index), path: "/fixture/A/sub/\(index)")
        }
        engine.setFindings(outside + inside, section: .fs)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.showFindings(under: "/fixture/A")
        try await eventually { store.auditPages.rows.count == 500 && !store.auditPages.isLoading }
        XCTAssertEqual(store.auditPages.rows.first?.id, 600)
        XCTAssertEqual(store.auditPages.rows.last?.id, 1099)
        XCTAssertEqual(store.searchText, "")
        XCTAssertEqual(store.auditPages.locationFilter, "/fixture/A")
        XCTAssertNotNil(store.auditPages.nextOffset)
        store.auditPages.next()
        try await eventually { store.auditPages.rows.count == 20 && !store.auditPages.isLoading }
        XCTAssertEqual(store.auditPages.rows.first?.id, 1100)
        XCTAssertNil(store.auditPages.nextOffset)
        store.auditPages.previous()
        try await eventually { store.auditPages.rows.count == 500 && !store.auditPages.isLoading }
        store.auditPages.filterLocation(nil)
        try await eventually { store.auditPages.rows.first?.id == 0 && !store.auditPages.isLoading }
    }

    func testLocationChangeInvalidatesPendingPage() async throws {
        let engine = FakeAppEngine()
        engine.setFindings([fixtureFinding(10)], section: .fs)
        let browser = AuditFindingsBrowser(engine: engine)
        engine.blockSection(.fs)
        browser.select(.fs)
        try await eventually { engine.blockedQueryStarted }
        browser.filterLocation("/fixture/B")
        engine.releaseQueries()
        try await eventually { !browser.isLoading }
        XCTAssertEqual(browser.locationFilter, "/fixture/B")
        XCTAssertTrue(browser.rows.isEmpty)
    }

    func testCancelRetainsLatePartialResultsAndReconcilesWorkerRetirement() async throws {
        let engine = FakeAppEngine()
        engine.setActiveScanners(2)
        engine.setFindings([fixtureFinding(10)], section: .fs)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.rescanAll()
        try await eventually { engine.runCount == 1 && store.canCancelScan }
        store.selectedItem = .section(.fs)
        store.browser.navigate(to: "/fixture/A")
        try await eventually { store.finding(10) != nil && store.browser.current != nil }
        store.cancelScan()
        XCTAssertEqual(engine.cancelCount, 1)
        XCTAssertFalse(store.canCancelScan)
        XCTAssertNotEqual(store.status(of: .fs), .idle)
        XCTAssertEqual(store.browser.current?.path, "/fixture/A")
        engine.emitScanEvent(.findings(section: .fs, gen: 1, findings: [fixtureFinding(11)]))
        try await eventually { store.finding(11) != nil && store.scanMetadata?.activeScanners == 2 }
        XCTAssertTrue(store.scanMetadata?.cancelled == true)
        XCTAssertTrue(store.isRetiringScan)
        engine.setActiveScanners(0)
        try await eventually { !store.isScanning && !store.isRetiringScan }
        XCTAssertNotNil(store.finding(10))
        XCTAssertNotNil(store.finding(11))
        XCTAssertEqual(store.scanMetadata?.diskCoverage, "cancelled")
        XCTAssertEqual(store.scanMetadata?.auditCoverage, "cancelled")
        XCTAssertNotEqual(store.status(of: .fs), .idle)
    }

    func testRefreshRejectsCancelledRunCallbacksAndRetirementMetadata() async throws {
        let engine = FakeAppEngine()
        engine.setActiveScanners(2)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.rescanAll()
        try await eventually { store.canCancelScan }
        store.cancelScan()
        try await eventually { store.scanMetadata?.runId == 1 }
        store.changeRoot("/fixture/B")
        try await eventually { engine.runCount == 2 && store.canRefresh }
        engine.emitScanEvent(.sectionFailed(section: .fs, gen: 1, error: "old failure"))
        store.apply(.sectionFinished(section: .fs, gen: 1, durationMs: 1))
        try await Task.sleep(for: .milliseconds(180))
        XCTAssertEqual(store.selectedRoot, "/fixture/B")
        XCTAssertNotEqual(store.status(of: .fs), .failed("old failure"))
        XCTAssertNotEqual(store.status(of: .fs), .done(durationMs: 1))
        XCTAssertNil(store.scanMetadata)
        XCTAssertTrue(store.canCancelScan)
        engine.setActiveScanners(0)
        store.cancelScan()
        try await eventually { !store.isScanning }
    }

    func testAccountingLabelsKeepUnknownSeparateFromObservedZero() {
        XCTAssertEqual(AccountingLabels.count(nil), "Unknown (partial or unavailable)")
        XCTAssertEqual(AccountingLabels.bytes(nil), "Unknown (partial or unavailable)")
        XCTAssertEqual(AccountingLabels.count(0), Formatting.count(0))
        XCTAssertEqual(AccountingLabels.bytes(0), Formatting.bytes(0))
    }

    func testRootAccountingClearsImmediatelyOnReset() async throws {
        let browser = DirBrowser(engine: FakeAppEngine(renderedFixture: true))
        browser.refreshRoot()
        try await eventually { browser.rootStats != nil }
        XCTAssertEqual(browser.rootStats?.directoryEntries, 4)
        XCTAssertEqual(browser.rootStats?.externallyLinkedBytes, 20)
        browser.reset()
        XCTAssertNil(browser.rootStats)
    }

    func testCacheEvictsLeastRecentlyUsed() {
        var cache = PresentationCache<String, Int>(capacity: 2)
        cache.insert(1, for: "A")
        cache.insert(2, for: "B")
        XCTAssertEqual(cache.value(for: "A"), 1)
        cache.insert(3, for: "C")
        XCTAssertNil(cache.value(for: "B"))
        XCTAssertEqual(Array(cache.values.keys), ["A", "C"])
    }

    func testAuditPagesAreAuthoritativeAndBounded() async throws {
        let engine = FakeAppEngine()
        engine.setFindings((0 ..< 3200).map { fixtureFinding(UInt64($0)) }, section: .fs)
        let browser = AuditFindingsBrowser(engine: engine)
        browser.select(.fs)
        try await eventually { browser.rows.count == 500 && !browser.isLoading }
        XCTAssertEqual(browser.total, 3200)
        for page in 1 ... 6 {
            browser.next()
            try await eventually { browser.offset == UInt64(page * 500) && !browser.isLoading }
            XCTAssertLessThanOrEqual(browser.rows.count, 500)
            XCTAssertLessThanOrEqual(browser.cachedRows.count, 2000)
        }
        XCTAssertEqual(browser.rows.count, 200)
        XCTAssertNil(browser.nextOffset)
        browser.previous()
        XCTAssertEqual(browser.offset, 2500)
        XCTAssertEqual(browser.rows.count, 500)
        browser.reset()
        XCTAssertTrue(browser.rows.isEmpty)
        XCTAssertTrue(browser.cachedRows.isEmpty)
        XCTAssertEqual(browser.total, 0)
    }

    func testTraceBudgetIsBounded() {
        var budget = PresentationTraceBudget(limit: 2)
        XCTAssertTrue(budget.claim())
        XCTAssertTrue(budget.claim())
        XCTAssertFalse(budget.claim())
        XCTAssertFalse(budget.claim())
        var disabled = PresentationTraceBudget(limit: -1)
        XCTAssertFalse(disabled.claim())
    }

    func testTraceRecordIncludesOnlyTimingAndNumericContext() {
        let record = PresentationTrace.record("audit.page.install", milliseconds: 1.25, run: 4, request: 7,
                                              generation: 2, revision: 9, rows: 500, cacheHit: false, mainActor: true)
        XCTAssertEqual(record, "[MacAuditTrace] event=audit.page.install elapsed_ms=1.250 run=4 request=7 generation=2 revision=9 rows=500 cache_hit=false work=main_actor\n")
    }

    func testAuditCachedSelectionInvalidatesPendingPage() async throws {
        let engine = FakeAppEngine()
        engine.setFindings([fixtureFinding(10)], section: .fs)
        let browser = AuditFindingsBrowser(engine: engine)
        browser.select(.fs)
        try await eventually { browser.rows.first?.id == 10 }
        engine.blockSection(.apps)
        browser.select(.apps)
        try await eventually { engine.blockedQueryStarted }
        browser.select(.fs)
        XCTAssertEqual(browser.rows.first?.id, 10)
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(browser.section, .fs)
        XCTAssertEqual(browser.rows.first?.id, 10)
    }

    func testAuditRootResetInvalidatesPendingPage() async throws {
        let engine = FakeAppEngine()
        engine.blockSection(.fs)
        let browser = AuditFindingsBrowser(engine: engine)
        browser.select(.fs)
        try await eventually { engine.blockedQueryStarted }
        browser.reset()
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertNil(browser.section)
        XCTAssertTrue(browser.rows.isEmpty)
        XCTAssertTrue(browser.cachedRows.isEmpty)
    }

    func testFixedDiskTargetsAreGlobalAudit() {
        XCTAssertEqual(fixtureFinding(10).auditScopeLabel, "Selected Explore root")
        XCTAssertEqual(fixtureFinding(10, metaJson: "{\"context\":\"audit_host\"}").auditScopeLabel, "Global Audit")
        XCTAssertEqual(fixtureFinding(10, metaJson: "{\"unrelated\":\"audit_host\"}").auditScopeLabel, "Selected Explore root")
    }

    func testCachedDirectoryChecksLocalNodeRevision() async throws {
        let engine = FakeAppEngine()
        let browser = DirBrowser(engine: engine)
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current?.nodeRevision == 0 && !browser.entries.isEmpty }
        engine.setNodeRevision(1)
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current?.nodeRevision == 1 && !browser.isLoading }
        XCTAssertEqual(browser.current?.path, "/fixture/A")
    }

    func testInventoryRevisionRefreshesCurrentSubjectBeforeTerminal() async throws {
        let engine = FakeAppEngine()
        let browser = DirBrowser(engine: engine)
        browser.navigate(to: "/fixture/A")
        try await eventually { !browser.entries.isEmpty }
        browser.selectedPath = "/fixture/A/child"
        engine.setNodeRevision(1)
        browser.inventoryChanged()
        try await eventually { browser.current?.nodeRevision == 1 && !browser.isLoading }
        XCTAssertEqual(browser.current?.path, "/fixture/A")
        XCTAssertEqual(browser.selectedPath, "/fixture/A/child")
    }

    func testInventoryRevisionPreservesSearchAndSelection() async throws {
        let engine = FakeAppEngine()
        let browser = DirBrowser(engine: engine)
        browser.navigate(to: "/fixture/A")
        try await eventually { !browser.entries.isEmpty }
        browser.searchText = "child"
        try await eventually { !browser.isSearching && !browser.searchResults.isEmpty }
        browser.selectedPath = "/fixture/A/child"
        engine.setNodeRevision(1)
        browser.inventoryChanged()
        try await eventually { browser.searchResults.first?.nodeRevision == 1 && !browser.isSearching }
        XCTAssertEqual(browser.searchText, "child")
        XCTAssertEqual(browser.selectedPath, "/fixture/A/child")
    }

    func testFileSearchUsesLiveObservationsWithoutChangingScannedTotals() async throws {
        let browser = DirBrowser(engine: FakeAppEngine())
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current != nil && !browser.isLoading }
        let allocation = browser.current?.alloc
        let entries = browser.entries
        browser.searchText = "child"
        try await eventually { !browser.isSearching && !browser.searchFiles.isEmpty }
        XCTAssertEqual(browser.current?.alloc, allocation)
        XCTAssertEqual(browser.entries, entries)
        XCTAssertEqual(browser.searchFiles.first?.alloc, 8_000)
        XCTAssertNotNil(browser.searchObservedAt)
        XCTAssertTrue(browser.searchCoverage.contains("partial"))
        XCTAssertTrue(browser.searchCoverage.contains("dataless"))
        let file = try XCTUnwrap(browser.searchFiles.first)
        browser.selectedPath = file.path
        XCTAssertNil(browser.selectedEntry)
        let view = NSHostingView(rootView: ExploreInspector(browser: browser))
        view.frame = NSRect(x: 0, y: 0, width: 340, height: 500)
        view.layoutSubtreeIfNeeded()
        browser.openParent(of: file)
        try await eventually { browser.current?.path == "/fixture/A" && !browser.isLoading }
        XCTAssertEqual(browser.searchText, "")
        XCTAssertTrue(browser.searchFiles.isEmpty)
        XCTAssertNotEqual(browser.current?.path, file.path)
    }

    func testSearchCancellationAndResetInvalidatePendingResponses() async throws {
        let engine = FakeAppEngine()
        engine.blockSearch()
        let browser = DirBrowser(engine: engine)
        browser.searchText = "child"
        try await eventually { engine.blockedQueryStarted }
        browser.cancelSearch()
        XCTAssertFalse(browser.isSearching)
        XCTAssertTrue(browser.searchCancelled)
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertTrue(browser.searchFiles.isEmpty)
        browser.reset()
        XCTAssertFalse(browser.searchCancelled)
        XCTAssertNil(browser.searchObservedAt)
        XCTAssertTrue(browser.searchResults.isEmpty)
    }

    func testLiveSearchRetainsCancelledPartialMatchesWithinCombinedLimit() async throws {
        let engine = FakeAppEngine()
        engine.configureSearch(fileCount: 1000, truncated: true, cancelled: true)
        let browser = DirBrowser(engine: engine)
        browser.searchText = "child"
        try await eventually { !browser.isSearching }
        XCTAssertEqual(browser.searchResults.count, 1)
        XCTAssertEqual(browser.searchFiles.count, 999)
        XCTAssertTrue(browser.searchCancelled)
        XCTAssertTrue(browser.searchTruncated)
        XCTAssertTrue(browser.searchCoverage.contains("cancelled"))
        XCTAssertNotNil(browser.searchObservedAt)
    }

    func testCachedNavigationInvalidatesPendingLoad() async throws {
        let engine = FakeAppEngine()
        let browser = DirBrowser(engine: engine)
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current?.path == "/fixture/A" && !browser.entries.isEmpty }
        engine.blockDirectory("/fixture/B")
        browser.navigate(to: "/fixture/B")
        try await eventually { engine.blockedQueryStarted }
        browser.navigate(to: "/fixture/A")
        XCTAssertFalse(browser.isLoading)
        XCTAssertEqual(browser.current?.path, "/fixture/A")
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        await Task.yield()
        XCTAssertEqual(browser.current?.path, "/fixture/A")
        XCTAssertEqual(browser.entries.first?.path, "/fixture/A/child")
    }

    func testResetInvalidatesDirectoryAndSearch() async throws {
        let engine = FakeAppEngine()
        let browser = DirBrowser(engine: engine)
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current != nil && !browser.entries.isEmpty }
        browser.selectedPath = browser.entries.first?.path
        browser.searchText = "child"
        browser.reset()
        XCTAssertNil(browser.current)
        XCTAssertNil(browser.root)
        XCTAssertNil(browser.selectedPath)
        XCTAssertTrue(browser.entries.isEmpty)
        XCTAssertTrue(browser.searchResults.isEmpty)
        XCTAssertEqual(browser.searchText, "")
        XCTAssertNil(browser.liveFilesObservedAt)
    }

    func testDirectoryPagesRejectWrongSubjectAndRun() async throws {
        for fault in [FakeAppEngine.QueryFault.directorySubject, .directoryRun] {
            let browser = DirBrowser(engine: FakeAppEngine(queryFault: fault))
            browser.navigate(to: "/fixture/A")
            try await eventually { browser.queryError != nil && !browser.isLoading }
            XCTAssertNil(browser.current)
            XCTAssertTrue(browser.entries.isEmpty)
        }
    }

    func testLivePagesRejectWrongSubjectWithoutReplacingScanRows() async throws {
        let browser = DirBrowser(engine: FakeAppEngine(queryFault: .liveSubject))
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.liveFilesError != nil && !browser.entries.isEmpty }
        XCTAssertEqual(browser.current?.path, "/fixture/A")
        XCTAssertNil(browser.liveFiles)
    }

    func testNamePagesRejectWrongQuery() async throws {
        let browser = DirBrowser(engine: FakeAppEngine(queryFault: .searchQuery))
        browser.searchText = "child"
        try await eventually { browser.queryError != nil && !browser.isSearching }
        XCTAssertTrue(browser.searchResults.isEmpty)
    }

    func testLiveFileObservationsDoNotChangeScanTreemapMass() async throws {
        let browser = DirBrowser(engine: FakeAppEngine())
        browser.navigate(to: "/fixture/A")
        try await eventually { browser.current != nil && browser.liveFilesObservedAt != nil }
        XCTAssertEqual(browser.topFiles.first?.alloc, 1_000_000)
        let scene = ExploreScene.build(current: browser.current, entries: browser.entries,
                                       incomplete: false, size: CGSize(width: 500, height: 300))
        XCTAssertEqual(scene.tiles.reduce(UInt64(0)) { $0 + $1.bytes }, 100)
        XCTAssertFalse(scene.tiles.contains { $0.id == browser.topFiles.first?.path })
    }

    func testCachedOwnerInvalidatesPendingFootprint() async throws {
        let engine = FakeAppEngine()
        let browser = OwnerBrowser(axis: .projects, engine: engine)
        browser.open(fixtureFinding(10))
        try await eventually { browser.footprint?.finding == 10 }
        engine.blockOwner(20)
        browser.open(fixtureFinding(20))
        try await eventually { engine.blockedQueryStarted }
        browser.open(fixtureFinding(10))
        XCTAssertEqual(browser.footprint?.finding, 10)
        XCTAssertFalse(browser.isLoading)
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(browser.selectedOwner?.id, 10)
        XCTAssertEqual(browser.footprint?.finding, 10)
    }

    func testPlanningPreventsRootChangeAndRefresh() async throws {
        let engine = FakeAppEngine()
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        engine.blockPlanning()
        store.marked = [10]
        store.openConfirm()
        XCTAssertFalse(store.canRefresh)
        try await eventually { engine.blockedQueryStarted }
        let root = store.selectedRoot
        store.changeRoot("/fixture/B")
        store.rescanAll()
        XCTAssertEqual(store.selectedRoot, root)
        XCTAssertEqual(engine.runCount, 0)
        engine.releaseQueries()
        try await eventually { store.canRefresh }
        XCTAssertNil(store.sheetRoute)
    }

    func testRootChangePreservesPresentationUntilAcceptedThenClears() async throws {
        let engine = FakeAppEngine()
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.rescanAll()
        try await eventually { engine.runCount == 1 && store.canRefresh }
        store.browser.navigate(to: "/fixture/A")
        try await eventually { store.browser.current != nil }
        store.owners[.projects]?.open(fixtureFinding(10))
        store.selectedFinding = 10
        store.searchText = "old root"
        engine.blockRun("/fixture/B")
        store.changeRoot("/fixture/B")
        try await eventually { engine.blockedQueryStarted }
        XCTAssertEqual(store.selectedRoot, "/fixture")
        XCTAssertEqual(store.browser.current?.path, "/fixture/A")
        XCTAssertEqual(store.selectedFinding, 10)
        XCTAssertEqual(store.searchText, "old root")
        XCTAssertFalse(store.canRefresh)
        store.marked = [10]
        store.openConfirm()
        store.changeRoot("/fixture/C")
        store.cancelScan()
        XCTAssertFalse(store.isPlanning)
        XCTAssertEqual(engine.cancelCount, 0)
        engine.releaseQueries()
        try await eventually { store.canRefresh && engine.runCount == 2 }
        XCTAssertEqual(store.selectedRoot, "/fixture/B")
        XCTAssertNil(store.browser.current)
        XCTAssertTrue(store.browser.entries.isEmpty)
        XCTAssertTrue(store.browser.topFiles.isEmpty)
        XCTAssertNil(store.owners[.projects]?.selectedOwner)
        XCTAssertNil(store.selectedFinding)
        XCTAssertEqual(store.searchText, "")
        store.cancelScan()
    }

    func testInvalidRootPreservesOldRunAndResultsWithoutCancellation() async throws {
        let engine = FakeAppEngine()
        engine.setFindings([fixtureFinding(10)], section: .fs)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.rescanAll()
        try await eventually { engine.runCount == 1 && store.canRefresh }
        store.selectedItem = .section(.fs)
        try await eventually { store.finding(10) != nil }
        store.browser.navigate(to: "/fixture/A")
        try await eventually { store.browser.current != nil }
        store.selectedFinding = 10
        store.toggleMark(10)
        let oldStatus = store.status(of: .fs)
        engine.rejectRun("/fixture/missing")
        store.changeRoot("/fixture/missing")
        try await eventually { store.rootError != nil && store.canRefresh }
        XCTAssertEqual(store.selectedRoot, "/fixture")
        XCTAssertEqual(engine.selectedRoot(), "/fixture")
        XCTAssertEqual(engine.runCount, 1)
        XCTAssertEqual(engine.cancelCount, 0)
        XCTAssertEqual(store.browser.current?.path, "/fixture/A")
        XCTAssertEqual(store.finding(10)?.id, 10)
        XCTAssertEqual(store.selectedFinding, 10)
        XCTAssertTrue(store.marked.contains(10))
        XCTAssertEqual(store.status(of: .fs), oldStatus)
        store.cancelScan()
    }

    func testRelativeRootRequestUsesConfiguredHome() async throws {
        let engine = FakeAppEngine()
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture/other",
                               homeRoot: "/fixture/home")
        store.changeRoot("cf-repos")
        try await eventually { store.canRefresh && engine.runCount == 1 }
        XCTAssertEqual(store.selectedRoot, "/fixture/home/cf-repos")
        XCTAssertEqual(engine.selectedRoot(), "/fixture/home/cf-repos")
        store.cancelScan()
    }

    func testAcceptedRunActivatesBufferedCallbacks() async throws {
        let engine = FakeAppEngine(emitsScanEvents: true)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.changeRoot("/fixture/B")
        try await eventually { store.status(of: .fs) == .done(durationMs: 1) }
        XCTAssertEqual(store.selectedRoot, "/fixture/B")
        XCTAssertEqual(engine.runCount, 1)
        XCTAssertTrue(store.canRefresh)
        store.cancelScan()
    }

    func testOwnerLandingInvalidatesPendingFootprint() async throws {
        let engine = FakeAppEngine()
        let browser = OwnerBrowser(axis: .projects, engine: engine)
        engine.blockOwner(10)
        browser.open(fixtureFinding(10))
        try await eventually { engine.blockedQueryStarted }
        browser.closeToLanding()
        XCTAssertFalse(browser.isLoading)
        engine.releaseQueries()
        try await eventually { engine.blockedQueryReturned }
        try await Task.sleep(for: .milliseconds(20))
        XCTAssertNil(browser.selectedOwner)
        XCTAssertNil(browser.footprint)
    }

    func testFullRefreshClearsAllPresentationOnAcceptance() async throws {
        let engine = FakeAppEngine()
        engine.setFindings([fixtureFinding(10)], section: .fs)
        let store = AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture")
        store.rescanAll()
        try await eventually { engine.runCount == 1 && store.canRefresh }
        store.selectedItem = .section(.fs)
        try await eventually { store.finding(10) != nil }
        store.toggleMark(10)
        store.remedyChoice = [10: 0]
        store.selectedFinding = 10
        store.owners[.projects]?.open(fixtureFinding(10))
        store.selectedItem = nil
        store.rescanAll()
        try await eventually { engine.runCount == 2 && store.canRefresh }
        XCTAssertTrue(store.findings.isEmpty)
        XCTAssertTrue(store.marked.isEmpty)
        XCTAssertTrue(store.remedyChoice.isEmpty)
        XCTAssertNil(store.selectedFinding)
        XCTAssertNil(store.owners[.projects]?.selectedOwner)
        XCTAssertNil(store.browser.root)
        XCTAssertNil(store.pendingPlan)
        XCTAssertNil(store.sheetRoute)
        store.apply(.enriched(gen: 1, findings: [fixtureFinding(10)]))
        XCTAssertTrue(store.findings.isEmpty)
        store.cancelScan()
    }

    func testCoordinatorLaunchesOnlyOnce() async throws {
        let engine = FakeAppEngine()
        let coordinator = ApplicationCoordinator(store: AuditStore(engine: engine, usingFakeData: true, initialRoot: "/fixture"))
        coordinator.start()
        coordinator.start()
        try await eventually { engine.runCount == 1 && coordinator.store.canRefresh }
        XCTAssertTrue(coordinator.didStart)
        XCTAssertEqual(engine.runCount, 1)
        XCTAssertEqual(engine.selectedRoot(), "/fixture")
        coordinator.store.cancelScan()
    }

    func testTreemapConservesDirectFilesAndResidualMass() {
        let current = fixtureDirectory("/fixture", bytes: 1000)
        let child = fixtureDirectory("/fixture/A", bytes: 400)
        let scene = ExploreScene.build(current: current, entries: [child],
                                       incomplete: false,
                                       size: CGSize(width: 1000, height: 500))
        XCTAssertEqual(scene.tiles.reduce(UInt64(0)) { $0 + $1.bytes }, 1000)
        XCTAssertEqual(scene.tiles.first { $0.kind == .residual }?.bytes, 600)
        XCTAssertEqual(scene.tiles.first { $0.kind == .residual }?.title, "Other direct files")
        XCTAssertEqual(scene.tiles.reduce(0.0) { $0 + $1.rect.width * $1.rect.height }, 500_000, accuracy: 0.001)
        XCTAssertEqual(scene.tiles.first { $0.id == child.path }?.rect.width ?? 0 > 0, true)
    }

    func testTreemapBudgetsAndIncompleteLabel() {
        let rows = (0 ..< 4000).map { fixtureDirectory("/fixture/\($0)", bytes: 1) }
        let scene = ExploreScene.build(current: fixtureDirectory("/fixture", bytes: 5000),
                                       entries: rows, incomplete: true, size: CGSize(width: 1000, height: 800))
        XCTAssertLessThanOrEqual(scene.tiles.count, 2048)
        XCTAssertLessThanOrEqual(scene.labels.count, 128)
        XCTAssertEqual(scene.tiles.reduce(UInt64(0)) { $0 + $1.bytes }, 5000)
        XCTAssertEqual(scene.tiles.last?.title, "Other folders and direct files")
    }

    func testTreemapPresentationSnapshot() {
        let scene = ExploreScene.build(current: fixtureDirectory("/fixture", bytes: 100),
                                       entries: [fixtureDirectory("/fixture/A", bytes: 40)],
                                       incomplete: false,
                                       size: CGSize(width: 500, height: 300))
        let description = scene.tiles.map { "\($0.title):\($0.bytes):\($0.kind.rawValue)" }.joined(separator: "\n") + "\n"
        assertSnapshot(of: description, as: .lines)
    }

    private func eventually(_ condition: @MainActor () -> Bool) async throws {
        for _ in 0 ..< 400 {
            if condition() {
                return
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("Timed out waiting for the fake-engine state transition")
        throw FakeFailure.timeout
    }
}

private enum FakeFailure: Error { case timeout, unavailable }

func fixtureDirectory(_ path: String, bytes: UInt64 = 100, nodeRevision: UInt64 = 0,
                      files: UInt64 = 1, dirs: UInt64 = 1) -> DirEntry
{
    DirEntry(path: path, name: (path as NSString).lastPathComponent, nodeRevision: nodeRevision, alloc: bytes,
             apparent: bytes, files: files, dirs: dirs, errors: 0, hasChildren: true)
}

func fixtureFinding(_ id: UInt64, metaJson: String = "{}", path: String = "/fixture/A", detail: String = "") -> Finding {
    Finding(id: id, kind: .largeFile, section: .fs, group: "Fixture", title: "Fixture \(id)",
            detail: detail, path: path, sizeBytes: 100, lastUsed: nil, severity: .info,
            remedies: [], provenance: nil, coverage: nil, metaJson: metaJson)
}

final class FakeAppEngine: MacAuditEngine, @unchecked Sendable {
    enum QueryFault: Equatable, Sendable { case directorySubject, directoryRun, liveSubject, searchQuery }
    private let renderedFixture: Bool
    private let queryFault: QueryFault?
    private let emitsScanEvents: Bool
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private var blockPath: String?
    private var blockFinding: UInt64?
    private var blockAuditSection: SectionId?
    private var auditFindings: [SectionId: [Finding]] = [:]
    private var planningBlocked = false
    private var blockedRunRoot: String?
    private var rejectedRunRoot: String?
    private var cancellations = 0
    private var queryStarted = false
    private var queryReturned = false
    private var runs = 0
    private var rootPath = "/fixture"
    private var nodeRevision: UInt64 = 0
    private var requestCount: UInt64 = 0
    private var activeScanners: UInt64 = 0
    private var runCancelled = false
    private var searchBlocked = false
    private var searchFileCount = 1
    private var searchIsTruncated = false
    private var searchIsCancelled = false
    private var listeners: [UInt64: any ScanListener] = [:]

    init(renderedFixture: Bool = false, queryFault: QueryFault? = nil, emitsScanEvents: Bool = false) {
        self.renderedFixture = renderedFixture
        self.queryFault = queryFault
        self.emitsScanEvents = emitsScanEvents
    }

    var blockedQueryStarted: Bool {
        lock.withLock { queryStarted }
    }

    var blockedQueryReturned: Bool {
        lock.withLock { queryReturned }
    }

    var runCount: Int {
        lock.withLock { runs }
    }

    var cancelCount: Int {
        lock.withLock { cancellations }
    }

    func blockRun(_ root: String) {
        lock.withLock { blockedRunRoot = root }
    }

    func rejectRun(_ root: String) {
        lock.withLock { rejectedRunRoot = root }
    }

    func blockDirectory(_ path: String) {
        lock.withLock { blockPath = path }
    }

    func blockOwner(_ id: UInt64) {
        lock.withLock { blockFinding = id }
    }

    func blockSection(_ section: SectionId) {
        lock.withLock { blockAuditSection = section }
    }

    func blockSearch() {
        lock.withLock { searchBlocked = true }
    }

    func configureSearch(fileCount: Int, truncated: Bool, cancelled: Bool) {
        lock.withLock {
            searchFileCount = fileCount
            searchIsTruncated = truncated
            searchIsCancelled = cancelled
        }
    }

    func setFindings(_ findings: [Finding], section: SectionId) {
        lock.withLock { auditFindings[section] = findings }
    }

    func setActiveScanners(_ count: UInt64) {
        lock.withLock { activeScanners = count }
    }

    func emitScanEvent(_ event: ScanEvent) {
        let listener = lock.withLock {
            if case let .findings(section, _, batch) = event, event.runId == UInt64(runs) {
                for finding in batch {
                    auditFindings[section, default: []].removeAll { $0.id == finding.id }
                    auditFindings[section, default: []].append(finding)
                }
            }
            return listeners[event.runId]
        }
        listener?.onEvent(event: event)
    }

    func blockPlanning() {
        lock.withLock { planningBlocked = true }
    }

    func setNodeRevision(_ revision: UInt64) {
        lock.withLock { nodeRevision = revision }
    }

    func releaseQueries() {
        lock.withLock { blockAuditSection = nil; searchBlocked = false }
        gate.signal()
    }

    private func blockIfNeeded(_ shouldBlock: Bool) {
        guard shouldBlock else { return }
        lock.withLock { queryStarted = true }
        _ = gate.wait(timeout: .now() + 3)
        lock.withLock { queryReturned = true }
    }

    func selectedRoot() -> String {
        lock.withLock { rootPath }
    }

    func sessionMetadata() -> SessionMetadata {
        makeSessionMetadata(runId: UInt64(runCount))
    }

    private func makeSessionMetadata(runId: UInt64) -> SessionMetadata {
        let (cancelled, active) = lock.withLock { (runCancelled, activeScanners) }
        return SessionMetadata(runId: runId, selectedRoot: selectedRoot(), revision: 0,
                        startedAtMs: 0, queriedAtMs: 0, diskComplete: !cancelled, diskErrors: 0,
                        diskElapsedMs: 0, auditComplete: !cancelled, cancelled: cancelled,
                        diskCoverage: cancelled ? "cancelled" : "complete", auditCoverage: cancelled ? "cancelled" : "complete",
                        walkCoverage: WalkCoverage(unreadable: 0, excluded: 0, dataless: 0, aliases: 0,
                                                   mounts: 0, cancelled: cancelled, resourceLimited: false, summariesTruncated: false,
                                                   deadline: false, entryLimit: false, unsupportedPaths: 0), diskStopReasons: cancelled ? ["cancelled"] : [], auditStopReasons: cancelled ? ["cancelled"] : [],
                        activeScanners: active, retiringCount: 0, retiringRuns: [], queryMemory: nil)
    }

    private func nextRequestId() -> UInt64 {
        lock.withLock { requestCount += 1; return requestCount }
    }

    func setRoot(root: String) throws {
        lock.withLock { rootPath = root }
    }

    func startRun(root: String, listener: any ScanListener) throws -> UInt64 {
        guard root == "/fixture" || root.hasPrefix("/fixture/") else { throw FakeFailure.unavailable }
        blockIfNeeded(lock.withLock { blockedRunRoot == root })
        guard !lock.withLock({ rejectedRunRoot == root }) else { throw FakeFailure.unavailable }
        try setRoot(root: root)
        return startScan(sections: SectionId.allCases, listener: listener)
    }

    func sections() -> [SectionMeta] {
        SectionId.allCases.map { SectionMeta(id: $0, slug: $0.slug, title: $0.slug, shortTitle: $0.slug, view: .table) }
    }

    func deleteMode() -> DeleteMode {
        .trash
    }

    func configPath() -> String {
        "/fixture/config"
    }

    func fullDiskAccess() -> Bool {
        true
    }

    func startScan(sections _: [SectionId], listener: any ScanListener) -> UInt64 {
        let runId = lock.withLock {
            runs += 1
            runCancelled = false
            listeners[UInt64(runs)] = listener
            return UInt64(runs)
        }
        if emitsScanEvents {
            listener.onEvent(event: .sectionStarted(section: .fs, gen: runId))
            listener.onEvent(event: .sectionFinished(section: .fs, gen: runId, durationMs: 1))
        }
        return runId
    }

    func cancelScan() {
        lock.withLock { cancellations += 1; runCancelled = true }
    }

    func sectionSummary(section: SectionId, runId: UInt64) throws -> SectionSummary {
        let metadata = sessionMetadata()
        guard metadata.runId == runId else { throw FakeFailure.unavailable }
        return SectionSummary(metadata: metadata, section: section, total: UInt64(findings(section: section).count),
                              reportedBytes: 0, terminal: metadata.cancelled && metadata.activeScanners == 0,
                              error: metadata.cancelled ? "run cancelled" : nil)
    }

    func findings(section: SectionId) -> [Finding] {
        blockIfNeeded(lock.withLock { blockAuditSection == section })
        return lock.withLock { auditFindings[section] ?? [] }
    }

    func plan(selection _: [Selection]) throws -> Plan {
        blockIfNeeded(lock.withLock { planningBlocked })
        throw FakeFailure.unavailable
    }

    func execute(plan _: Plan, listener _: any ExecListener) throws {
        throw FakeFailure.unavailable
    }

    func cancelCleanup() {}
    func dirRoot() -> DirEntry? {
        fixtureDirectory(selectedRoot(), nodeRevision: lock.withLock { nodeRevision }, files: renderedFixture ? 3 : 1,
                         dirs: renderedFixture ? 2 : 1)
    }

    func dirEntry(path: String) -> DirEntry? {
        fixtureDirectory(path, nodeRevision: lock.withLock { nodeRevision }, files: renderedFixture ? 3 : 1,
                         dirs: renderedFixture ? 2 : 1)
    }

    func dirAncestors(path: String) -> [DirEntry] {
        [fixtureDirectory("/fixture"), fixtureDirectory(path)]
    }

    func dirChildren(path: String) -> [DirEntry] {
        blockIfNeeded(lock.withLock { blockPath == path })
        if renderedFixture {
            return [fixtureDirectory(path + "/Projects", bytes: 40),
                    fixtureDirectory(path + "/Caches", bytes: 30)]
        }
        return [fixtureDirectory(path + "/child")]
    }

    func dirSubtree(path _: String, depth _: UInt32, maxNodes _: UInt32) -> [DirEntry] {
        []
    }

    func dirChildrenPage(path: String, offset: UInt64, limit: UInt32) throws -> DirectoryPage {
        let children = dirChildren(path: path)
        let entries = Array(children.dropFirst(Int(offset)).prefix(Int(limit)))
        let end = offset + UInt64(entries.count)
        let metadata = queryFault == .directoryRun ? makeSessionMetadata(runId: UInt64(runCount) + 1) : sessionMetadata()
        return DirectoryPage(requestId: nextRequestId(), subjectPath: queryFault == .directorySubject ? "/fixture/wrong" : path,
                             metadata: metadata, entries: entries, nextOffset: end < UInt64(children.count) ? end : nil,
                             truncated: end < UInt64(children.count))
    }

    func nameSearch(query: String, limit: UInt32, cancellation: QueryCancellation) throws -> DirectorySearchPage {
        blockIfNeeded(lock.withLock { searchBlocked })
        let entry = fixtureDirectory("/fixture/A/child", nodeRevision: lock.withLock { nodeRevision })
        let entries = entry.name.contains(query) && limit > 0 && !cancellation.isCancelled() ? [entry] : []
        let (count, truncated, cancelled) = lock.withLock { (searchFileCount, searchIsTruncated, searchIsCancelled) }
        let files = query.localizedCaseInsensitiveContains("child") && !cancellation.isCancelled()
            ? (0..<count).map { TopFile(path: selectedRoot() + "/A/child-file\($0)", alloc: 8_000) } : []
        return DirectorySearchPage(requestId: nextRequestId(), query: queryFault == .searchQuery ? "wrong" : query,
                                   metadata: sessionMetadata(), entries: entries,
                                   files: files, observedAtMs: 1_790_883_000_000,
                                   coverage: cancelled ? "cancelled" : "partial", stopReasons: ["dataless"],
                                   truncated: truncated, cancelled: cancelled || cancellation.isCancelled())
    }

    func dirTopFiles(path: String, n _: UInt32) -> [TopFile] {
        [TopFile(path: path + "/live-file", alloc: 1_000_000)]
    }

    func liveFilesPage(path: String, limit: UInt32) throws -> LiveFilesPage {
        LiveFilesPage(requestId: nextRequestId(), subjectPath: queryFault == .liveSubject ? "/fixture/wrong" : path,
                      metadata: sessionMetadata(), observedAtMs: 1_790_883_000_000,
                      coverage: "partial", files: dirTopFiles(path: path, n: limit), dataless: 2,
                      errors: 0, truncated: false, stopReasons: ["dataless"])
    }

    func largestFiles(n _: UInt32) -> [TopFile] {
        []
    }

    func dirTreeStats() -> DirTreeStats? {
        DirTreeStats(root: selectedRoot(), files: 3,
                     directoryEntries: renderedFixture ? 4 : nil,
                     externallyLinkedBytes: renderedFixture ? 20 : nil,
                     dirs: 2, bytes: 100, errors: 0, complete: renderedFixture,
                     elapsedMs: 10, coverage: sessionMetadata().walkCoverage)
    }

    func footprint(findingId: UInt64) -> Footprint? {
        blockIfNeeded(lock.withLock { blockFinding == findingId })
        return Footprint(finding: findingId, owner: Owner(key: "fixture-\(findingId)", kind: .project,
                                                          name: "Fixture", path: "/fixture"), exclusive: 100, shared: 0, reach: 100,
                         baselineShare: 0, groups: [], worktrees: [], processes: [], ports: [], cloneNote: false, queryMemory: nil)
    }

    func footprintBuckets(axis _: MacAuditKit.Axis) -> FootprintBuckets? {
        nil
    }
}
