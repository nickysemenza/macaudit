import Foundation
import MacAuditCollections
import MacAuditKit

private struct OwnerPresentation {
    var footprint: Footprint
    var runId: UInt64
    var revision: UInt64
}

/// Drill-down state for one attribution lens (Projects or App Storage): the
/// open owner's `Footprint` (fetched on demand), the axis's coverage
/// `FootprintBuckets`, and the list/treemap view mode. Mirrors `DirBrowser`'s
/// relationship to the engine — a small `@Observable` model the views bind
/// to directly. `AuditStore` owns one per axis (`store.owners[axis]`).
@MainActor
@Observable
final class OwnerBrowser {
    let axis: AttributionAxis
    let engine: any MacAuditEngine
    private let queries: MacAuditQueries

    /// The lens landing page's presentation: a sortable table, or a
    /// squarified treemap. Kept in memory for this app session only.
    enum ViewMode: String, CaseIterable {
        case list, treemap
    }

    var viewMode: ViewMode = .list

    /// The owner whose entity page (`OwnerDetailView`) is open, `nil` on
    /// the lens landing page.
    private(set) var selectedOwner: Finding?
    /// `selectedOwner`'s footprint. `nil` while loading *or* while the axis
    /// hasn't resolved this owner yet — `AuditStore` retries via `refresh()`
    /// whenever the section (re)finishes, same as `DirBrowser.refreshRoot()`
    /// for `.fs`.
    private(set) var footprint: Footprint?
    private(set) var isLoading = false
    private(set) var isLoadingEntries = false
    private(set) var totalEntries: UInt64 = 0
    private(set) var entriesError: String?
    private(set) var nextEntriesCursor: FootprintCursor?
    private var entries: OrderedDictionary<String, FootprintEntry> = [:]
    private var entriesMetadata: [SessionMetadata] = []
    static let entryLimit = 2048
    var selectedEntry: FootprintEntry?

    /// This axis's coverage buckets (Baseline/Unattributed rows, totals) —
    /// independent of which owner (if any) is open.
    private(set) var buckets: FootprintBuckets?

    /// Previously open owners, for the entity page's Back button. `open(_:)`
    /// pushes the current owner before switching; `goBack()` pops one level,
    /// or returns to the landing page once the stack is empty.
    private var back: [Finding] = []

    private var loadGeneration: UInt64 = 0
    private var bucketGeneration: UInt64 = 0
    private var loadTask: Task<Void, Never>?
    private var bucketTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?
    private var cache = PresentationCache<UInt64, OwnerPresentation>(capacity: 8)

    var displayedGroups: [FootprintGroup] {
        guard let footprint else { return [] }
        guard !entries.isEmpty else { return footprint.groups }
        let grouped = Dictionary(grouping: entries.values, by: \.kind)
        return footprint.groups.map { FootprintGroup(kind: $0.kind, bytes: $0.bytes, entries: grouped[$0.kind] ?? []) }
    }

    var loadedEntryCount: Int {
        entries.isEmpty ? footprint?.groups.reduce(0) { $0 + $1.entries.count } ?? 0 : entries.count
    }

    init(axis: AttributionAxis, engine: any MacAuditEngine) {
        self.axis = axis
        self.engine = engine
        queries = MacAuditQueries(engine: engine)
    }

    /// Re-fetches this axis's coverage buckets, off-main. Safe to call
    /// repeatedly (the lens landing page calls it on appear).
    func refreshBuckets() {
        bucketGeneration &+= 1
        let generation = bucketGeneration
        bucketTask?.cancel()
        let queries = queries
        let axis = axis
        bucketTask = Task { [weak self] in
            let metadata = await queries.metadata()
            let result = await queries.footprintBuckets(axis: axis, runId: metadata.runId)
            guard let self, bucketGeneration == generation, !Task.isCancelled else { return }
            buckets = result
        }
    }

    /// Opens `owner`'s entity page, pushing whatever was open onto the back
    /// stack.
    func open(_ owner: Finding) {
        if let current = selectedOwner, current.id != owner.id {
            back.append(current)
            if back.count > 64 {
                back.removeFirst()
            }
        }
        selectedOwner = owner
        selectedEntry = nil
        load(owner)
    }

    /// One level back: the previous owner, or the landing page once the
    /// stack is empty.
    func goBack() {
        invalidateLoad()
        selectedEntry = nil
        if let previous = back.popLast() {
            selectedOwner = previous
            load(previous)
        } else {
            selectedOwner = nil
            footprint = nil
        }
    }

    var canGoBack: Bool {
        selectedOwner != nil
    }

    /// Returns straight to the lens landing page, discarding any back-stack
    /// depth — the breadcrumb bar's axis-name crumb.
    func closeToLanding() {
        invalidateLoad()
        back.removeAll()
        selectedOwner = nil
        footprint = nil
        selectedEntry = nil
    }

    /// Jumps directly to a breadcrumb entry — pops the back stack down to
    /// (and including) `owner`, instead of the single-level `goBack()`.
    func openBreadcrumb(_ owner: Finding) {
        if let index = back.firstIndex(where: { $0.id == owner.id }) {
            back.removeSubrange(index...)
        }
        selectedOwner = owner
        selectedEntry = nil
        load(owner)
    }

    /// Every open owner from the landing page down to the current one, for
    /// the entity page's breadcrumb bar.
    var breadcrumbs: [Finding] {
        (back + [selectedOwner]).compactMap(\.self)
    }

    /// Re-fetches the coverage buckets and, if an owner is open, its
    /// footprint — called after this axis's section (re)finishes.
    func refresh() {
        cache.removeAll()
        refreshBuckets()
        if let owner = selectedOwner {
            load(owner)
        }
    }

    func inventoryChanged() {
        cache.removeAll()
        guard refreshTask == nil else { return }
        refreshTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(150)) } catch { return }
            guard let self else { return }
            refreshTask = nil
            refresh()
        }
    }

    private func load(_ owner: Finding) {
        invalidateLoad()
        let generation = loadGeneration
        footprint = nil
        if let cached = cache.value(for: owner.id) {
            let started = PresentationTrace.start()
            footprint = cached.footprint
            PresentationTrace.finish("audit.owner.cache", since: started, run: cached.runId,
                                     generation: generation, revision: cached.revision,
                                     cacheHit: true, mainActor: true)
            let queries = queries
            loadTask = Task { [weak self] in
                let metadata = await queries.metadata()
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                if cached.runId != metadata.runId || cached.revision != metadata.revision {
                    cache.removeAll()
                    load(owner)
                } else {
                    await loadFirstEntries(owner: owner, generation: generation, runId: metadata.runId)
                }
            }
            return
        }
        isLoading = true
        let queries = queries
        let id = owner.id
        loadTask = Task { [weak self] in
            let started = PresentationTrace.start()
            let metadata = await queries.metadata()
            let result = await queries.footprint(findingId: id, runId: metadata.runId)
            PresentationTrace.finish("audit.owner.query", since: started, run: metadata.runId,
                                     generation: generation, revision: metadata.revision, cacheHit: false)
            guard let self, loadGeneration == generation, !Task.isCancelled else { return }
            if let result {
                cache.insert(OwnerPresentation(footprint: result, runId: metadata.runId,
                                               revision: metadata.revision), for: id)
            }
            footprint = result
            isLoading = false
            if result != nil {
                await loadFirstEntries(owner: owner, generation: generation, runId: metadata.runId)
            }
        }
    }

    private func loadFirstEntries(owner: Finding, generation: UInt64, runId: UInt64) async {
        isLoadingEntries = true
        do {
            let page = try await queries.footprintEntries(findingId: owner.id, runId: runId, limit: 500)
            guard loadGeneration == generation, !Task.isCancelled else { return }
            entries.removeAll()
            entriesMetadata = [page.metadata]
            for entry in page.entries.prefix(Self.entryLimit) {
                entries[entry.path] = entry
            }
            totalEntries = page.total
            nextEntriesCursor = page.nextCursor
            isLoadingEntries = false
        } catch {
            guard loadGeneration == generation, !Task.isCancelled else { return }
            entriesError = "\(error)"
            isLoadingEntries = false
        }
    }

    func loadMoreEntries() {
        guard let cursor = nextEntriesCursor, !isLoadingEntries, entries.count < Self.entryLimit else { return }
        let generation = loadGeneration
        let queries = queries
        let limit = UInt32(min(500, Self.entryLimit - entries.count))
        isLoadingEntries = true
        loadTask = Task { [weak self] in
            do {
                let page = try await queries.footprintEntries(cursor: cursor, limit: limit)
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                for entry in page.entries.prefix(Self.entryLimit - entries.count) {
                    entries[entry.path] = entry
                }
                entriesMetadata.append(page.metadata)
                totalEntries = page.total
                nextEntriesCursor = page.nextCursor
                isLoadingEntries = false
            } catch {
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                entriesError = "\(error)"
                isLoadingEntries = false
            }
        }
    }

    func reset() {
        refreshTask?.cancel()
        refreshTask = nil
        closeToLanding()
        bucketGeneration &+= 1
        bucketTask?.cancel()
        buckets = nil
        cache.removeAll()
    }

    private func invalidateLoad() {
        loadGeneration &+= 1
        loadTask?.cancel()
        isLoading = false
        isLoadingEntries = false
        entriesError = nil
        totalEntries = 0
        nextEntriesCursor = nil
        entries.removeAll()
        entriesMetadata = []
        selectedEntry = nil
    }
}
