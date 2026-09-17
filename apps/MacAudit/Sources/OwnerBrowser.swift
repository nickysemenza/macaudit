import Foundation
import MacAuditKit

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

    /// The lens landing page's presentation: a sortable table, or a
    /// squarified treemap. Persisted per axis across launches.
    enum ViewMode: String, CaseIterable {
        case list, treemap
    }

    private let viewModeDefaultsKey: String

    var viewMode: ViewMode {
        didSet {
            UserDefaults.standard.set(viewMode.rawValue, forKey: viewModeDefaultsKey)
        }
    }

    /// The owner whose entity page (`OwnerDetailView`) is open, `nil` on
    /// the lens landing page.
    private(set) var selectedOwner: Finding?
    /// `selectedOwner`'s footprint. `nil` while loading *or* while the axis
    /// hasn't resolved this owner yet — `AuditStore` retries via `refresh()`
    /// whenever the section (re)finishes, same as `DirBrowser.refreshRoot()`
    /// for `.fs`.
    private(set) var footprint: Footprint?
    private(set) var isLoading = false
    var selectedEntry: FootprintEntry?

    /// This axis's coverage buckets (Baseline/Unattributed rows, totals) —
    /// independent of which owner (if any) is open.
    private(set) var buckets: FootprintBuckets?

    /// Previously open owners, for the entity page's Back button. `open(_:)`
    /// pushes the current owner before switching; `goBack()` pops one level,
    /// or returns to the landing page once the stack is empty.
    private var back: [Finding] = []

    private var loadGeneration: UInt64 = 0

    init(axis: AttributionAxis, engine: any MacAuditEngine) {
        self.axis = axis
        self.engine = engine
        self.viewModeDefaultsKey = "lensViewMode.\(axis == .projects ? "projects" : "appStorage")"
        if let raw = UserDefaults.standard.string(forKey: viewModeDefaultsKey),
            let mode = ViewMode(rawValue: raw)
        {
            self.viewMode = mode
        } else {
            self.viewMode = .list
        }
    }

    /// Re-fetches this axis's coverage buckets, off-main. Safe to call
    /// repeatedly (the lens landing page calls it on appear).
    func refreshBuckets() {
        let engine = self.engine
        let axis = self.axis
        Task { [weak self] in
            let result = await Task.detached { engine.footprintBuckets(axis: axis) }.value
            self?.buckets = result
        }
    }

    /// Opens `owner`'s entity page, pushing whatever was open onto the back
    /// stack.
    func open(_ owner: Finding) {
        if let current = selectedOwner, current.id != owner.id {
            back.append(current)
        }
        selectedOwner = owner
        selectedEntry = nil
        load(owner)
    }

    /// One level back: the previous owner, or the landing page once the
    /// stack is empty.
    func goBack() {
        selectedEntry = nil
        if let previous = back.popLast() {
            selectedOwner = previous
            load(previous)
        } else {
            selectedOwner = nil
            footprint = nil
        }
    }

    var canGoBack: Bool { selectedOwner != nil }

    /// Returns straight to the lens landing page, discarding any back-stack
    /// depth — the breadcrumb bar's axis-name crumb.
    func closeToLanding() {
        back.removeAll()
        selectedOwner = nil
        footprint = nil
        selectedEntry = nil
    }

    /// Jumps directly to a breadcrumb entry — pops the back stack down to
    /// (and including) `owner`, instead of the single-level `goBack()`.
    func openBreadcrumb(_ owner: Finding) {
        guard owner.id != selectedOwner?.id else { return }
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
        (back + [selectedOwner]).compactMap { $0 }
    }

    /// Re-fetches the coverage buckets and, if an owner is open, its
    /// footprint — called after this axis's section (re)finishes.
    func refresh() {
        refreshBuckets()
        if let owner = selectedOwner {
            load(owner)
        }
    }

    private func load(_ owner: Finding) {
        isLoading = true
        loadGeneration += 1
        let generation = loadGeneration
        let engine = self.engine
        let id = owner.id
        Task { [weak self] in
            let result = await Task.detached { engine.footprint(findingId: id) }.value
            guard let self, self.loadGeneration == generation else { return }
            self.footprint = result
            self.isLoading = false
        }
    }
}
