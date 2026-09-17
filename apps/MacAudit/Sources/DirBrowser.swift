import Foundation
import MacAuditKit

/// Drill-down state for the Folders browser: the current directory, its
/// children (sorted by the user's chosen column), and back/up navigation.
/// Mirrors `AuditStore`'s relationship to the engine — a small
/// `@Observable` model the views bind to directly.
@MainActor
@Observable
final class DirBrowser {
    /// How the current directory's children are displayed. Not `private` —
    /// `TreemapView` needs it for `dirSubtree` lookups off-main.
    let engine: any MacAuditEngine

    /// The Folders drill-down's presentation: a sortable table, or a
    /// squarified treemap. Persisted across launches.
    enum ViewMode: String, CaseIterable {
        case list, treemap
    }

    private static let viewModeDefaultsKey = "foldersViewMode"

    var viewMode: ViewMode {
        didSet {
            UserDefaults.standard.set(viewMode.rawValue, forKey: Self.viewModeDefaultsKey)
        }
    }

    private(set) var root: DirEntry?
    private(set) var current: DirEntry?
    private(set) var entries: [DirEntry] = []
    private(set) var isLoading = false

    var selectedPath: String?
    var sortOrder: [KeyPathComparator<DirEntry>] = [.init(\.alloc, order: .reverse)]

    /// Children by path, so revisiting a folder (breadcrumb, back, up) is
    /// instant. Cleared on `invalidate()`.
    private var cache: [String: [DirEntry]] = [:]
    private var back: [String] = []
    /// Bumped on every `navigate(to:)`; a load only commits if it is still
    /// the most recent one requested (guards against a slow lookup for a
    /// folder the user already left landing after a faster, later one).
    private var loadGeneration: UInt64 = 0

    init(engine: any MacAuditEngine) {
        self.engine = engine
        if let raw = UserDefaults.standard.string(forKey: Self.viewModeDefaultsKey),
            let mode = ViewMode(rawValue: raw)
        {
            self.viewMode = mode
        } else {
            self.viewMode = .list
        }
    }

    /// Re-reads the scan root. Called after the fs section (re)finishes.
    func refreshRoot() {
        root = engine.dirRoot()
        if current == nil, let root {
            navigate(to: root.path)
        }
    }

    /// Drops all cached children and re-loads the current directory —
    /// called after a rescan, since sizes/children may have changed.
    func invalidate() {
        cache.removeAll()
        if let path = current?.path, engine.dirEntry(path: path) != nil {
            navigate(to: path)
        } else if let root {
            navigate(to: root.path)
        }
    }

    func navigate(to path: String) {
        current = engine.dirEntry(path: path)
        selectedPath = nil
        loadChildren(for: path)
    }

    func descend(_ entry: DirEntry) {
        guard entry.hasChildren else { return }
        if let path = current?.path { back.append(path) }
        navigate(to: entry.path)
    }

    func up() {
        guard let parent = parentPath(of: current?.path) else { return }
        if let path = current?.path { back.append(path) }
        navigate(to: parent)
    }

    func goBack() {
        guard let path = back.popLast() else { return }
        navigate(to: path)
    }

    var canGoUp: Bool {
        guard let path = current?.path, let root else { return false }
        return path != root.path
    }

    var canGoBack: Bool { !back.isEmpty }

    var breadcrumbs: [(label: String, path: String)] {
        guard let current, let root else { return [] }
        return PathDisplay.components(current.path, root: root.path)
    }

    var selectedEntry: DirEntry? {
        entries.first { $0.path == selectedPath }
    }

    private func loadChildren(for path: String) {
        if let cached = cache[path] {
            entries = cached
            return
        }
        entries = []
        isLoading = true
        loadGeneration += 1
        let generation = loadGeneration
        let engine = self.engine
        Task { [weak self] in
            let children = await Task.detached { engine.dirChildren(path: path) }.value
            guard let self, self.loadGeneration == generation else { return }
            self.cache[path] = children
            self.entries = children
            self.isLoading = false
        }
    }

    private func parentPath(of path: String?) -> String? {
        guard let path else { return nil }
        let parent = (path as NSString).deletingLastPathComponent
        guard !parent.isEmpty, parent != path else { return nil }
        return parent
    }
}
