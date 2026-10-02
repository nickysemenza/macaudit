import Foundation
import MacAuditCollections
import MacAuditKit

struct DirectoryPresentation: Sendable {
    var current: DirEntry?
    var entries: [DirEntry]
    var liveFiles: LiveFilesPage?
    var liveFilesError: String?
    var metadata: SessionMetadata?
    var pageMetadata: [SessionMetadata] = []
    var requestId: UInt64?
    var nextOffset: UInt64?
}

@MainActor
@Observable
final class DirBrowser {
    let engine: any MacAuditEngine
    let queries: MacAuditQueries
    enum ViewMode: String, CaseIterable { case list, treemap }
    var viewMode: ViewMode = .list
    private(set) var root: DirEntry?
    private(set) var rootStats: DirTreeStats?
    private(set) var current: DirEntry?
    private(set) var entries: [DirEntry] = []
    private(set) var liveFiles: LiveFilesPage?
    private(set) var liveFilesError: String?
    private(set) var metadata: SessionMetadata?
    private(set) var pageMetadata: [SessionMetadata] = []
    private(set) var requestId: UInt64?
    var topFiles: [TopFile] {
        liveFiles?.files ?? []
    }

    var liveFilesObservedAt: Date? {
        guard let milliseconds = liveFiles?.observedAtMs, milliseconds > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
    }

    var liveFilesCoverage: String {
        if let liveFilesError {
            return "Live listing unavailable: \(liveFilesError)"
        }
        guard let liveFiles else { return "Waiting for live observations…" }
        var details = ["Live coverage: \(liveFiles.coverage)"]
        if liveFiles.dataless > 0 {
            details.append("\(liveFiles.dataless) dataless skipped")
        }
        if liveFiles.errors > 0 {
            details.append("\(liveFiles.errors) errors")
        }
        if liveFiles.truncated {
            details.append("limited to largest 128 direct files")
        }
        details.append(contentsOf: liveFiles.stopReasons)
        return details.joined(separator: " · ")
    }

    private(set) var isLoading = false
    private(set) var nextOffset: UInt64?
    private(set) var searchResults: [DirEntry] = []
    private(set) var searchFiles: [TopFile] = []
    private(set) var searchObservedAt: Date?
    private(set) var searchCoverage = "Waiting for live observations…"
    private(set) var searchCancelled = false
    private(set) var isSearching = false
    private(set) var searchTruncated = false
    private(set) var queryError: String?
    private(set) var revision: UInt64 = 0
    private var requestedPath: String?
    private var searchMetadata: SessionMetadata?
    private var refreshTask: Task<Void, Never>?
    var selectedPath: String?
    var searchText = "" {
        didSet { search() }
    }

    var sortOrder: [KeyPathComparator<DirEntry>] = [.init(\.alloc, order: .reverse)] {
        didSet { sortEntries() }
    }

    private var loadedRows: OrderedDictionary<String, DirEntry> = [:]
    private var cache = PresentationCache<String, DirectoryPresentation>(capacity: 8)
    private var back: [String] = []
    private var loadGeneration: UInt64 = 0
    private var sortGeneration: UInt64 = 0
    private var searchGeneration: UInt64 = 0
    private var rootGeneration: UInt64 = 0
    private var task: Task<Void, Never>?
    private var searchTask: Task<Void, Never>?
    private var rootTask: Task<Void, Never>?
    static let rowLimit = 2048

    init(engine: any MacAuditEngine) {
        self.engine = engine
        queries = MacAuditQueries(engine: engine)
    }

    func reset() {
        loadGeneration &+= 1
        sortGeneration &+= 1
        searchGeneration &+= 1
        rootGeneration &+= 1
        task?.cancel()
        searchTask?.cancel()
        rootTask?.cancel()
        refreshTask?.cancel()
        refreshTask = nil
        requestedPath = nil
        cache.removeAll()
        loadedRows.removeAll()
        back.removeAll()
        root = nil
        rootStats = nil
        current = nil
        entries = []
        liveFiles = nil
        liveFilesError = nil
        metadata = nil
        pageMetadata = []
        searchMetadata = nil
        requestId = nil
        selectedPath = nil
        queryError = nil
        nextOffset = nil
        searchText = ""
        searchResults = []
        searchFiles = []
        searchObservedAt = nil
        searchCoverage = "Waiting for live observations…"
        searchCancelled = false
        revision &+= 1
        isSearching = false
        isLoading = false
    }

    func refreshRoot() {
        rootGeneration &+= 1
        let generation = rootGeneration
        let queries = queries
        let subject = requestedPath
        let selectionGeneration = loadGeneration
        rootTask?.cancel()
        rootTask = Task { [weak self] in
            let root = await queries.root()
            let stats = await queries.stats()
            guard let self, rootGeneration == generation, !Task.isCancelled else { return }
            self.root = root
            rootStats = stats?.root == root?.path ? stats : nil
            if loadGeneration == selectionGeneration, let path = subject ?? root?.path {
                navigate(to: path, retainingRows: current?.path == path)
            }
        }
    }

    func inventoryChanged() {
        cache.removeAll()
        guard refreshTask == nil else { return }
        refreshTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(150)) } catch { return }
            guard let self else { return }
            refreshTask = nil
            refreshRoot()
        }
    }

    func invalidate() {
        cache.removeAll()
        if let path = current?.path {
            navigate(to: path)
        }
    }

    func navigate(to path: String, retainingRows: Bool = false) {
        if !retainingRows, !searchText.isEmpty {
            searchText = ""
        }
        loadGeneration &+= 1
        sortGeneration &+= 1
        let generation = loadGeneration
        task?.cancel()
        requestedPath = path
        if !retainingRows {
            selectedPath = nil
            current = nil
            entries = []
            loadedRows.removeAll()
            liveFiles = nil
            liveFilesError = nil
            metadata = nil
            pageMetadata = []
            requestId = nil
        }
        queryError = nil
        nextOffset = nil
        isLoading = false
        revision &+= 1
        if let cached = cache.value(for: path) {
            let started = PresentationTrace.start()
            install(cached)
            PresentationTrace.finish("explore.directory.cache", since: started, run: cached.metadata?.runId,
                                     generation: generation, revision: cached.current?.nodeRevision,
                                     rows: cached.entries.count, cacheHit: true, mainActor: true)
            let queries = queries
            task = Task { [weak self] in
                let metadata = await queries.metadata()
                let entry = await queries.entry(path: path)
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                if cached.metadata?.runId != metadata.runId || cached.current?.nodeRevision != entry?.nodeRevision {
                    cache.removeAll()
                    navigate(to: path)
                }
            }
            return
        }
        isLoading = true
        let queries = queries
        task = Task { [weak self] in
            do {
                let started = PresentationTrace.start()
                let expected = await queries.metadata()
                let entry = await queries.entry(path: path)
                let page = try await queries.children(path: path, offset: 0, limit: 500)
                let latest = await queries.metadata()
                PresentationTrace.finish("explore.directory.query", since: started, run: page.metadata.runId,
                                         request: page.requestId, generation: generation, revision: entry?.nodeRevision,
                                         rows: page.entries.count, cacheHit: false)
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                guard page.subjectPath == path, entry?.path == path,
                      Self.sameRun(page.metadata, expected), Self.sameRun(latest, expected)
                else {
                    throw MacAuditError.Invalid(message: "The directory query belongs to a changed run or another folder.")
                }
                let presentation = DirectoryPresentation(
                    current: entry, entries: page.entries,
                    liveFiles: nil, liveFilesError: nil, metadata: page.metadata, pageMetadata: [page.metadata],
                    requestId: page.requestId, nextOffset: page.nextOffset
                )
                cache.insert(presentation, for: path)
                install(presentation)
                do {
                    let observations = try await queries.liveFiles(path: path, limit: 128)
                    let latest = await queries.metadata()
                    guard loadGeneration == generation, !Task.isCancelled else { return }
                    guard observations.subjectPath == path,
                          Self.sameRun(observations.metadata, page.metadata), Self.sameRun(latest, page.metadata)
                    else {
                        throw MacAuditError.Invalid(message: "The live observation belongs to a changed run or another folder.")
                    }
                    liveFiles = observations
                } catch {
                    guard loadGeneration == generation, !Task.isCancelled else { return }
                    liveFilesError = "\(error)"
                }
                cache.insert(DirectoryPresentation(current: current, entries: Array(loadedRows.values),
                                                   liveFiles: liveFiles, liveFilesError: liveFilesError, metadata: metadata,
                                                   pageMetadata: pageMetadata,
                                                   requestId: requestId, nextOffset: nextOffset), for: path)
                revision &+= 1
            } catch {
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                isLoading = false
                queryError = "\(error)"
            }
        }
    }

    func loadMore() {
        guard let offset = nextOffset, let path = current?.path,
              !isLoading, loadedRows.count < Self.rowLimit else { return }
        let generation = loadGeneration
        let expected = metadata
        let expectedNodeRevision = current?.nodeRevision
        let previousRequestId = requestId
        isLoading = true
        let queries = queries
        task = Task { [weak self] in
            do {
                let page = try await queries.children(path: path, offset: offset, limit: 500)
                let entry = await queries.entry(path: path)
                let latest = await queries.metadata()
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                guard let expected, page.subjectPath == path, entry?.path == path,
                      entry?.nodeRevision == expectedNodeRevision,
                      Self.sameRun(page.metadata, expected), Self.sameRun(latest, expected),
                      (previousRequestId ?? 0) == 0 || page.requestId > (previousRequestId ?? 0)
                else {
                    throw MacAuditError.Invalid(message: "The scan changed. Reload this folder before loading more rows.")
                }
                for entry in page.entries.prefix(Self.rowLimit - loadedRows.count) {
                    loadedRows[entry.path] = entry
                }
                nextOffset = page.nextOffset
                metadata = page.metadata
                pageMetadata.append(page.metadata)
                requestId = page.requestId
                isLoading = false
                sortEntries()
                revision &+= 1
                cache.insert(DirectoryPresentation(current: current, entries: Array(loadedRows.values),
                                                   liveFiles: liveFiles, liveFilesError: liveFilesError,
                                                   metadata: page.metadata,
                                                   pageMetadata: pageMetadata,
                                                   requestId: page.requestId, nextOffset: nextOffset), for: path)
            } catch {
                guard let self, loadGeneration == generation, !Task.isCancelled else { return }
                isLoading = false
                queryError = "\(error)"
            }
        }
    }

    private func install(_ presentation: DirectoryPresentation) {
        let started = PresentationTrace.start()
        current = presentation.current
        loadedRows.removeAll()
        for entry in presentation.entries.prefix(Self.rowLimit) {
            loadedRows[entry.path] = entry
        }
        liveFiles = presentation.liveFiles
        liveFilesError = presentation.liveFilesError
        metadata = presentation.metadata
        pageMetadata = presentation.pageMetadata
        requestId = presentation.requestId
        nextOffset = presentation.nextOffset
        isLoading = false
        sortEntries()
        revision &+= 1
        PresentationTrace.finish("explore.directory.install", since: started, run: presentation.metadata?.runId,
                                 generation: loadGeneration, revision: presentation.current?.nodeRevision,
                                 rows: loadedRows.count, mainActor: true)
        if !searchText.isEmpty {
            search(retainingRows: true)
        }
    }

    private func sortEntries() {
        sortGeneration &+= 1
        let generation = sortGeneration
        let rows = Array(loadedRows.values)
        let pageMetadata = pageMetadata
        let order = sortOrder
        Task { [weak self] in
            let sorted = await Task.detached { (rows.sorted(using: order), pageMetadata) }.value
            guard let self, sortGeneration == generation else { return }
            withExtendedLifetime(sorted.1) { entries = sorted.0 }
            revision &+= 1
        }
    }

    private func search(retainingRows: Bool = false) {
        searchGeneration &+= 1
        let generation = searchGeneration
        searchTask?.cancel()
        if !retainingRows {
            searchResults = []
            searchFiles = []
            searchObservedAt = nil
            searchCoverage = "Waiting for live observations…"
            searchMetadata = nil
            selectedPath = nil
        }
        searchTruncated = false
        searchCancelled = false
        queryError = nil
        revision &+= 1
        let text = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        isSearching = !text.isEmpty
        guard !text.isEmpty else { return }
        let queries = queries
        searchTask = Task { [weak self] in
            if !retainingRows {
                do { try await Task.sleep(for: .milliseconds(200)) } catch { return }
            }
            do {
                let started = PresentationTrace.start()
                let expected = await queries.metadata()
                let page = try await queries.searchNames(query: text, limit: 1000)
                let latest = await queries.metadata()
                PresentationTrace.finish("explore.name.query", since: started, run: page.metadata.runId,
                                         request: page.requestId, generation: generation,
                                         revision: page.metadata.revision, rows: page.entries.count + page.files.count)
                guard let self, searchGeneration == generation, !Task.isCancelled else { return }
                guard page.query == text, Self.sameRun(page.metadata, expected), Self.sameRun(latest, expected) else {
                    throw MacAuditError.Invalid(message: "The name query belongs to a changed run or another search.")
                }
                searchResults = Array(page.entries.prefix(1000))
                searchFiles = Array(page.files.prefix(1000 - searchResults.count))
                searchObservedAt = page.observedAtMs > 0 ? Date(timeIntervalSince1970: Double(page.observedAtMs) / 1000) : nil
                searchCoverage = (["Live search coverage: \(page.coverage)"] + page.stopReasons).joined(separator: " · ")
                searchCancelled = page.cancelled
                searchMetadata = page.metadata
                revision &+= 1
                searchTruncated = page.truncated || page.entries.count + page.files.count > 1000
                isSearching = false
            } catch {
                guard let self, searchGeneration == generation, !Task.isCancelled else { return }
                isSearching = false
                queryError = "\(error)"
            }
        }
    }

    func cancelSearch() {
        searchGeneration &+= 1
        searchTask?.cancel()
        isSearching = false
        searchCancelled = true
        revision &+= 1
    }

    func openParent(of file: TopFile) {
        let parent = (file.path as NSString).deletingLastPathComponent
        guard let root = metadata?.selectedRoot ?? self.root?.path,
              AuditStore.containsLocation(parent, under: root) else { return }
        searchText = ""
        navigate(to: parent)
    }

    private static func sameRun(_ actual: SessionMetadata, _ expected: SessionMetadata) -> Bool {
        actual.runId == expected.runId && actual.selectedRoot == expected.selectedRoot
    }

    func descend(_ entry: DirEntry) {
        if let path = current?.path {
            back.append(path)
        }
        if back.count > 64 {
            back.removeFirst()
        }
        searchText = ""
        navigate(to: entry.path)
    }

    func up() {
        guard canGoUp, let path = current?.path else { return }
        back.append(path)
        if back.count > 64 {
            back.removeFirst()
        }
        searchText = ""
        navigate(to: (path as NSString).deletingLastPathComponent)
    }

    func goBack() {
        guard let path = back.popLast() else { return }
        searchText = ""
        navigate(to: path)
    }

    var canGoUp: Bool {
        root != nil && current != nil && current?.path != root?.path
    }

    var canGoBack: Bool {
        !back.isEmpty
    }

    var breadcrumbs: [(label: String, path: String)] {
        guard let current, let root else { return [] }
        return PathDisplay.components(current.path, root: root.path)
    }

    var selectedEntry: DirEntry? {
        (entries + searchResults).first { $0.path == selectedPath }
    }
}
