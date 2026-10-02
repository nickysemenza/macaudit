import Foundation
import MacAuditCollections
import MacAuditKit
import Observation

private struct AuditPageKey: Hashable {
    var section: SectionId
    var offset: UInt64
    var location: String?
}

private struct AuditPage: Sendable {
    var metadata: SessionMetadata
    var findings: [Finding]
    var nextOffset: UInt64?
    var runId: UInt64
    var revision: UInt64
    var requestId: UInt64
    var total: UInt64
}

@MainActor
@Observable
final class AuditFindingsBrowser {
    static let pageSize: UInt32 = 500
    static let cacheLimit = 4
    private(set) var section: SectionId?
    private(set) var offset: UInt64 = 0
    private(set) var nextOffset: UInt64?
    private(set) var rows: [Finding] = []
    private(set) var isLoading = false
    private(set) var error: String?
    private(set) var revision: UInt64 = 0
    private(set) var total: UInt64 = 0
    private(set) var locationFilter: String?
    private var pageRevision: UInt64?
    private var requestId: UInt64?
    private var loadedRows: OrderedDictionary<UInt64, Finding> = [:]
    private var loadedMetadata: SessionMetadata?
    private var cache = PresentationCache<AuditPageKey, AuditPage>(capacity: cacheLimit)
    private var previousOffsets: [UInt64] = []
    private var generation: UInt64 = 0
    private var runId: UInt64?
    private var task: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?
    private let queries: MacAuditQueries

    init(engine: any MacAuditEngine) {
        queries = MacAuditQueries(engine: engine)
    }

    var cachedRows: [Finding] {
        var unique: OrderedDictionary<UInt64, Finding> = [:]
        for page in cache.values.values {
            for finding in page.findings {
                unique[finding.id] = finding
            }
        }
        for finding in loadedRows.values {
            unique[finding.id] = finding
        }
        return Array(unique.values)
    }

    var canGoBack: Bool {
        !previousOffsets.isEmpty && !isLoading
    }

    func findings(in section: SectionId) -> [Finding] {
        if self.section == section {
            return rows
        }
        return cache.values.values.reversed().first { $0.findings.first?.section == section }?.findings ?? []
    }

    func metadata(for findingId: UInt64) -> SessionMetadata? {
        if loadedRows[findingId] != nil {
            return loadedMetadata
        }
        return cache.values.values.first { $0.findings.contains { $0.id == findingId } }?.metadata
    }

    func reset() {
        generation &+= 1
        task?.cancel()
        refreshTask?.cancel()
        refreshTask = nil
        cache.removeAll()
        loadedRows.removeAll()
        loadedMetadata = nil
        rows = []
        section = nil
        locationFilter = nil
        runId = nil
        offset = 0
        nextOffset = nil
        pageRevision = nil
        requestId = nil
        total = 0
        previousOffsets = []
        isLoading = false
        error = nil
        revision &+= 1
    }

    func activate(runId: UInt64, section: SectionId?) {
        reset()
        self.runId = runId
        select(section)
    }

    func select(_ section: SectionId?) {
        previousOffsets = []
        pageRevision = nil
        requestId = nil
        locationFilter = nil
        self.section = section
        load(offset: 0)
    }

    func filterLocation(_ path: String?) {
        refreshTask?.cancel()
        refreshTask = nil
        previousOffsets = []
        pageRevision = nil
        requestId = nil
        locationFilter = path
        cache.removeAll()
        load(offset: 0)
    }

    func next() {
        guard let nextOffset, !isLoading else { return }
        previousOffsets.append(offset)
        if previousOffsets.count > 64 {
            previousOffsets.removeFirst()
        }
        load(offset: nextOffset)
    }

    func previous() {
        guard !isLoading, let offset = previousOffsets.popLast() else { return }
        load(offset: offset)
    }

    func invalidate() {
        cache.removeAll()
        guard section != nil, refreshTask == nil else { return }
        refreshTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(150)) } catch { return }
            guard let self else { return }
            refreshTask = nil
            previousOffsets = []
            pageRevision = nil
            requestId = nil
            load(offset: 0, retainingRows: true)
        }
    }

    private func load(offset: UInt64, retainingRows: Bool = false) {
        generation &+= 1
        let generation = generation
        task?.cancel()
        self.offset = offset
        error = nil
        isLoading = false
        if !retainingRows {
            loadedRows.removeAll()
            loadedMetadata = nil
            rows = []
            nextOffset = nil
            total = 0
            revision &+= 1
        }
        guard let section else { return }
        let location = locationFilter
        let key = AuditPageKey(section: section, offset: offset, location: location)
        if let cached = cache.value(for: key) {
            let started = PresentationTrace.start()
            install(cached)
            PresentationTrace.finish("audit.page.cache", since: started, run: cached.runId, request: cached.requestId,
                                     generation: generation, revision: cached.revision, rows: cached.findings.count,
                                     cacheHit: true, mainActor: true)
            let queries = queries
            task = Task { [weak self] in
                let metadata = await queries.metadata()
                guard let self, self.generation == generation, !Task.isCancelled else { return }
                if cached.runId != metadata.runId || cached.revision != metadata.revision {
                    cache.removeAll()
                    pageRevision = nil
                    requestId = nil
                    load(offset: 0)
                }
            }
            return
        }
        let queries = queries
        let expectedRunId = runId
        let expectedRevision = offset == 0 ? nil : pageRevision
        let expectedRequestId = offset == 0 ? nil : requestId
        isLoading = true
        task = Task { [weak self] in
            do {
                let started = PresentationTrace.start()
                let page = try await Self.filteredPage(queries: queries, section: section, runId: expectedRunId,
                                                       revision: expectedRevision, requestId: expectedRequestId,
                                                       offset: offset, location: location)
                PresentationTrace.finish("audit.page.query", since: started, run: page.metadata.runId,
                                         request: page.requestId, generation: generation, revision: page.revision,
                                         rows: page.findings.count, cacheHit: false)
                guard let self, self.generation == generation, !Task.isCancelled else { return }
                guard expectedRunId == nil || page.metadata.runId == expectedRunId else {
                    isLoading = false
                    error = "The scan changed. Refresh this page."
                    return
                }
                let bounded = AuditPage(metadata: page.metadata, findings: Array(page.findings.prefix(Int(Self.pageSize))),
                                        nextOffset: page.nextOffset, runId: page.metadata.runId,
                                        revision: page.revision, requestId: page.requestId, total: page.total)
                cache.insert(bounded, for: key)
                install(bounded)
            } catch {
                guard let self, self.generation == generation, !Task.isCancelled else { return }
                isLoading = false
                self.error = "\(error)"
            }
        }
    }

    private nonisolated static func filteredPage(queries: MacAuditQueries, section: SectionId,
                                                runId: UInt64?, revision: UInt64?, requestId: UInt64?,
                                                offset: UInt64, location: String?) async throws -> FindingsPage {
        guard let location else {
            return try await queries.findings(section: section, runId: runId, revision: revision,
                                              requestId: requestId, offset: offset, limit: 500)
        }
        var sourceOffset = offset
        var sourceRevision = revision
        var sourceRequestId = requestId
        var findings: [Finding] = []
        while true {
            try Task.checkCancellation()
            let page = try await queries.findings(section: section, runId: runId, revision: sourceRevision,
                                                  requestId: sourceRequestId, offset: sourceOffset,
                                                  limit: UInt32(500 - findings.count))
            findings.append(contentsOf: page.findings.filter { finding in
                guard let path = finding.path else { return false }
                return AuditStore.containsLocation(path, under: location)
            })
            guard findings.count < 500, let next = page.nextOffset else {
                return FindingsPage(metadata: page.metadata, requestId: page.requestId, revision: page.revision,
                                    total: page.total, findings: findings, nextOffset: page.nextOffset,
                                    nextCursor: page.nextCursor)
            }
            guard next > sourceOffset else {
                throw MacAuditError.Invalid(message: "The finding cursor did not advance.")
            }
            sourceOffset = next
            sourceRevision = page.revision
            sourceRequestId = page.requestId
        }
    }

    private func install(_ page: AuditPage) {
        let started = PresentationTrace.start()
        loadedRows.removeAll()
        loadedMetadata = page.metadata
        for finding in page.findings {
            loadedRows[finding.id] = finding
        }
        rows = Array(loadedRows.values)
        nextOffset = page.nextOffset
        pageRevision = page.revision
        requestId = page.requestId
        total = page.total
        isLoading = false
        revision &+= 1
        PresentationTrace.finish("audit.page.install", since: started, run: page.runId, request: page.requestId,
                                 generation: generation, revision: page.revision, rows: rows.count, mainActor: true)
    }
}
