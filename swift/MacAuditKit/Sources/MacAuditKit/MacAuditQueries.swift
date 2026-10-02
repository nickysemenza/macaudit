import Foundation

public actor MacAuditQueries {
    private let engine: any MacAuditEngine

    public init(engine: any MacAuditEngine) { self.engine = engine }

    public func setRoot(_ root: String) throws { try engine.setRoot(root: root) }
    public func startRun(root: String, listener: ScanListener) throws -> UInt64 {
        try engine.startRun(root: root, listener: listener)
    }
    public func selectedRoot() -> String { engine.selectedRoot() }
    public func root() -> DirEntry? { engine.dirRoot() }
    public func entry(path: String) -> DirEntry? { engine.dirEntry(path: path) }
    public func children(path: String, offset: UInt64 = 0, limit: UInt32 = 500) async throws -> DirectoryPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery {
            try engine.dirChildrenPage(path: path, offset: offset, limit: limit)
        }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func ancestors(path: String) async -> [DirEntry] {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let entries = try? await detachedQuery({ engine.dirAncestors(path: path) }),
            (try? validateRun(issued)) != nil else { return [] }
        return entries
    }
    public func searchNames(query: String, limit: UInt32 = 1000) async throws -> DirectorySearchPage {
        let issued = engine.sessionMetadata()
        let cancellation = QueryCancellation()
        let engine = self.engine
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let result: DirectorySearchPage
            do {
                result = try await Task.detached {
                    try engine.nameSearch(query: query, limit: limit, cancellation: cancellation)
                }.value
            } catch {
                try Task.checkCancellation()
                throw error
            }
            try Task.checkCancellation()
            try validate(result.metadata, issued: issued)
            return result
        } onCancel: {
            cancellation.cancel()
        }
    }
    public func openNameQuery(query: String, limit: UInt32 = 1000) async throws -> DirectoryCursor {
        let issued = engine.sessionMetadata()
        let cancellation = QueryCancellation()
        let engine = self.engine
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let cursor: DirectoryCursor
            do {
                cursor = try await Task.detached {
                    try engine.openNameQuery(query: query, limit: limit, cancellation: cancellation)
                }.value
            } catch {
                try Task.checkCancellation()
                throw error
            }
            do {
                try Task.checkCancellation()
                try validateRun(issued)
                guard cursor.runId == issued.runId else {
                    throw MacAuditError.Invalid(message: "query belongs to a retired run")
                }
            } catch {
                engine.releaseDirectoryQuery(cursor: cursor)
                throw error
            }
            return cursor
        } onCancel: {
            cancellation.cancel()
        }
    }
    public func directoryPage(cursor: DirectoryCursor, limit: UInt32 = 500) async throws -> DirectoryQueryPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery { try engine.directoryQueryPage(cursor: cursor, limit: limit) }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func releaseDirectoryQuery(cursor: DirectoryCursor) { engine.releaseDirectoryQuery(cursor: cursor) }
    public func subtree(path: String, depth: UInt32, maxNodes: UInt32) async -> [DirEntry] {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let entries = try? await detachedQuery({
            engine.dirSubtree(path: path, depth: depth, maxNodes: min(maxNodes, 500))
        }), (try? validateRun(issued)) != nil else { return [] }
        return entries
    }
    public func topFiles(path: String, n: UInt32) async -> [TopFile] {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let files = try? await detachedQuery({ engine.dirTopFiles(path: path, n: min(n, 500)) }),
            (try? validateRun(issued)) != nil else { return [] }
        return files
    }
    public func liveFiles(path: String, limit: UInt32 = 500) async throws -> LiveFilesPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery { try engine.liveFilesPage(path: path, limit: limit) }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func largestFiles(n: UInt32) async -> [TopFile] {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let files = try? await detachedQuery({ engine.largestFiles(n: min(n, 500)) }),
            (try? validateRun(issued)) != nil else { return [] }
        return files
    }
    public func footprint(findingId: UInt64, runId: UInt64? = nil) async -> Footprint? {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let footprint = try? await detachedQuery({
            try engine.footprintForRun(findingId: findingId, runId: runId ?? issued.runId)
        }), (try? validateRun(issued)) != nil else { return nil }
        return footprint
    }
    public func footprintEntries(findingId: UInt64, runId: UInt64? = nil, revision: UInt64? = nil,
        requestId: UInt64? = nil, offset: UInt64 = 0, limit: UInt32 = 500) async throws -> FootprintEntriesPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery {
            try engine.footprintEntriesPageForRun(findingId: findingId, runId: runId ?? issued.runId,
                revision: revision, requestId: requestId, offset: offset, limit: limit)
        }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func footprintEntries(cursor: FootprintCursor, limit: UInt32 = 500) async throws -> FootprintEntriesPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery { try engine.footprintCursorPage(cursor: cursor, limit: limit) }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func decodeMetadata(finding: Finding) -> FindingMeta { FindingMeta(json: finding.metaJson) }
    public func footprintBuckets(axis: Axis, runId: UInt64? = nil) async -> FootprintBuckets? {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        guard let buckets = try? await detachedQuery({
            try engine.footprintBucketsForRun(axis: axis, runId: runId ?? issued.runId)
        }), (try? validateRun(issued)) != nil else { return nil }
        return buckets
    }
    public func metadata() -> SessionMetadata { engine.sessionMetadata() }
    public func stats() -> DirTreeStats? { engine.dirTreeStats() }
    public func plan(selection: [Selection]) async throws -> Plan {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let plan = try await detachedQuery { try engine.plan(selection: selection) }
        try validateRun(issued)
        guard plan.runId() == issued.runId else {
            throw MacAuditError.Invalid(message: "plan belongs to a retired run")
        }
        return plan
    }
    public func findings(section: SectionId, runId: UInt64? = nil, revision: UInt64? = nil,
        requestId: UInt64? = nil, offset: UInt64 = 0, limit: UInt32 = 500) async throws -> FindingsPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery {
            try engine.findingsPageForRun(section: section, runId: runId ?? issued.runId,
                revision: revision, requestId: requestId, offset: offset, limit: limit)
        }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func findings(cursor: FindingsCursor, limit: UInt32 = 500) async throws -> FindingsPage {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let page = try await detachedQuery { try engine.findingsCursorPage(cursor: cursor, limit: limit) }
        try validate(page.metadata, issued: issued)
        return page
    }
    public func sectionSummary(section: SectionId, runId: UInt64) async throws -> SectionSummary {
        let issued = engine.sessionMetadata()
        let engine = self.engine
        let summary = try await detachedQuery { try engine.sectionSummary(section: section, runId: runId) }
        try validate(summary.metadata, issued: issued)
        return summary
    }

    private func validate(_ metadata: SessionMetadata, issued: SessionMetadata) throws {
        try validateRun(issued)
        guard metadata.runId == issued.runId, metadata.selectedRoot == issued.selectedRoot else {
            throw MacAuditError.Invalid(message: "query belongs to a retired run or root")
        }
    }

    private func validateRun(_ issued: SessionMetadata) throws {
        let current = engine.sessionMetadata()
        guard current.runId == issued.runId, current.selectedRoot == issued.selectedRoot else {
            throw MacAuditError.Invalid(message: "query belongs to a retired run or root")
        }
    }

    private nonisolated func detachedQuery<Output: Sendable>(
        _ operation: @escaping @Sendable () throws -> Output
    ) async throws -> Output {
        try Task.checkCancellation()
        let worker = Task.detached {
            try Task.checkCancellation()
            return try operation()
        }
        return try await withTaskCancellationHandler {
            do {
                let output = try await worker.value
                try Task.checkCancellation()
                return output
            } catch {
                try Task.checkCancellation()
                throw error
            }
        } onCancel: {
            worker.cancel()
        }
    }
}

extension MacAuditEngine {
    public func queryDirRoot() async -> DirEntry? { await MacAuditQueries(engine: self).root() }
    public func queryDirEntry(path: String) async -> DirEntry? { await MacAuditQueries(engine: self).entry(path: path) }
    public func queryDirChildren(path: String, offset: UInt32 = 0, limit: UInt32 = 500) async throws -> [DirEntry] {
        try await MacAuditQueries(engine: self).children(path: path, offset: UInt64(offset), limit: limit).entries
    }
    public func queryDirSearch(query: String, limit: UInt32 = 1000) async throws -> [DirEntry] {
        try await MacAuditQueries(engine: self).searchNames(query: query, limit: limit).entries
    }
    public func queryDirTopFiles(path: String, n: UInt32) async -> [TopFile] {
        await MacAuditQueries(engine: self).topFiles(path: path, n: n)
    }
    public func queryFootprint(findingId: UInt64) async -> Footprint? {
        await MacAuditQueries(engine: self).footprint(findingId: findingId)
    }
    public func queryFootprintBuckets(axis: Axis) async -> FootprintBuckets? {
        await MacAuditQueries(engine: self).footprintBuckets(axis: axis)
    }
}
