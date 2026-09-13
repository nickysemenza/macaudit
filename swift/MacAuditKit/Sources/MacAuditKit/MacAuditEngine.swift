import Foundation

/// The engine surface the app talks to. `Engine` (generated) conforms; a
/// stub can stand in for previews and tests. Keep this to what the app
/// actually calls.
public protocol MacAuditEngine: AnyObject, Sendable {
    func sections() -> [SectionMeta]
    func deleteMode() -> DeleteMode
    func configPath() -> String
    @discardableResult
    func startScan(sections: [SectionId], listener: ScanListener) -> UInt64
    func cancelScan()
    func findings(section: SectionId) -> [Finding]
    func plan(selection: [Selection]) throws -> Plan
    func execute(plan: Plan, listener: ExecListener) throws
    func cancelCleanup()
    func snapshots() throws -> [SnapshotMeta]
    func saveSnapshot() throws -> Int64
    func diffSnapshots(a: Int64, b: Int64) throws -> SnapshotDiff
    func baselineCounts() -> [SectionBaseline]
}

extension Engine: MacAuditEngine {}

extension SectionId: CaseIterable {
    /// Sidebar order — the same order as `Engine.sections()`.
    public static let allCases: [SectionId] = [
        .system, .apps, .brew, .tools, .fs, .launchd, .shellEnv, .runtimes,
        .docker, .ports, .git, .simulator, .sshKeys, .tmSnapshots,
    ]
}

extension SectionId: Identifiable {
    public var id: Self { self }
}

extension Finding: Identifiable {}
extension SnapshotMeta: Identifiable {}
