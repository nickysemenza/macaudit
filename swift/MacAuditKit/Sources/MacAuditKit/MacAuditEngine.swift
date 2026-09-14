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
    func sectionHistory() throws -> [SectionHistoryPoint]
}

extension Engine: MacAuditEngine {}

extension SectionId: CaseIterable {
    /// Sidebar order — the same order as `Engine.sections()`.
    public static let allCases: [SectionId] = [
        .system, .apps, .brew, .tools, .fs, .launchd, .shellEnv, .runtimes,
        .docker, .ports, .git, .simulator, .sshKeys, .timeMachine,
    ]
}

extension SectionId: Identifiable {
    public var id: Self { self }
}

extension Finding: Identifiable {}
extension SnapshotMeta: Identifiable {}

extension SectionId {
    /// The engine's section slug (`macaudit scan --section <slug>`).
    public var slug: String {
        switch self {
        case .system: "system"
        case .apps: "apps"
        case .brew: "brew"
        case .tools: "tools"
        case .fs: "fs"
        case .launchd: "launchd"
        case .shellEnv: "shell_env"
        case .runtimes: "runtimes"
        case .docker: "docker"
        case .ports: "ports"
        case .git: "git"
        case .simulator: "simulator"
        case .sshKeys: "ssh_keys"
        case .timeMachine: "time_machine"
        }
    }
}
