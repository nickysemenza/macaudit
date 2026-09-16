import Foundation

/// Display helpers with the same conventions as the TUI (`ui/fmt.rs`):
/// binary byte units, coarse relative ages. Uses value-type format styles
/// so it is safe to call from any isolation domain.
public enum Formatting {
    public static func bytes(_ n: UInt64) -> String {
        Int64(clamping: n).formatted(.byteCount(style: .binary, spellsOutZero: false))
    }

    public static func bytes(_ n: UInt64?) -> String {
        n.map(bytes) ?? "–"
    }

    public static func age(_ date: Date?) -> String {
        guard let date else { return "–" }
        return date.formatted(.relative(presentation: .named, unitsStyle: .abbreviated))
    }
}

extension Severity {
    public var label: String {
        switch self {
        case .info: "info"
        case .attention: "attention"
        case .reclaimable: "reclaimable"
        case .warning: "warning"
        }
    }
}
