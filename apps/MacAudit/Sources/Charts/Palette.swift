import MacAuditKit
import SwiftUI

/// One colour system for every chart, so the Storage bar and the donuts
/// agree on what a category looks like.
enum Palette {
    /// Ordered categorical colours (Storage-bar spirit: warm → cool → grey).
    static let categorical: [Color] = [
        .red, .orange, .yellow, .green, .mint, .teal, .cyan, .blue, .indigo, .purple, .pink, .brown,
    ]

    /// Stable colour for a named category: fixed for the well-known ones,
    /// hashed into the palette for the rest.
    static func color(for name: String) -> Color {
        if let fixed = fixed[name] { return fixed }
        var h: UInt64 = 1469598103934665603
        for b in name.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        return categorical[Int(h % UInt64(categorical.count))]
    }

    private static let fixed: [String: Color] = [
        "Development": .red,
        "Documents": .orange,
        "Pictures": .yellow,
        "Application Support": .green,
        "App caches": .mint,
        "Developer caches": .teal,
        "Apple developer data": .cyan,
        "iCloud Drive": .blue,
        "Agent worktrees": .indigo,
        "Homebrew": .brown,
        "Docker": .purple,
        "Simulators": .pink,
        "Other": .gray,
        "Other scanned": .gray,
        "Unscanned": .gray.opacity(0.6),
        "Other (unscanned)": .gray,
        "Purgeable": .gray.opacity(0.6),
        "Free": .clear,
        // iOS device storage bars.
        "Apps": .blue,
        "Not attributed": .gray,
        "Committed": .indigo,
        "app": .blue.opacity(0.55), "data": .blue,
        // Reclaimable breakdown.
        "Stale build artifacts": .orange,
        "Recent build artifacts": .orange.opacity(0.55),
        "Caches": .teal,
        "Time Machine snapshots": .indigo,
        "Orphaned tools": .cyan,
        "Rust toolchains": .red,
        // Brew install reasons / app classifications.
        "requested": .blue, "dependency": .teal, "autoremove": .orange, "unknown": .gray,
        "system": .gray, "user": .blue, "app_store": .cyan, "unmanaged": .orange, "cask": .brown,
        // Projects/App Storage lens coverage bar.
        "Attributed": .green,
        "Baseline": .gray,
        "Unattributed": .red.opacity(0.7),
    ]

    static let reclaimable = Color.orange
    static let stale = Color.orange.opacity(0.55)

    static func section(_ id: SectionId) -> Color {
        categorical[SectionId.allCases.firstIndex(of: id)! % categorical.count]
    }

    /// Stable colour per `EntryKind` — an owner's resource-kind breakdown
    /// (`OwnerDetailView`'s `BarBreakdown`/table/treemap, `OwnerInspector`).
    /// Grouped so kinds from the same ecosystem read as a family (Xcode ↔
    /// Simulator, the various `~/Library` locations, …).
    static func color(for kind: EntryKind) -> Color {
        switch kind {
        case .workingTree: .red
        case .artifacts: .orange
        case .worktree: .indigo
        case .packageCache: .mint
        case .toolchain: .cyan
        case .xcode: .purple
        case .simulator: .pink
        case .docker: .purple.opacity(0.6)
        case .agentState: .teal
        case .editorState: .yellow
        case .projectCache: .mint.opacity(0.6)
        case .appBundle: .blue
        case .container: .indigo.opacity(0.6)
        case .groupContainer: .indigo.opacity(0.4)
        case .appSupport: .green
        case .cache: .teal.opacity(0.6)
        case .preferences: .brown
        case .logs: .brown.opacity(0.6)
        case .webData: .cyan.opacity(0.6)
        case .savedState: .yellow.opacity(0.6)
        case .dotDir: .gray.opacity(0.7)
        case .data: .blue.opacity(0.6)
        case .other: .gray
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .info: .secondary
        case .attention: .blue
        case .reclaimable: Palette.reclaimable
        case .warning: .red
        }
    }
}
