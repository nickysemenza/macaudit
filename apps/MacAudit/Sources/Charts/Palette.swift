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

    /// Stable colour per `EntryKind` label — an owner's resource-kind
    /// breakdown (`OwnerDetailView`'s `BarBreakdown`/table/treemap,
    /// `OwnerInspector`). Grouped so kinds from the same ecosystem read as a
    /// family (Xcode ↔ Simulator, the various `~/Library` locations, …).
    /// Takes `EntryKind.label` rather than the enum itself so a breakdown
    /// entry whose label doesn't match any known case (forward-compatible
    /// with a scanner-only label) still gets a colour instead of requiring a
    /// reverse `EntryKind(label:)` decode.
    static func color(forKindLabel label: String) -> Color {
        switch label {
        case "Working tree": .red
        case "Artifacts": .orange
        case "Worktree": .indigo
        case "Package cache": .mint
        case "Toolchain": .cyan
        case "Xcode": .purple
        case "Simulator": .pink
        case "Docker": .purple.opacity(0.6)
        case "Agent state": .teal
        case "Editor state": .yellow
        case "Project cache": .mint.opacity(0.6)
        case "App bundle": .blue
        case "Container": .indigo.opacity(0.6)
        case "Group container": .indigo.opacity(0.4)
        case "App support": .green
        case "Cache": .teal.opacity(0.6)
        case "Preferences": .brown
        case "Logs": .brown.opacity(0.6)
        case "Web data": .cyan.opacity(0.6)
        case "Saved state": .yellow.opacity(0.6)
        case "Dot dir": .gray.opacity(0.7)
        case "Data": .blue.opacity(0.6)
        default: .gray
        }
    }
}

extension Color {
    /// Maps a `FlagTint` (Kit) to a real `Color` — MacAuditKit doesn't
    /// import SwiftUI, so `FootprintEntry.flags` hands back a tint name and
    /// the app does this mapping.
    init(_ tint: FlagTint) {
        switch tint {
        case .orange: self = .orange
        case .blue: self = .blue
        case .purple: self = .purple
        case .gray: self = .gray
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
