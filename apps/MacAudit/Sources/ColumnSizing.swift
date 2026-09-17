import SwiftUI

extension View {
    /// Pins a split-view column's size constraints so data-driven content never alters the
    /// column's min/max size.
    ///
    /// On macOS 26+/27 a `NavigationSplitView` column whose min size changes while AppKit is
    /// mid-constraint-update makes SwiftUI re-request layout re-entrantly, and AppKit throws from
    /// `-[NSWindow _postWindowNeedsUpdateConstraints]` (crash 2026-09-15: streaming scan results
    /// changed the chart header's height inside the detail column). Rules:
    /// - this is the OUTERMOST modifier on a column root — nothing layout-contributing
    ///   (`safeAreaInset`, padding, overlays, `.frame`) may sit outside it;
    /// - data-driven `.frame(height:)` / `minHeight` belongs inside a `ScrollView`, never at a
    ///   column root.
    func stableColumnSize() -> some View {
        frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
    }
}
