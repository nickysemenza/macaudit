import SwiftUI

/// The two-way list/treemap toggle every drill-down view offers
/// (`DirBrowser.ViewMode`, `OwnerBrowser.ViewMode`) — lets `ViewModePicker`
/// bind to either browser's own mode enum without knowing which.
protocol ListOrTreemapMode: Hashable {
    static var list: Self { get }
    static var treemap: Self { get }
}

extension DirBrowser.ViewMode: ListOrTreemapMode {}
extension OwnerBrowser.ViewMode: ListOrTreemapMode {}

/// The segmented list/treemap picker shown by every drill-down view's
/// header/breadcrumb bar (`LensView`, `OwnerDetailView`, `FolderBrowserView`)
/// — same icons, style, and sizing everywhere.
struct ViewModePicker<Mode: ListOrTreemapMode>: View {
    @Binding var selection: Mode

    var body: some View {
        Picker("", selection: $selection) {
            Image(systemName: "list.bullet").tag(Mode.list)
            Image(systemName: "square.grid.2x2").tag(Mode.treemap)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .controlSize(.small)
        .fixedSize()
    }
}
