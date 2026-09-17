import AppKit
import MacAuditKit
import SwiftUI

/// The Folders drill-down: breadcrumbs over a sortable table of the current
/// directory's children. Placed inside `ContentView`'s detail `Group`, which
/// already carries `.navigationSplitViewColumnWidth` + `.stableColumnSize()`
/// as the outermost modifiers — nothing here adds a data-driven frame at
/// this view's own root (see `ColumnSizing.swift`).
struct FolderBrowserView: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        VStack(spacing: 0) {
            BreadcrumbBar(browser: store.browser)
            Divider()
            content
        }
    }

    @ViewBuilder
    private var content: some View {
        let browser = store.browser
        if browser.root == nil {
            emptyState
        } else if browser.entries.isEmpty && !browser.isLoading {
            ContentUnavailableView(
                "No subfolders", systemImage: "folder",
                description: Text("Files directly here are listed in the inspector."))
        } else {
            switch browser.viewMode {
            case .list:
                DirTable(browser: browser, store: store, parentAlloc: browser.current?.alloc ?? 0)
            case .treemap:
                TreemapView(browser: browser, store: store, engine: browser.engine)
            }
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        switch store.status(of: .fs) {
        case .scanning(let msg, _, _):
            VStack(spacing: 12) {
                ProgressView()
                Text(msg.isEmpty ? "Indexing…" : msg).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let error):
            ContentUnavailableView {
                Label("Scan failed", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            } actions: {
                Button("Retry") { store.rescan(.fs) }
            }
        case .idle:
            ContentUnavailableView {
                Label("Not scanned", systemImage: "magnifyingglass")
            } actions: {
                Button("Scan") { store.rescan(.fs) }
            }
        case .done:
            ContentUnavailableView("Nothing found", systemImage: "checkmark.circle")
        }
    }
}

/// Back/up navigation, the path trail, and a live summary of the current
/// directory. Takes `browser` as a stored property rather than reading the
/// environment — kept consistent with the table's cell views below, even
/// though this one is not itself hosted inside a `Table`/`List` cell.
private struct BreadcrumbBar: View {
    let browser: DirBrowser

    var body: some View {
        @Bindable var browser = browser
        HStack(spacing: 4) {
            Button {
                browser.goBack()
            } label: {
                Image(systemName: "chevron.backward")
            }
            .buttonStyle(.borderless)
            .disabled(!browser.canGoBack)
            .help("Back (⌘[)")

            Button {
                browser.up()
            } label: {
                Image(systemName: "arrow.up")
            }
            .buttonStyle(.borderless)
            .disabled(!browser.canGoUp)
            .help("Enclosing Folder (⌘↑)")

            let crumbs = browser.breadcrumbs
            ForEach(Array(crumbs.enumerated()), id: \.offset) { index, crumb in
                if index > 0 {
                    Text("›").foregroundStyle(.tertiary)
                }
                let isLast = index == crumbs.count - 1
                Button(crumb.label) { browser.navigate(to: crumb.path) }
                    .buttonStyle(.borderless)
                    .fontWeight(isLast ? .bold : .regular)
                    .disabled(isLast)
            }

            Spacer()

            Picker("", selection: $browser.viewMode) {
                Image(systemName: "list.bullet").tag(DirBrowser.ViewMode.list)
                Image(systemName: "square.grid.2x2").tag(DirBrowser.ViewMode.treemap)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.small)
            .fixedSize()

            if browser.isLoading {
                ProgressView().controlSize(.small)
            }

            if let current = browser.current {
                Text(summary(for: current)).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private func summary(for entry: DirEntry) -> String {
        var s = "\(Formatting.bytes(entry.alloc)) · \(Formatting.count(entry.files)) files · \(Formatting.count(entry.dirs)) folders"
        if entry.errors > 0 {
            s += " · \(Formatting.count(entry.errors)) unreadable"
        }
        return s
    }
}

/// The children table. `store`/`browser` are stored properties, not
/// `@Environment` reads: `Table` rows are hosted in per-cell
/// `NSHostingView`s, and on macOS 26 a cell built while the table is already
/// visible (rows streaming in) traps reading the Observable environment
/// (see `MarkToggle` in `SectionDetail.swift`).
private struct DirTable: View {
    let browser: DirBrowser
    let store: AuditStore
    let parentAlloc: UInt64

    private var sortedEntries: [DirEntry] {
        browser.entries.sorted(using: browser.sortOrder)
    }

    var body: some View {
        Table(
            sortedEntries,
            selection: Binding(get: { browser.selectedPath }, set: { browser.selectedPath = $0 }),
            sortOrder: Binding(get: { browser.sortOrder }, set: { browser.sortOrder = $0 })
        ) {
            TableColumn("Name", value: \.name) { e in
                Label(e.name, systemImage: e.hasChildren ? "folder.fill" : "folder")
                    .lineLimit(1)
            }
            .width(min: 200, ideal: 320)
            TableColumn("Size", value: \.alloc) { e in
                Text(Formatting.bytes(e.alloc)).monospacedDigit()
            }
            .width(min: 80, ideal: 96)
            TableColumn("Share") { e in
                HStack(spacing: 6) {
                    ShareBar(fraction: parentAlloc > 0 ? Double(e.alloc) / Double(parentAlloc) : 0)
                    Text(Formatting.share(e.alloc, of: parentAlloc)).foregroundStyle(.secondary)
                }
            }
            .width(min: 110, ideal: 160)
            TableColumn("Files", value: \.files) { e in
                Text(Formatting.count(e.files)).foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("Folders", value: \.dirs) { e in
                Text(Formatting.count(e.dirs)).foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("") { e in
                if e.errors > 0 {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                        .help("\(e.errors) unreadable folders")
                }
            }
            .width(24)
        }
        .contextMenu(forSelectionType: String.self) { paths in
            if let path = paths.first, let entry = browser.entries.first(where: { $0.path == path }) {
                DirContextMenu(store: store, browser: browser, entry: entry)
            }
        } primaryAction: { paths in
            if let path = paths.first, let entry = browser.entries.first(where: { $0.path == path }) {
                browser.descend(entry)
            }
        }
        .onKeyPress(.return) {
            guard let entry = browser.selectedEntry else { return .ignored }
            browser.descend(entry)
            return .handled
        }
    }
}

/// A thin capsule showing `fraction` of the row's parent, drawn only inside
/// the cell it measures — `GeometryReader` at a column root would fight the
/// column's own sizing.
private struct ShareBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary)
                Capsule()
                    .fill(Color.accentColor)
                    .frame(width: max(0, min(1, fraction)) * geo.size.width)
            }
        }
        .frame(height: 6)
    }
}

/// Folder row menu. No mark/trash actions here — those apply to findings,
/// not to arbitrary folders the user is merely browsing.
private struct DirContextMenu: View {
    let store: AuditStore
    let browser: DirBrowser
    let entry: DirEntry

    var body: some View {
        if entry.hasChildren {
            Button("Open") { browser.descend(entry) }
        }
        Button("Reveal in Finder") {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: entry.path)])
        }
        Button("Copy Path") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(entry.path, forType: .string)
        }
        Divider()
        Button("Show Findings Here") {
            store.selectedItem = .section(.fs)
            store.searchText = entry.path
        }
    }
}
