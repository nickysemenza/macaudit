import AppKit
import MacAuditKit
import SwiftUI

struct ExploreView: View {
    let store: AuditStore
    private var browser: DirBrowser {
        store.browser
    }

    var body: some View {
        @Bindable var browser = browser
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button { browser.goBack() } label: { Label("Back", systemImage: "chevron.backward") }
                    .labelStyle(.iconOnly).disabled(!browser.canGoBack)
                Button { browser.up() } label: { Label("Enclosing Folder", systemImage: "arrow.up") }
                    .labelStyle(.iconOnly).disabled(!browser.canGoUp)
                ScrollView(.horizontal) {
                    HStack(spacing: 4) {
                        ForEach(browser.breadcrumbs, id: \.path) { crumb in
                            Button(crumb.label) { browser.navigate(to: crumb.path) }
                                .buttonStyle(.borderless)
                            if crumb.path != browser.current?.path {
                                Text("›").foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                if browser.isLoading {
                    ProgressView().controlSize(.small)
                }
            }
            .padding(10)
            Divider()
            if browser.root != nil {
                RootAccountingFacts(stats: browser.rootStats).padding(8)
                Divider()
            }
            if let error = browser.queryError {
                Text(error).font(.caption).foregroundStyle(.red).padding(8)
            }
            if store.isStartingRun {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Validating root… Previous results remain until the new run is accepted.")
                }.font(.caption).padding(8)
            }
            if let error = store.rootError, browser.root != nil || browser.current != nil {
                Text("Root request rejected: \(error) Previous results are unchanged.")
                    .font(.caption).foregroundStyle(.red).padding(8)
            }
            if let metadata = browser.metadata, !metadata.diskComplete || !metadata.diskStopReasons.isEmpty {
                Text("Scan coverage: \(metadata.diskCoverage) · \(metadata.diskStopReasons.joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.orange).frame(maxWidth: .infinity, alignment: .leading).padding(8)
            }
            if let error = store.rootError, browser.root == nil, browser.current == nil {
                ContentUnavailableView("Root unavailable", systemImage: "folder.badge.questionmark",
                                       description: Text(error))
            } else if browser.root == nil, browser.current == nil {
                ContentUnavailableView(store.isScanning ? "Indexing selected root…" : "No indexed root",
                                       systemImage: "internaldrive", description: Text(store.selectedRoot))
            } else if !browser.searchText.isEmpty {
                VSplitView {
                    VStack(spacing: 0) {
                        Text("Indexed folder matches · scan allocation").font(.caption).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        ExploreTable(browser: browser, store: store, rows: browser.searchResults)
                    }.frame(minHeight: 120)
                    LiveFilesTable(browser: browser, isSearch: true).frame(minHeight: 120)
                }
                HStack {
                    if browser.isSearching {
                        ProgressView().controlSize(.small)
                        Button("Cancel Search") { browser.cancelSearch() }
                    }
                    Text(browser.searchTruncated ? "First 1,000 name matches; refine your search." : "\(browser.searchResults.count) indexed folders · \(browser.searchFiles.count) live file matches")
                    if browser.searchCancelled { Text("Cancelled · incomplete results").foregroundStyle(.orange) }
                    Spacer()
                }.font(.caption).padding(8)
            } else {
                VSplitView {
                    ExploreTreemap(browser: browser)
                        .frame(minHeight: 160, idealHeight: 300)
                    VStack(spacing: 0) {
                        Text("Indexed folders · scan allocation").font(.caption).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        ExploreTable(browser: browser, store: store, rows: browser.entries)
                            .frame(minHeight: 120)
                        Divider()
                        LiveFilesTable(browser: browser).frame(minHeight: 120, idealHeight: 180)
                    }.frame(minHeight: 260)
                }
                HStack {
                    Text("\(browser.entries.count) indexed folders · \(Formatting.bytes(browser.current?.alloc ?? 0)) scan allocation · direct files remain Other")
                    Spacer()
                    if browser.nextOffset != nil {
                        if browser.entries.count < DirBrowser.rowLimit {
                            Button("Load More Folders") { browser.loadMore() }.disabled(browser.isLoading)
                        } else {
                            Text("2,048-row limit · use name search to find more")
                        }
                    }
                }.font(.caption).padding(8)
            }
        }
        .searchable(text: $browser.searchText, placement: .toolbar, prompt: "Search names in selected root")
    }
}

private struct ExploreRow: Identifiable, Sendable {
    let id: String
    let name: String
    let alloc: UInt64
    let files: UInt64
    let directory: DirEntry?
}

struct ExploreTable: View {
    let browser: DirBrowser
    let store: AuditStore
    let rows: [DirEntry]
    @State private var presented: [ExploreRow] = []
    @State private var presentedSource: [DirEntry] = []
    @State private var sortOrder: [KeyPathComparator<ExploreRow>] = [.init(\.alloc, order: .reverse)]

    var body: some View {
        @Bindable var browser = browser
        Table(presentedSource == rows ? presented : [], selection: selection, sortOrder: $sortOrder) {
            TableColumn("Name", value: \.name) { entry in
                Label(entry.name, systemImage: "folder").lineLimit(1)
                    .accessibilityAction(named: Text("Select Folder")) { browser.selectedPath = entry.id }
                    .accessibilityAction(named: Text("Open Folder")) {
                        if let directory = entry.directory {
                            browser.descend(directory)
                        }
                    }
            }.width(min: 160, ideal: 280)
            TableColumn("Allocated", value: \.alloc) { entry in
                Text(Formatting.bytes(entry.alloc)).monospacedDigit()
            }.width(min: 80, ideal: 110)
            TableColumn("Unique files", value: \.files) { entry in Text(Formatting.count(entry.files)) }.width(100)
            TableColumn("Path") { entry in Text(entry.id).lineLimit(1).truncationMode(.middle) }
        }
        .contextMenu(forSelectionType: String.self) { paths in
            if let path = paths.first, let entry = presented.first(where: { $0.id == path }) {
                if let directory = entry.directory {
                    Button("Open Folder") { browser.descend(directory) }
                }
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(path, forType: .string)
                }
                Button("Show Audit Findings Here") {
                    store.showFindings(under: path)
                }
            }
        } primaryAction: { paths in
            if let path = paths.first, let entry = rows.first(where: { $0.path == path }) {
                browser.descend(entry)
            }
        }
        .onKeyPress(.return) {
            guard let entry = browser.selectedEntry else { return .ignored }
            browser.descend(entry)
            return .handled
        }
        .accessibilityLabel("Indexed folders, sorted by allocated size")
        .task(id: rows) { await prepareRows() }
        .task(id: sortOrder) { await prepareRows() }
        .task(id: browser.searchText) { await prepareRows() }
        .onChange(of: browser.current?.path) { _, _ in presented = [] }
    }

    private var selection: Binding<String?> {
        Binding(get: {
            presented.contains(where: { $0.id == browser.selectedPath }) ? browser.selectedPath : nil
        }, set: { value in
            if value == nil, !presented.contains(where: { $0.id == browser.selectedPath }) {
                return
            }
            browser.selectedPath = value
        })
    }

    private func prepareRows() async {
        let order = sortOrder
        let directories = rows
        let result = await Task.detached {
            let folders = directories.map { ExploreRow(id: $0.path, name: $0.name, alloc: $0.alloc, files: $0.files, directory: $0) }
            return folders.sorted(using: order)
        }.value
        guard !Task.isCancelled, rows == directories, sortOrder == order else { return }
        presented = result
        presentedSource = directories
    }
}

struct LiveFilesTable: View {
    let browser: DirBrowser
    var isSearch = false
    @Environment(\.locale) private var locale
    @Environment(\.timeZone) private var timeZone
    @State private var presented: [TopFile] = []
    @State private var presentedRevision: UInt64?
    @State private var sortOrder: [KeyPathComparator<TopFile>] = [.init(\.alloc, order: .reverse)]

    var body: some View {
        @Bindable var browser = browser
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(isSearch ? "Live filename matches · not scan allocation" : "Live largest direct files · not part of scan treemap")
                Spacer()
                if let observedAt = isSearch ? browser.searchObservedAt : browser.liveFilesObservedAt {
                    Text("Observed \(observedAt.formatted(Date.FormatStyle(date: .abbreviated, time: .standard, locale: locale, timeZone: timeZone)))")
                }
            }.font(.caption).foregroundStyle(.secondary).padding(8)
            Text(isSearch ? browser.searchCoverage : browser.liveFilesCoverage).font(.caption).foregroundStyle(.secondary).padding(.horizontal, 8)
            Table(presentedRevision == browser.revision ? presented : [], selection: selection, sortOrder: $sortOrder) {
                TableColumn("Live file", value: \.path) { file in
                    Label((file.path as NSString).lastPathComponent, systemImage: "doc").lineLimit(1)
                        .accessibilityAction(named: Text("Select Live File")) { browser.selectedPath = file.path }
                }.width(min: 160, ideal: 280)
                TableColumn("Live allocated", value: \.alloc) { file in
                    Text(Formatting.bytes(file.alloc)).monospacedDigit()
                }.width(min: 100, ideal: 120)
                TableColumn("Path") { file in Text(file.path).lineLimit(1).truncationMode(.middle) }
            }
            .accessibilityLabel("Live file observations, separate from indexed folder allocation")
            .contextMenu(forSelectionType: String.self) { paths in
                if let path = paths.first {
                    if isSearch, let file = browser.searchFiles.first(where: { $0.path == path }) {
                        Button("Open Enclosing Folder") { browser.openParent(of: file) }
                    }
                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                    Button("Copy Path") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(path, forType: .string)
                    }
                }
            } primaryAction: { paths in
                if isSearch, let path = paths.first, let file = browser.searchFiles.first(where: { $0.path == path }) {
                    browser.openParent(of: file)
                }
            }
            .task(id: browser.revision) { await prepareRows() }
            .task(id: sortOrder) { await prepareRows() }
            .onChange(of: browser.current?.path) { _, _ in presented = [] }
        }
    }

    private var selection: Binding<String?> {
        Binding(get: {
            presented.contains(where: { $0.path == browser.selectedPath }) ? browser.selectedPath : nil
        }, set: { value in
            if value == nil, !presented.contains(where: { $0.path == browser.selectedPath }) {
                return
            }
            browser.selectedPath = value
        })
    }

    private func prepareRows() async {
        let generation = browser.revision
        let files = isSearch ? browser.searchFiles : browser.topFiles
        let order = sortOrder
        let result = await Task.detached { files.sorted(using: order) }.value
        guard !Task.isCancelled, browser.revision == generation, sortOrder == order else { return }
        presented = result
        presentedRevision = generation
    }
}

private struct SceneKey: Hashable {
    var runId: UInt64?
    var path: String?
    var nodeRevision: UInt64?
    var loadedCount: Int
    var incomplete: Bool
    var width: Int
    var height: Int
}

struct ExploreTreemap: View {
    let browser: DirBrowser
    @State private var scene = ExploreScene(tiles: [], labels: [])
    @State private var cache = PresentationCache<SceneKey, ExploreScene>(capacity: 3)
    @State private var sceneKey: SceneKey?
    @State private var hover: String?

    private func key(for size: CGSize) -> SceneKey {
        SceneKey(runId: browser.metadata?.runId, path: browser.current?.path,
                 nodeRevision: browser.current?.nodeRevision, loadedCount: browser.entries.count,
                 incomplete: browser.nextOffset != nil, width: Int(size.width), height: Int(size.height))
    }

    var body: some View {
        GeometryReader { geometry in
            let key = key(for: geometry.size)
            ZStack(alignment: .topLeading) {
                Canvas(rendersAsynchronously: true) { context, _ in
                    for tile in scene.tiles {
                        let fill: Color = switch tile.kind {
                        case .directory: .blue.opacity(0.5)
                        case .residual: .gray.opacity(0.25)
                        }
                        context.fill(Path(tile.rect), with: .color(fill))
                        context.stroke(Path(tile.rect), with: .color(Color(nsColor: .windowBackgroundColor)), lineWidth: 1)
                        if scene.labels.contains(tile.id) {
                            context.drawLayer { layer in
                                layer.clip(to: Path(tile.rect.insetBy(dx: 4, dy: 2)))
                                layer.draw(Text(tile.title).font(.caption), at: CGPoint(x: tile.rect.minX + 5, y: tile.rect.minY + 3), anchor: .topLeading)
                                layer.draw(Text(Formatting.bytes(tile.bytes)).font(.caption2), at: CGPoint(x: tile.rect.minX + 5, y: tile.rect.minY + 20), anchor: .topLeading)
                            }
                        }
                    }
                }
                .accessibilityHidden(true)
                if let selected = browser.selectedPath, let tile = scene.tiles.first(where: { $0.id == selected }) {
                    Path(tile.rect.insetBy(dx: 1, dy: 1)).stroke(Color.accentColor, lineWidth: 3).allowsHitTesting(false)
                }
                if let hover, let tile = scene.tiles.first(where: { $0.id == hover }) {
                    Text("\(tile.title) · \(Formatting.bytes(tile.bytes))")
                        .font(.caption).padding(5).background(.regularMaterial).allowsHitTesting(false)
                }
            }
            .opacity(sceneKey == key ? 1 : 0)
            .contentShape(Rectangle())
            .onTapGesture(count: 2) { point in
                guard sceneKey == key, let tile = scene.tiles.first(where: { $0.rect.contains(point) }),
                      let entry = browser.entries.first(where: { $0.path == tile.id }) else { return }
                browser.descend(entry)
            }
            .onTapGesture { point in
                guard sceneKey == key, let tile = scene.tiles.first(where: { $0.rect.contains(point) }), tile.kind != .residual else { return }
                browser.selectedPath = tile.id
            }
            .onContinuousHover { phase in
                switch phase {
                case let .active(point): hover = scene.tiles.first(where: { $0.rect.contains(point) })?.id
                case .ended: hover = nil
                }
            }
            .accessibilityLabel("Allocated space treemap")
            .focusable()
            .onKeyPress(.rightArrow) { moveSelection(by: 1); return .handled }
            .onKeyPress(.leftArrow) { moveSelection(by: -1); return .handled }
            .onKeyPress(.downArrow) { moveSelection(by: 1); return .handled }
            .onKeyPress(.upArrow) { moveSelection(by: -1); return .handled }
            .onKeyPress(.return) {
                guard let entry = browser.selectedEntry else { return .ignored }
                browser.descend(entry)
                return .handled
            }
            .onKeyPress(.escape) { browser.selectedPath = nil; return .handled }
            .accessibilityChildren {
                ForEach(scene.tiles.prefix(ExploreScene.labelLimit)) { tile in
                    Button("\(tile.title), \(Formatting.bytes(tile.bytes))") {
                        if tile.kind != .residual {
                            browser.selectedPath = tile.id
                        }
                    }
                    .accessibilityAddTraits(browser.selectedPath == tile.id ? .isSelected : [])
                    .accessibilityAction(named: Text("Open Folder")) {
                        if let entry = browser.entries.first(where: { $0.path == tile.id }) {
                            browser.descend(entry)
                        }
                    }
                }
            }
            .contextMenu {
                if let path = browser.selectedPath {
                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                    Button("Copy Path") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(path, forType: .string)
                    }
                }
            }
            .task(id: key) {
                if sceneKey?.runId != key.runId || sceneKey?.path != key.path || sceneKey?.nodeRevision != key.nodeRevision {
                    cache.removeAll()
                }
                if let cached = cache.value(for: key) {
                    let started = PresentationTrace.start()
                    scene = cached
                    sceneKey = key
                    PresentationTrace.finish("explore.scene.cache", since: started, run: key.runId,
                                             revision: key.nodeRevision, rows: cached.tiles.count,
                                             cacheHit: true, mainActor: true)
                    return
                }
                let current = browser.current
                let entries = browser.entries
                let pageMetadata = browser.pageMetadata
                let incomplete = browser.nextOffset != nil
                let size = geometry.size
                let rendered = await Task.detached {
                    let started = PresentationTrace.start()
                    let scene = ExploreScene.build(current: current, entries: entries, incomplete: incomplete,
                                                   size: size, pageMetadata: pageMetadata)
                    PresentationTrace.finish("explore.scene.layout", since: started, run: key.runId,
                                             revision: key.nodeRevision, rows: scene.tiles.count, cacheHit: false)
                    return scene
                }.value
                guard !Task.isCancelled, self.key(for: size) == key else { return }
                let started = PresentationTrace.start()
                cache.insert(rendered, for: key)
                scene = rendered
                sceneKey = key
                PresentationTrace.finish("explore.scene.install", since: started, run: key.runId,
                                         revision: key.nodeRevision, rows: rendered.tiles.count, mainActor: true)
            }
        }
    }

    private func moveSelection(by offset: Int) {
        let selectable = scene.tiles.filter { $0.kind != .residual }
        guard !selectable.isEmpty else { return }
        let current = selectable.firstIndex(where: { $0.id == browser.selectedPath }) ?? (offset > 0 ? -1 : selectable.count)
        let next = min(selectable.count - 1, max(0, current + offset))
        browser.selectedPath = selectable[next].id
    }
}

struct RootSheet: View {
    let store: AuditStore
    @State private var path = ""
    @FocusState private var pathFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Explore a Folder").font(.title2)
            TextField("Folder path, ~/cf-repos, or a path relative to Home", text: $path)
                .focused($pathFocused)
                .onSubmit { store.changeRoot(path) }
                .disabled(store.isStartingRun)
            HStack {
                Button("Home") { path = "~"; pathFocused = true }
                Button("Boot Volume") { path = "/"; pathFocused = true }
                Text("Or enter any folder path above.").font(.caption).foregroundStyle(.secondary)
            }.disabled(store.isStartingRun)
            if store.isStartingRun {
                ProgressView("Validating root…").controlSize(.small)
            } else if let error = store.rootError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { store.sheetRoute = nil }.keyboardShortcut(.cancelAction).disabled(store.isStartingRun)
                Button("Use Root and Refresh All") { store.changeRoot(path) }
                    .keyboardShortcut(.defaultAction).disabled(AuditStore.expandedRoot(path) == nil || !store.canRefresh)
            }
            Text("Accepted roots clear previous results. Relative paths use Home. Projects, Apps, and Audit remain global.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(20).frame(width: 540)
            .background(MemoryOnlyWindow())
            .onAppear { path = store.selectedRoot; pathFocused = true }
    }
}
