import AppKit
import MacAuditKit
import SwiftUI

struct ExploreInspector: View {
    let browser: DirBrowser
    @Environment(\.locale) private var locale
    @Environment(\.timeZone) private var timeZone

    private var selectedFile: TopFile? {
        let files = browser.searchText.isEmpty ? browser.topFiles : browser.searchFiles
        return files.first { $0.path == browser.selectedPath }
    }

    var body: some View {
        if let path = browser.selectedPath, let file = selectedFile {
            VStack(alignment: .leading, spacing: 12) {
                Label((path as NSString).lastPathComponent, systemImage: "doc").font(.headline)
                LabeledContent("Live allocated", value: Formatting.bytes(file.alloc))
                if let observedAt = browser.searchText.isEmpty ? browser.liveFilesObservedAt : browser.searchObservedAt {
                    LabeledContent("Observed", value: observedAt.formatted(Date.FormatStyle(date: .abbreviated, time: .standard, locale: locale, timeZone: timeZone)))
                }
                Text("Live metadata, not a scan observation. File matches never change scanned folder totals or treemap allocation.")
                    .font(.caption).foregroundStyle(.secondary)
                Text(browser.searchText.isEmpty ? browser.liveFilesCoverage : browser.searchCoverage).font(.caption).foregroundStyle(.secondary)
                if browser.searchCancelled { Text("Search cancelled · incomplete results").font(.caption).foregroundStyle(.orange) }
                if browser.searchTruncated { Text("Search truncated at 1,000 matches").font(.caption).foregroundStyle(.secondary) }
                Text(path).font(.caption).textSelection(.enabled)
                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                Button("Open Enclosing Folder") { browser.openParent(of: file) }
                Text("Explore is read-only. Cleanup is available only for eligible Audit findings.").font(.caption).foregroundStyle(.secondary)
                Spacer()
            }.padding()
        } else {
            DirInspector(entry: browser.selectedEntry ?? browser.current)
                .id(browser.selectedEntry?.path ?? browser.current?.path)
        }
    }
}
