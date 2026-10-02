import SwiftUI

struct AuditPageControls: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        HStack {
            if let location = store.auditPages.locationFilter {
                Text("\(store.auditPages.rows.count) matching findings on this page · \(store.auditPages.total) unfiltered section findings")
                    .font(.caption)
                Text(location).font(.caption).lineLimit(1).truncationMode(.middle)
                Button("Clear Location") { store.selectedFinding = nil; store.auditPages.filterLocation(nil) }
            } else {
                Text("\(store.auditPages.offset + (store.auditPages.rows.isEmpty ? 0 : 1))–\(store.auditPages.offset + UInt64(store.auditPages.rows.count)) of \(store.auditPages.total) · search, sort and charts: this page")
                    .font(.caption)
            }
            Spacer()
            if store.auditPages.isLoading {
                ProgressView().controlSize(.small)
            }
            Button("Previous Page") { store.selectedFinding = nil; store.auditPages.previous() }
                .disabled(!store.auditPages.canGoBack)
                .keyboardShortcut(.leftArrow, modifiers: [.command, .option])
            Button("Next Page") { store.selectedFinding = nil; store.auditPages.next() }
                .disabled(store.auditPages.nextOffset == nil || store.auditPages.isLoading)
                .keyboardShortcut(.rightArrow, modifiers: [.command, .option])
        }
        .padding(10)
        .background(.bar)
        if let error = store.auditPages.error {
            HStack {
                Text(error).foregroundStyle(.red)
                Button("Retry Page") { store.auditPages.invalidate() }
            }.padding(8)
        }
    }
}
