import AppKit
import SwiftUI

/// Callout shown wherever unreadable folders may be TCC's doing: the
/// Storage overview (one row) and the Folders inspector (`compact`, stacked
/// for a 280-pt column). Both layouts have constant intrinsic constraints —
/// no data-driven frame (see `ColumnSizing.swift`).
struct FullDiskAccessBanner: View {
    let store: AuditStore
    var compact = false

    var body: some View {
        Group {
            if compact {
                VStack(alignment: .leading, spacing: 8) {
                    message
                    HStack(spacing: 8) {
                        openSettings
                        rescan
                    }
                }
            } else {
                HStack(spacing: 10) {
                    message
                    Spacer()
                    openSettings
                    rescan
                }
            }
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
    }

    private var message: some View {
        Label {
            Text("Some folders can't be read without Full Disk Access.")
                .lineLimit(compact ? 3 : 1)
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "lock.shield").foregroundStyle(.orange)
        }
    }

    private var openSettings: some View {
        Button("Open Privacy Settings…") {
            NSWorkspace.shared.open(
                URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
        }
    }

    private var rescan: some View {
        Button("Rescan Disk") { store.rescan(.fs) }
    }
}
