import SwiftUI

/// Callout shown wherever an owner or entry's bytes are an APFS clone (or
/// hard-linked import) of some shared store: the owner entity page
/// (`OwnerDetailView`, when `Footprint.cloneNote`) and any entry row whose
/// `cloneOfStore` is set. Same shape as `FullDiskAccessBanner` — constant
/// intrinsic constraints, no data-driven frame (see `ColumnSizing.swift`).
struct ApfsCloneNote: View {
    let store: AuditStore
    var compact = false

    var body: some View {
        Group {
            if compact {
                VStack(alignment: .leading, spacing: 8) {
                    message
                    learnMore
                }
            } else {
                HStack(spacing: 10) {
                    message
                    Spacer()
                    learnMore
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
            Text(
                "node_modules here is an APFS clone of the pnpm store — those bytes are shared with the store and are not freed by deleting node_modules."
            )
            .lineLimit(compact ? 4 : 1)
            .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "doc.on.doc").foregroundStyle(.blue)
        }
    }

    private var learnMore: some View {
        LearnMoreButton()
    }
}

/// Split out so `@State` for the popover doesn't force `ApfsCloneNote`
/// itself to own presentation state (kept a plain, cheaply-constructed
/// value type like `FullDiskAccessBanner`).
private struct LearnMoreButton: View {
    @State private var showing = false

    var body: some View {
        Button("Learn more…") { showing = true }
            .popover(isPresented: $showing, arrowEdge: .top) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("APFS clones & hard links").font(.headline)
                    Text(
                        "An APFS clone (or a hard-linked import) shares its on-disk blocks with another file or directory until one side is edited — deleting the clone alone frees nothing, since the original still holds those blocks. macaudit counts cloned/hard-linked bytes in an owner's reach, never its exclusive total, so cleanup estimates stay honest."
                    )
                    Text(
                        "Docker image/container sizes work similarly: layers are shared across images, so the size Docker reports (\"virtual\") overstates what deleting any one object actually reclaims — macaudit shows it for context only, never in a total."
                    )
                }
                .font(.callout)
                .frame(width: 320, alignment: .leading)
                .padding()
            }
    }
}
