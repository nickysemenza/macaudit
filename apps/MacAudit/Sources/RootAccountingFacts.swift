import MacAuditKit
import SwiftUI

enum AccountingLabels {
    static func count(_ observed: UInt64?) -> String {
        observed.map(Formatting.count) ?? "Unknown (partial or unavailable)"
    }

    static func bytes(_ observed: UInt64?) -> String {
        observed.map(Formatting.bytes) ?? "Unknown (partial or unavailable)"
    }
}

struct RootAccountingFacts: View {
    let stats: DirTreeStats?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Selected root · scan accounting").fontWeight(.semibold)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 3) {
                GridRow {
                    Text("Directory entries").foregroundStyle(.secondary)
                    Text(AccountingLabels.count(stats?.directoryEntries))
                }
                GridRow {
                    Text("Unique files").foregroundStyle(.secondary)
                    Text(AccountingLabels.count(stats?.files))
                }
                GridRow {
                    Text("Externally linked allocation").foregroundStyle(.secondary)
                    Text(AccountingLabels.bytes(stats?.externallyLinkedBytes))
                }
            }
            Text("Allocation is not reclaimable space. Hard links are charged once; external links and shared extents can retain storage after deletion.")
                .foregroundStyle(.secondary)
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
