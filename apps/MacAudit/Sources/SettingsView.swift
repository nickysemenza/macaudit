import MacAuditKit
import SwiftUI

struct SettingsView: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        Form {
            LabeledContent("Deletions") {
                Text(store.engine.deleteMode() == .rm ? "rm -rf (permanent)" : "Move to Trash")
            }
            LabeledContent("Config file") {
                Text(store.engine.configPath()).textSelection(.enabled)
            }
            Text("Presentation settings last only for this session. Choose the Explore root in the toolbar. Launch with MACAUDIT_FAKE=1 for demo data or MACAUDIT_OFFLINE=1 to skip network enrichment.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .padding()
    }
}
