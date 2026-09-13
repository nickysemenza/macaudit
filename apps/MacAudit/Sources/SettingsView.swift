import MacAuditKit
import SwiftUI

struct SettingsView: View {
    @Environment(AuditStore.self) private var store
    @AppStorage("useFakeData") private var useFakeData = false
    @AppStorage("offline") private var offline = false

    var body: some View {
        Form {
            LabeledContent("Deletions") {
                Text(store.engine.deleteMode() == .rm ? "rm -rf (permanent)" : "Move to Trash")
            }
            LabeledContent("Config file") {
                Text(store.engine.configPath()).textSelection(.enabled)
            }
            Toggle("Offline (skip network enrichment)", isOn: $offline)
            #if DEBUG
                Toggle("Use fake data", isOn: $useFakeData)
            #endif
            Text("Changes to these take effect on next launch. Delete mode and scan roots are set in the config file, shared with the CLI and TUI.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .padding()
    }
}
