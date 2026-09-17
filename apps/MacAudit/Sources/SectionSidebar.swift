import MacAuditKit
import SwiftUI

struct SectionSidebar: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        @Bindable var store = store
        List(selection: $store.selectedItem) {
            Label("Storage", systemImage: "internaldrive")
                .tag(SidebarItem.storage)
            Label("Projects", systemImage: "folder.badge.gearshape")
                .tag(SidebarItem.projects)
            Label("Apps", systemImage: "app.badge")
                .tag(SidebarItem.apps)
            Label("Folders", systemImage: "folder")
                .tag(SidebarItem.folders)
            Section("Sections") {
                // Projects/App Storage are top-level lenses above, not
                // generic scanner sections — kept out of this list and the
                // Rescan-All menu (`MacAuditApp.swift`) the same way.
                ForEach(store.sections.filter { $0.id != .projects && $0.id != .appStorage }, id: \.id) { meta in
                    SectionRow(meta: meta).tag(SidebarItem.section(meta.id))
                }
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 200, ideal: 240)
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                if store.usingFakeData {
                    Label("Fake data", systemImage: "wand.and.stars")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                HStack {
                    Text("Reclaimable")
                    Spacer()
                    Text(Formatting.bytes(store.totalReclaimableBytes))
                        .monospacedDigit()
                        .contentTransition(.numericText())
                        .animation(.default, value: store.totalReclaimableBytes)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if let last = store.activity.last {
                    Text(last)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.bar)
        }
        // Outermost on purpose: the footer above is the sidebar's churn source.
        .stableColumnSize()
    }
}

private struct SectionRow: View {
    @Environment(AuditStore.self) private var store
    let meta: SectionMeta

    var body: some View {
        let status = store.status(of: meta.id)
        HStack(spacing: 8) {
            Image(systemName: icon)
                .frame(width: 18)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(meta.title)
                if case .done = status, store.reclaimableBytes(in: meta.id) > 0 {
                    Text(Formatting.bytes(store.reclaimableBytes(in: meta.id)))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            Spacer()
            trailing(status)
        }
        .contextMenu {
            Button("Rescan \(meta.title)") { store.rescan(meta.id) }
        }
    }

    @ViewBuilder
    private func trailing(_ status: SectionStatus) -> some View {
        switch status {
        case .idle:
            EmptyView()
        case .scanning(let msg, let done, let total):
            Group {
                if let total, total > 0 {
                    ProgressView(value: Double(done), total: Double(total))
                        .progressViewStyle(.circular)
                } else {
                    ProgressView()
                }
            }
            .controlSize(.mini)
            .help(msg.isEmpty ? "scanning" : msg)
        case .done:
            HStack(spacing: 4) {
                Text("\(store.count(of: meta.id))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .contentTransition(.numericText())
                    .animation(.default, value: store.count(of: meta.id))
            }
        case .failed:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .help("scan failed")
        }
    }

    private var icon: String {
        switch meta.id {
        case .system: "gauge.with.dots.needle.33percent"
        case .apps: "app.badge"
        case .brew: "mug"
        case .tools: "wrench.and.screwdriver"
        case .fs: "internaldrive"
        case .projects: "folder.badge.gearshape"
        case .appStorage: "app.badge"
        case .launchd: "gearshape.2"
        case .shellEnv: "terminal"
        case .runtimes: "cube.box"
        case .docker: "shippingbox"
        case .ports: "network"
        case .git: "arrow.triangle.branch"
        case .simulator: "iphone"
        case .ios: "iphone.gen3"
        case .sshKeys: "key"
        case .timeMachine: "clock.arrow.2.circlepath"
        }
    }
}
