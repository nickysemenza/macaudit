import MacAuditKit
import SwiftUI

struct SectionSidebar: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        @Bindable var store = store
        List(store.sections, id: \.id, selection: $store.selectedSection) { meta in
            SectionRow(meta: meta)
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
                    Text(Formatting.bytes(store.totalReclaimableBytes)).monospacedDigit()
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
        case .scanning:
            ProgressView().controlSize(.mini)
        case .done:
            HStack(spacing: 4) {
                if let delta = store.reclaimableDelta(in: meta.id) {
                    Text(Formatting.delta(delta))
                        .font(.caption2)
                        .foregroundStyle(delta > 0 ? .orange : .green)
                        .monospacedDigit()
                }
                Text("\(store.count(of: meta.id))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
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
        case .launchd: "gearshape.2"
        case .shellEnv: "terminal"
        case .runtimes: "cube.box"
        case .docker: "shippingbox"
        case .ports: "network"
        case .git: "arrow.triangle.branch"
        case .simulator: "iphone"
        case .sshKeys: "key"
        case .tmSnapshots: "clock.arrow.2.circlepath"
        }
    }
}
