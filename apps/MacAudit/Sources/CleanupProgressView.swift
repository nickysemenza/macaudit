import AppKit
import MacAuditKit
import SwiftUI

struct CleanupProgressView: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        if let run = store.cleanup {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text(title(run.phase)).font(.title2.weight(.semibold))
                    Spacer()
                    if case .executing(let i, let total) = run.phase {
                        Text("\(i + 1) of \(total)").foregroundStyle(.secondary).monospacedDigit()
                    }
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(run.actions.enumerated()), id: \.offset) { i, a in
                            let running: Bool = {
                                if case .executing(let idx, _) = run.phase { return idx == i && run.results[i] == nil }
                                return false
                            }()
                            ActionLine(index: i, action: a, status: run.results[i], running: running)
                        }
                        if !run.cancelled.isEmpty {
                            Text("Cancelled").font(.headline)
                            ForEach(Array(run.cancelled.enumerated()), id: \.offset) { _, a in
                                Text(a.rendered).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                        if !run.refused.isEmpty {
                            Text("Refused").font(.headline)
                            ForEach(Array(run.refused.enumerated()), id: \.offset) { _, r in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(r.action.rendered).font(.caption.monospaced()).strikethrough()
                                    Text(r.reason).font(.caption).foregroundStyle(.red)
                                }
                            }
                        }
                        if let summary = run.summary {
                            Divider()
                            Text(summary).font(.callout).textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack {
                    if let path = run.reportPath {
                        Button("Show Report") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                        }
                    }
                    Spacer()
                    if case .done = run.phase {
                        Button("Done") { store.dismissCleanup() }.keyboardShortcut(.defaultAction)
                    } else {
                        Button(run.cancelRequested ? "Stopping after this action…" : "Stop") {
                            store.cancelCleanup()
                        }
                        .disabled(run.cancelRequested)
                    }
                }
            }
            .padding(20)
            .frame(minWidth: 560, idealWidth: 680, minHeight: 320, idealHeight: 480)
            .interactiveDismissDisabled(!isDone(run.phase))
        }
    }

    private func isDone(_ p: CleanupRun.Phase) -> Bool {
        if case .done = p { return true }
        return false
    }

    private func title(_ phase: CleanupRun.Phase) -> String {
        switch phase {
        case .preflight: "Re-checking targets…"
        case .executing: "Running cleanup"
        case .verifying: "Verifying retained tools…"
        case .done: "Cleanup finished"
        }
    }
}
