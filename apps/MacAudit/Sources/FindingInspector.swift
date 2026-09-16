import AppKit
import MacAuditKit
import SwiftUI

struct FindingInspector: View {
    @Environment(AuditStore.self) private var store
    let finding: Finding?

    var body: some View {
        if let f = finding {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header(f)
                    if !f.detail.isEmpty {
                        Text(f.detail).font(.callout).textSelection(.enabled)
                    }
                    facts(f)
                    if let d = IosDeviceStorage(f) { iosStorage(d) }
                    if let a = IosAppUsage(f) { iosApp(a) }
                    if !f.remedies.isEmpty { remedies(f) }
                    if let text = f.coverage { note("Coverage", text) }
                    if let text = f.provenance { note("Provenance", text) }
                    meta(f)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("No selection", systemImage: "info.circle")
        }
    }

    private func header(_ f: Finding) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Text(f.title).font(.title3.weight(.semibold)).textSelection(.enabled)
                Spacer()
                SeverityBadge(severity: f.severity)
            }
            HStack {
                MarkToggle(store: store, id: f.id)
                Text(store.marked.contains(f.id) ? "Marked for cleanup" : "Mark for cleanup")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func facts(_ f: Finding) -> some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
            if let path = f.path {
                GridRow {
                    Text("Path").foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        Text(path).textSelection(.enabled).lineLimit(3).truncationMode(.middle)
                        Button {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                        } label: {
                            Image(systemName: "arrow.up.forward.app")
                        }
                        .buttonStyle(.borderless)
                        .help("Reveal in Finder")
                    }
                }
            }
            if let bytes = f.sizeBytes {
                GridRow {
                    Text("Size").foregroundStyle(.secondary)
                    Text(Formatting.bytes(bytes)).monospacedDigit()
                }
            }
            if let used = f.lastUsed {
                GridRow {
                    Text("Last used").foregroundStyle(.secondary)
                    Text("\(Formatting.age(used)) · \(used.formatted(date: .abbreviated, time: .shortened))")
                }
            }
            GridRow {
                Text("Kind").foregroundStyle(.secondary)
                Text("\(f.kind)")
            }
        }
        .font(.callout)
    }

    private func remedies(_ f: Finding) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Remedies").font(.headline)
            let choice = store.remedyChoice[f.id]
            ForEach(Array(f.remedies.enumerated()), id: \.offset) { index, r in
                HStack(alignment: .top, spacing: 8) {
                    Button {
                        store.chooseRemedy(choice == index ? nil : index, for: f.id)
                    } label: {
                        Image(systemName: choice == index ? "largecircle.fill.circle" : "circle")
                    }
                    .buttonStyle(.borderless)
                    .help(choice == index ? "Using this remedy for the batch" : "Use this remedy for the batch")
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(r.label)
                            if r.destructive {
                                Text("destructive").font(.caption2).foregroundStyle(.red)
                            }
                            if r.alternative {
                                Text("alternative").font(.caption2).foregroundStyle(.secondary)
                            }
                            if r.hasGuard {
                                Image(systemName: "lock.shield").font(.caption2).foregroundStyle(.secondary)
                                    .help("Re-checked against a fresh scan before it runs")
                            }
                        }
                        Text(r.rendered)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        if let bytes = r.reclaimsBytes {
                            Text("reclaims \(Formatting.bytes(bytes))").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Text("No radio selected: the batch runs every primary destructive remedy, else the first primary command.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    /// The raw meta grid would print `capacity_bytes 246266159104`; this is
    /// the same data with units and the one sentence each number needs.
    private func iosStorage(_ d: IosDeviceStorage) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Storage").font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 3) {
                let rows: [(String, String, String?)] = [
                    ("Capacity", Formatting.bytes(d.capacityBytes), nil),
                    ("Used", Formatting.bytes(d.usedBytes), "what Settings shows; includes purgeable"),
                    ("Free", Formatting.bytes(d.freeBytes), nil),
                    ("Purgeable", Formatting.bytes(d.purgeableBytes), "caches iOS frees on demand — Settings never shows this"),
                    ("Committed", Formatting.bytes(d.committedBytes), "stays used after iOS purges everything it can"),
                    ("Apps", "\(Formatting.bytes(d.appsBytes)) across \(d.appCount) apps", "bundle + data"),
                    ("Not attributed", Formatting.bytes(d.unattributedBytes), "media, Messages, system, purgeable caches"),
                ]
                ForEach(rows, id: \.0) { label, value, hint in
                    GridRow {
                        Text(label).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(value).monospacedDigit()
                            if let hint { Text(hint).font(.caption2).foregroundStyle(.tertiary) }
                        }
                    }
                }
            }
            .font(.callout)
        }
    }

    private func iosApp(_ a: IosAppUsage) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Storage").font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 3) {
                GridRow {
                    Text("App").foregroundStyle(.secondary)
                    Text(Formatting.bytes(a.staticBytes)).monospacedDigit()
                }
                GridRow {
                    Text("Data").foregroundStyle(.secondary)
                    Text(Formatting.bytes(a.dynamicBytes)).monospacedDigit()
                }
                GridRow {
                    Text("Bundle ID").foregroundStyle(.secondary)
                    Text(a.bundleId).textSelection(.enabled)
                }
                if let v = a.version {
                    GridRow {
                        Text("Version").foregroundStyle(.secondary)
                        Text(v)
                    }
                }
            }
            .font(.callout)
        }
    }

    private func note(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            Text(body).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }

    @ViewBuilder
    private func meta(_ f: Finding) -> some View {
        let pairs = metaPairs(f.metaJson)
        if !pairs.isEmpty {
            DisclosureGroup("Details") {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 3) {
                    ForEach(pairs, id: \.0) { key, value in
                        GridRow {
                            Text(key).foregroundStyle(.secondary)
                            Text(value).textSelection(.enabled).lineLimit(4)
                        }
                    }
                }
                .font(.caption)
            }
        }
    }

    private func metaPairs(_ json: String) -> [(String, String)] {
        guard let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return [] }
        return object.keys.sorted().map { key in
            let v = object[key]!
            let text: String
            if let s = v as? String {
                text = s
            } else if let d = try? JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed, .sortedKeys]),
                let s = String(data: d, encoding: .utf8)
            {
                text = s
            } else {
                text = "\(v)"
            }
            return (key, text)
        }
    }
}
