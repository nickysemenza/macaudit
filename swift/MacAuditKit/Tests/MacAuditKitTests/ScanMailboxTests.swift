import Foundation
import Testing
@testable import MacAuditKit

private func mailboxFinding(id: UInt64, title: String) -> Finding {
    Finding(id: id, kind: .project, section: .projects, group: "Project", title: title,
        detail: "", path: nil, sizeBytes: nil, lastUsed: nil, severity: .info, remedies: [],
        provenance: nil, coverage: nil, metaJson: "{}")
}

@Test func boundedPresentationKeepsLatestUpsertsAndInvalidates() async {
    let mailbox = ScanMailbox()
    mailbox.activate(runId: 1)
    for index in 0..<2_000 {
        mailbox.onEvent(event: .findings(section: .projects, gen: 1,
            findings: [mailboxFinding(id: UInt64(index), title: "row \(index)")]))
    }
    mailbox.onEvent(event: .enriched(gen: 1, findings: [mailboxFinding(id: 12, title: "updated")]))
    mailbox.onEvent(event: .sectionFinished(section: .projects, gen: 1, durationMs: 10))
    let snapshot = await mailbox.snapshot()
    #expect(snapshot.sections[.projects]?.findings.count == ScanMailbox.maximumRowsPerSection)
    #expect(snapshot.sections[.projects]?.truncated == true)
    #expect(snapshot.sections[.projects]?.findings.first(where: { $0.id == 12 })?.title == "updated")
    #expect(snapshot.sections[.projects]?.terminal == true)
    #expect(snapshot.sections[.projects]?.durationMs == 10)
    #expect(snapshot.sections[.projects]?.revision == 2_001)
    mailbox.finish()
    var wakes = 0
    for await _ in mailbox.updates { wakes += 1 }
    #expect(wakes == 1)
}

@Test func retiredRunCallbacksCannotRestoreOldFindings() async {
    let mailbox = ScanMailbox()
    mailbox.onEvent(event: .findings(section: .projects, gen: 1,
        findings: [mailboxFinding(id: 1, title: "old")]))
    mailbox.activate(runId: 2)
    mailbox.onEvent(event: .enriched(gen: 1, findings: [mailboxFinding(id: 1, title: "stale")]))
    mailbox.onEvent(event: .sectionFinished(section: .projects, gen: 1, durationMs: 10))
    mailbox.onEvent(event: .findings(section: .projects, gen: 2,
        findings: [mailboxFinding(id: 2, title: "new")]))
    mailbox.activate(runId: 2)
    let snapshot = await mailbox.snapshot()
    #expect(snapshot.runId == 2)
    #expect(snapshot.sections[.projects]?.findings.map(\.id) == [2])
    #expect(snapshot.sections[.projects]?.terminal == false)
    #expect(snapshot.sections[.projects]?.truncated == false)
    mailbox.finish()
    mailbox.onEvent(event: .findings(section: .projects, gen: 3,
        findings: [mailboxFinding(id: 3, title: "closed")]))
    #expect(await mailbox.snapshot().runId == 2)
}

@Test func partialInventoryInvalidatesBeforeSectionFinishes() async {
    let mailbox = ScanMailbox()
    mailbox.activate(runId: 4)
    mailbox.onEvent(event: .findings(section: .fs, gen: 4, findings: []))
    let snapshot = await mailbox.snapshot()
    #expect(snapshot.sections[.fs]?.revision == 1)
    #expect(snapshot.sections[.fs]?.findings.isEmpty == true)
    #expect(snapshot.sections[.fs]?.terminal == false)
    mailbox.finish()
}
