import AppKit
@testable import MacAudit
import MacAuditKit
import SnapshotTesting
import SwiftUI
import XCTest

@MainActor
final class RenderedPresentationTests: XCTestCase {
    private enum Fixture: String, CaseIterable {
        case treemapSelection, tables, inspector, empty, error
    }

    private let size = CGSize(width: 800, height: 600)

    func testRenderedFixtureSmoke() async throws {
        for fixture in Fixture.allCases {
            let image = try await render(fixture)
            let attachment = XCTAttachment(image: image)
            attachment.name = fixture.rawValue
            attachment.lifetime = .keepAlways
            add(attachment)
        }
    }

    func testTreemapSelectionImageOnMacOS15() async throws {
        try await compare(.treemapSelection)
    }

    func testTablesImageOnMacOS15() async throws {
        try await compare(.tables)
    }

    func testInspectorImageOnMacOS15() async throws {
        try await compare(.inspector)
    }

    func testEmptyImageOnMacOS15() async throws {
        try await compare(.empty)
    }

    func testErrorImageOnMacOS15() async throws {
        try await compare(.error)
    }

    private func compare(_ fixture: Fixture, testName: String = #function,
                         file: StaticString = #filePath, line: UInt = #line) async throws
    {
        let environment = ProcessInfo.processInfo.environment
        let recording = environment["MACAUDIT_RECORD_SNAPSHOTS"] == "1"
        let required = environment["MACAUDIT_REQUIRE_SNAPSHOTS"] == "1"
        guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 15 else {
            if required {
                XCTFail("Required image comparison must run on the pinned macOS 15 runner.", file: file, line: line)
                throw RenderFailure.referenceUnavailable
            }
            throw XCTSkip("Image references must be recorded and compared on the pinned macOS 15 runner.")
        }
        let snapshotDirectory = URL(fileURLWithPath: "\(file)").deletingLastPathComponent()
            .appendingPathComponent("__Snapshots__/RenderedPresentationTests", isDirectory: true)
        let snapshotName = "macos15-light-800x600"
        let sanitizedTestName = testName.replacingOccurrences(of: "\\W+", with: "-", options: .regularExpression)
            .replacingOccurrences(of: "^-|-$", with: "", options: .regularExpression)
        let reference = snapshotDirectory.appendingPathComponent("\(sanitizedTestName).\(snapshotName).png")
        guard recording || FileManager.default.fileExists(atPath: reference.path) else {
            let message = "Missing reviewed macOS 15 reference: \(reference.lastPathComponent). Record and review with MacAuditSnapshotReferences; image comparison is not verified."
            if required {
                XCTFail(message, file: file, line: line)
                throw RenderFailure.referenceUnavailable
            }
            throw XCTSkip(message)
        }
        let image = try await render(fixture)
        assertSnapshot(of: image, as: .image, named: snapshotName,
                       record: recording ? .all : .never,
                       file: file, testName: testName, line: line)
    }

    private func render(_ fixture: Fixture) async throws -> NSImage {
        let store = AuditStore(engine: FakeAppEngine(renderedFixture: true), usingFakeData: true, initialRoot: "/fixture")
        if fixture != .empty, fixture != .error {
            store.browser.refreshRoot()
            try await waitUntil { store.browser.root != nil && store.browser.liveFiles != nil && !store.browser.isLoading }
            store.browser.selectedPath = "/fixture/Projects"
            if fixture == .inspector {
                store.browser.selectedPath = nil
            }
        } else if fixture == .error {
            store.changeRoot(" ")
            XCTAssertNotNil(store.rootError)
        }

        let content = switch fixture {
        case .treemapSelection:
            AnyView(ExploreTreemap(browser: store.browser).padding(12))
        case .tables:
            AnyView(VStack(spacing: 0) {
                Text("Indexed folders · scan allocation").font(.caption).padding(8)
                ExploreTable(browser: store.browser, store: store, rows: store.browser.entries)
                Divider()
                LiveFilesTable(browser: store.browser).frame(height: 220)
            })
        case .inspector:
            AnyView(ExploreInspector(browser: store.browser))
        case .empty, .error:
            AnyView(ExploreView(store: store))
        }
        let hosting = NSHostingView(rootView: content
            .environment(store)
            .environment(\.locale, Locale(identifier: "en_US_POSIX"))
            .environment(\.timeZone, TimeZone(secondsFromGMT: 0)!)
            .environment(\.colorScheme, .light)
            .environment(\.displayScale, 1)
            .tint(.blue)
            .transaction { $0.animation = nil }
            .frame(width: size.width, height: size.height)
            .background(Color(nsColor: .windowBackgroundColor)))
        hosting.frame = NSRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: hosting.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: .aqua)
        WindowMemoryPolicy.apply(to: window)
        window.contentView = hosting
        defer { window.close() }
        hosting.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(500))
        hosting.layoutSubtreeIfNeeded()
        hosting.displayIfNeeded()

        var captured: NSImage?
        Snapshotting<NSView, NSImage>.image(size: size).snapshot(hosting).run { captured = $0 }
        try await waitUntil { captured != nil }
        let source = try XCTUnwrap(captured)
        let bitmap = try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width),
                                                    pixelsHigh: Int(size.height), bitsPerSample: 8,
                                                    samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                                    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
        bitmap.size = size
        let context = try XCTUnwrap(NSGraphicsContext(bitmapImageRep: bitmap))
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        source.draw(in: NSRect(origin: .zero, size: size))
        NSGraphicsContext.restoreGraphicsState()
        let image = NSImage(size: size)
        image.addRepresentation(bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        XCTAssertGreaterThan(png.count, 3000, "The \(fixture.rawValue) fixture must render content, not an empty hosting view.")
        XCTAssertEqual(bitmap.pixelsWide, 800)
        XCTAssertEqual(bitmap.pixelsHigh, 600)
        return image
    }

    private func waitUntil(_ condition: @MainActor () -> Bool) async throws {
        for _ in 0 ..< 400 {
            if condition() {
                return
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("Timed out preparing a rendered fake-engine fixture")
        throw RenderFailure.timeout
    }

    private enum RenderFailure: Error { case timeout, referenceUnavailable }
}
