import AppKit
import SwiftUI

@MainActor
enum WindowMemoryPolicy {
    static func apply(to window: NSWindow) {
        window.isRestorable = false
        window.restorationClass = nil
        window.setFrameAutosaveName("")
        window.disableSnapshotRestoration()
    }
}

struct MemoryOnlyWindow: NSViewRepresentable {
    func makeNSView(context _: Context) -> MemoryOnlyWindowView {
        MemoryOnlyWindowView()
    }

    func updateNSView(_ view: MemoryOnlyWindowView, context _: Context) {
        view.configureWindow()
    }
}

final class MemoryOnlyWindowView: NSView {
    private weak var configuredWindow: NSWindow?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        configureWindow()
    }

    func configureWindow() {
        guard let window, window !== configuredWindow else { return }
        configuredWindow = window
        WindowMemoryPolicy.apply(to: window)
    }
}
