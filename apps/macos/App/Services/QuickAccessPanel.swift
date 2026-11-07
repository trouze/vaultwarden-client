import AppKit
import SwiftUI

private final class QuickAccessPanel: NSPanel {
    var dismiss: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
    override func cancelOperation(_ sender: Any?) { dismiss?() }
}

@MainActor
final class QuickAccessPanelController: NSObject, NSWindowDelegate {
    private let model: QuickAccessModel
    private let panel: QuickAccessPanel

    init(model: QuickAccessModel, copier: CopyCoordinator, openVault: @escaping () -> Void) {
        self.model = model
        panel = QuickAccessPanel(
            contentRect: NSRect(x: 0, y: 0, width: 580, height: 520),
            styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered, defer: false
        )
        super.init()
        panel.title = "Vaultwarden Quick Access"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.delegate = self
        panel.dismiss = { [weak self] in self?.hide() }
        panel.contentView = NSHostingView(rootView: QuickAccessView(
            model: model, copier: copier, dismiss: { [weak self] in self?.hide() }, openVault: openVault
        ))
    }

    func toggle() {
        if panel.isVisible { hide() } else { show() }
    }

    func show() {
        model.open()
        let mouse = NSEvent.mouseLocation
        if let screen = NSScreen.screens.first(where: { $0.frame.contains(mouse) }) ?? NSScreen.main {
            let area = screen.visibleFrame
            let size = panel.frame.size
            panel.setFrameOrigin(NSPoint(x: area.midX - size.width / 2, y: area.midY - size.height / 2))
        }
        // Nonactivating key panel: copying can return focus to the previous app
        // without synthesizing keystrokes or inspecting that app's contents.
        panel.makeKeyAndOrderFront(nil)
    }

    func hide() {
        panel.orderOut(nil)
        model.close()
    }

    func windowDidResignKey(_ notification: Notification) { hide() }
}
