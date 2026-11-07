import AppKit
import Combine

/// Lifecycle/security services belong to the app, not a window that can close.
@MainActor
final class AppRuntime: ObservableObject {
    let preferences: Preferences
    let clipboard: SafeClipboard
    let copier: CopyCoordinator
    let shortcut = GlobalShortcut()
    let quickAccess: QuickAccessModel
    var openMainWindow: (() -> Void)?
    private let core: CoreAdapter
    private var panel: QuickAccessPanelController?
    private var timer: Timer?
    private var eventMonitor: Any?
    private var unlockActivity: NSObjectProtocol?
    private var subscriptions: Set<AnyCancellable> = []
    private var started = false

    init(core: CoreAdapter) {
        self.core = core
        preferences = Preferences()
        clipboard = SafeClipboard(writer: SystemClipboard())
        copier = CopyCoordinator(core: core, clipboard: clipboard, preferences: preferences)
        quickAccess = QuickAccessModel(core: core, copier: copier)
        NotificationCenter.default.publisher(for: NSApplication.didFinishLaunchingNotification)
            .sink { [weak self] _ in self?.start() }.store(in: &subscriptions)
        if NSApp?.isRunning == true { start() }
    }

    func start() {
        guard !started else { return }
        started = true
        Task { await core.inspectSavedCache() }
        core.$session.sink { [weak self] session in
            self?.keepDeadlinesActive(unlocked: session.state != .locked)
        }.store(in: &subscriptions)
        preferences.$shortcut.combineLatest(preferences.$globalShortcutEnabled)
            .sink { [weak self] shortcut, enabled in
                self?.shortcut.configure(enabled: enabled, shortcut: shortcut) { [weak self] in
                    self?.toggleQuickAccess()
                }
            }.store(in: &subscriptions)

        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            workspace.publisher(for: name).receive(on: RunLoop.main)
                .sink { [weak self] _ in self?.core.lock() }.store(in: &subscriptions)
        }
        NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)
            .sink { [weak self] _ in self?.shutdown() }.store(in: &subscriptions)

        // Only app-local interactions extend unlock. Never monitor other apps'
        // typing or request Accessibility permissions to keep the vault unlocked.
        eventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]) { [weak self] event in
            MainActor.assumeIsolated { self?.core.recordActivity() }
            return event
        }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.tick() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func toggleQuickAccess() {
        if panel == nil {
            panel = QuickAccessPanelController(model: quickAccess, copier: copier) { [weak self] in self?.openMainWindow?() }
        }
        panel?.toggle()
    }

    func tick() {
        core.lockIfInactive(timeout: TimeInterval(preferences.idleLock.rawValue))
        copier.tick()
    }

    func shutdown() {
        core.lock()
        clipboard.clearOwned()
        panel?.hide()
        shortcut.stop()
        timer?.invalidate()
        timer = nil
        keepDeadlinesActive(unlocked: false)
        if let eventMonitor { NSEvent.removeMonitor(eventMonitor) }
        eventMonitor = nil
        subscriptions.removeAll()
        started = false
        openMainWindow = nil
    }

    private func keepDeadlinesActive(unlocked: Bool) {
        if unlocked, unlockActivity == nil {
            // Keep App Nap from deferring security deadlines while unlocked,
            // but do not prevent system sleep or change system-wide settings.
            unlockActivity = ProcessInfo.processInfo.beginActivity(
                options: .userInitiatedAllowingIdleSystemSleep,
                reason: "Enforce vault lock and clipboard expiration deadlines"
            )
        } else if !unlocked, let unlockActivity {
            ProcessInfo.processInfo.endActivity(unlockActivity)
            self.unlockActivity = nil
        }
    }
}
