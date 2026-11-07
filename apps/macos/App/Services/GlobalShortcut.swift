import Carbon
import Combine

/// Registers a specific system hotkey, not a global keyboard monitor. No
/// Accessibility/Input Monitoring permission or arbitrary input collection.
@MainActor
final class GlobalShortcut: ObservableObject {
    @Published private(set) var errorMessage: String?
    private var hotKey: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private var action: (() -> Void)?
    private let signature: OSType = 0x56574B31 // VWK1

    func configure(enabled: Bool, shortcut: QuickAccessShortcut, action: @escaping () -> Void) {
        stop()
        errorMessage = nil
        guard enabled else { return }
        self.action = action
        var eventType = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let callback: EventHandlerUPP = { _, event, context in
            guard let context, let event else { return OSStatus(eventNotHandledErr) }
            // Application event-target handlers execute on the main event loop.
            return MainActor.assumeIsolated {
                let owner = Unmanaged<GlobalShortcut>.fromOpaque(context).takeUnretainedValue()
                var identifier = EventHotKeyID()
                let status = GetEventParameter(event, EventParamName(kEventParamDirectObject),
                    EventParamType(typeEventHotKeyID), nil, MemoryLayout<EventHotKeyID>.size, nil, &identifier)
                guard status == noErr, identifier.signature == owner.signature, identifier.id == 1 else {
                    return OSStatus(eventNotHandledErr)
                }
                owner.action?()
                return noErr
            }
        }
        let installed = InstallEventHandler(GetApplicationEventTarget(), callback, 1, &eventType,
            Unmanaged.passUnretained(self).toOpaque(), &handler)
        guard installed == noErr else {
            errorMessage = "Quick-access shortcut could not be registered. Use the menu bar instead."
            stop()
            return
        }
        let modifiers = shortcut == .controlShiftSpace ? UInt32(controlKey | shiftKey) : UInt32(controlKey | optionKey)
        let status = RegisterEventHotKey(UInt32(kVK_Space), modifiers,
            EventHotKeyID(signature: signature, id: 1), GetApplicationEventTarget(), 0, &hotKey)
        if status != noErr {
            errorMessage = "\(shortcut.label) is unavailable. Choose another shortcut or use the menu bar."
            stop()
        }
    }

    /// AppRuntime retains this object for the app lifetime and calls stop on
    /// shutdown. Always remove the C callback before its context can disappear.
    func stop() {
        if let hotKey { UnregisterEventHotKey(hotKey) }
        if let handler { RemoveEventHandler(handler) }
        hotKey = nil
        handler = nil
        action = nil
    }
}
