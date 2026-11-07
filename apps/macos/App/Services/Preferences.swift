import Combine
import Foundation

enum IdleLockInterval: Int, CaseIterable, Identifiable {
    case oneMinute = 60
    case fiveMinutes = 300
    case fifteenMinutes = 900
    var id: Int { rawValue }
    var label: String { "\(rawValue / 60) minute\(rawValue == 60 ? "" : "s")" }
}

enum ClipboardInterval: Int, CaseIterable, Identifiable {
    case fifteenSeconds = 15
    case thirtySeconds = 30
    case sixtySeconds = 60
    var id: Int { rawValue }
    var label: String { "\(rawValue) seconds" }
}

enum QuickAccessShortcut: String, CaseIterable, Identifiable {
    case controlShiftSpace
    case controlOptionSpace
    var id: String { rawValue }
    var label: String { self == .controlShiftSpace ? "⌃⇧Space" : "⌃⌥Space" }
}

/// Only non-sensitive UI preferences are persisted. No endpoint/account data.
@MainActor
final class Preferences: ObservableObject {
    private let defaults: UserDefaults
    @Published var idleLock: IdleLockInterval {
        didSet { defaults.set(idleLock.rawValue, forKey: "idleLockSeconds") }
    }
    @Published var clipboardInterval: ClipboardInterval {
        didSet { defaults.set(clipboardInterval.rawValue, forKey: "clipboardSeconds") }
    }
    @Published var shortcut: QuickAccessShortcut {
        didSet { defaults.set(shortcut.rawValue, forKey: "quickAccessShortcut") }
    }
    @Published var globalShortcutEnabled: Bool {
        didSet { defaults.set(globalShortcutEnabled, forKey: "globalShortcutEnabled") }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        idleLock = IdleLockInterval(rawValue: defaults.integer(forKey: "idleLockSeconds")) ?? .fiveMinutes
        clipboardInterval = ClipboardInterval(rawValue: defaults.integer(forKey: "clipboardSeconds")) ?? .thirtySeconds
        shortcut = QuickAccessShortcut(rawValue: defaults.string(forKey: "quickAccessShortcut") ?? "") ?? .controlShiftSpace
        globalShortcutEnabled = defaults.object(forKey: "globalShortcutEnabled") as? Bool ?? true
    }
}
