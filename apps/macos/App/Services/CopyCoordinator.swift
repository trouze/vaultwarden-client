import Combine
import Foundation

enum CopyField: String {
    case password, username, website
}

@MainActor
final class CopyCoordinator: ObservableObject {
    private let core: CoreAdapter
    private let clipboard: SafeClipboard
    private let preferences: Preferences
    private let clock: () -> TimeInterval
    private var feedbackExpiration: TimeInterval?
    private var sessionSubscription: AnyCancellable?
    @Published private(set) var feedback: String?

    init(core: CoreAdapter, clipboard: SafeClipboard, preferences: Preferences,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.core = core
        self.clipboard = clipboard
        self.preferences = preferences
        self.clock = clock
        sessionSubscription = core.$session.sink { [weak self] session in
            guard session.state == .locked else { return }
            self?.clipboard.clearOwned()
            self?.clearFeedback()
        }
    }

    @discardableResult
    func copy(_ field: CopyField, id: String?) -> Bool {
        guard core.isUnlocked, let id else {
            showFeedback("Unlock the vault and select an item first.")
            return false
        }
        do {
            // Re-read through the locked core; never trust a stale view's value.
            let item = try core.item(id: id)
            let value: String
            switch field {
            case .password: value = try core.passwordForSelection(id: id)
            case .username: value = item.username
            case .website: value = item.website
            }
            let seconds = preferences.clipboardInterval.rawValue
            guard clipboard.copy(value, lifetime: TimeInterval(seconds)) else {
                showFeedback("Could not copy \(field.rawValue).")
                return false
            }
            core.recordActivity()
            showFeedback("Copied \(field.rawValue) · clears in \(seconds)s or on lock")
            return true
        } catch {
            showFeedback("Copy failed. Unlock the vault and try again.")
            return false
        }
    }

    @discardableResult
    func copyField(id: String, fieldID: String, label: String) -> Bool {
        guard core.isUnlocked else { return false }
        do {
            let value = try core.readField(id: id, fieldID: fieldID)
            let seconds = preferences.clipboardInterval.rawValue
            guard clipboard.copy(value, lifetime: TimeInterval(seconds)) else { return false }
            core.recordActivity()
            showFeedback("Copied \(label.lowercased()) · clears in \(seconds)s or on lock")
            return true
        } catch {
            showFeedback("Could not copy the selected field.")
            return false
        }
    }

    func tick() {
        clipboard.expireIfDue()
        if let feedbackExpiration, clock() >= feedbackExpiration { clearFeedback() }
    }

    func clearFeedback() {
        feedback = nil
        feedbackExpiration = nil
    }

    private func showFeedback(_ message: String) {
        feedback = message
        feedbackExpiration = clock() + 5
    }
}
