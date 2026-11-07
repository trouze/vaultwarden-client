import AppKit
import Foundation
import Security

private struct InteractionCheckFailed: Error { let message: String }

@MainActor
private final class TestClock {
    var value: TimeInterval = 100
}

@MainActor
private final class MemoryClipboard: ClipboardWriting {
    private(set) var changeCount = 0
    private(set) var value: String?
    var rejectWrites = false

    func writeConcealed(_ value: String) -> Bool {
        guard !rejectWrites else { return false }
        changeCount += 1
        self.value = value
        return true
    }
    func clear() { changeCount += 1; value = nil }
    func externalCopy(_ value: String) { changeCount += 1; self.value = value }
}

@MainActor
private final class FakePersistence: VaultPersistence {
    var hasStoredCache = true
    var biometricsEnrolled = false
    var biometricsAvailable = false
    var restoreInteractions: [Bool] = []
    var saveCalls = 0
    var enrollmentCalls = 0
    var forgetCalls = 0
    func restore(client: VaultClient, generation: UInt64, allowInteraction: Bool) async throws -> Session {
        restoreInteractions.append(allowInteraction)
        throw PersistenceError.cacheKeyMissing
    }
    func save(client: VaultClient, generation: UInt64) async throws { saveCalls += 1 }
    func enrollBiometrics(client: VaultClient, generation: UInt64) async throws { enrollmentCalls += 1 }
    func unlockBiometrics(client: VaultClient, generation: UInt64) async throws -> Session { throw PersistenceError.biometricUnavailable }
    func disableBiometrics() async throws {}
    func forget(client: VaultClient, generation: UInt64) async throws { forgetCalls += 1; hasStoredCache = false }
    func cancelAuthentication() {}
}

/// Deterministic clocks and isolated pasteboards; no sleeps, real clipboard,
/// endpoint settings, Accessibility permissions, or persistent user preferences.
@MainActor
enum InteractionChecks {
    static func persistenceChecks() async throws {
        for allowed in [errSecSuccess, errSecItemNotFound, errSecInteractionNotAllowed] {
            try KeychainVaultKeys.validateBiometricPreflight(allowed)
        }
        for denied in [errSecMissingEntitlement, errSecNotAvailable, errSecParam] {
            do {
                try KeychainVaultKeys.validateBiometricPreflight(denied)
                throw InteractionCheckFailed(message: "Denied Keychain access must stop before the biometric prompt")
            } catch let error as PersistenceError {
                let message = error.localizedDescription
                try check(message.contains("OSStatus \(denied)") && message.contains("capability check"), "Diagnostic must preserve the operation and safe numeric status")
                try check(!message.contains("example.com"), "Diagnostics must not disclose account or endpoint data")
            }
        }
        let deletion = PersistenceError.keychainFailure(operation: .deleteBiometricKey, status: errSecParam).localizedDescription
        try check(deletion.contains("previous Touch ID") && deletion.contains("-50"), "Post-touch failure identifies deletion separately from add/read")
        let storage = FakePersistence()
        let core = CoreAdapter(persistence: storage)
        try check(!core.rememberVault, "Persistence must be opt-in")
        await core.inspectSavedCache()
        try check(storage.restoreInteractions == [false] && core.hasStoredCache && core.cacheWarning != nil,
            "Startup must not authorize Keychain interaction or silently discard a missing cache key")
        core.unlockDemo()
        try check(!core.isUnlocked, "Demo must not overwrite an existing saved vault")
        await core.enableBiometrics()
        try check(storage.enrollmentCalls == 0, "Locked state must not export a biometric user key")
        await core.logout()
        try check(storage.forgetCalls == 1 && !core.hasStoredCache && !core.hasCachedVault,
            "Explicit forget performs cleanup without touching real Keychain in tests")
        core.unlockDemo()
        await core.saveLocalCache()
        await core.enableBiometrics()
        try check(storage.saveCalls == 0 && storage.enrollmentCalls == 0, "Demo keys/data must never be persisted or enrolled")
        core.lock()
    }
    static func run() throws {
        try clipboardOwnership()
        try namedPasteboardMarkers()
        try inactivityAndCategories()
        try typedCategoryCounts()
        try middleColumnSortingAndSelection()
        try settingsAndQuickAccess()
        print("Clipboard, idle-lock, preferences, and quick-access interaction checks passed")
    }

    private static func clipboardOwnership() throws {
        let time = TestClock()
        let writer = MemoryClipboard()
        let clipboard = SafeClipboard(writer: writer, clock: { time.value })
        try check(clipboard.copy("fictional-first", lifetime: 30), "Copy should succeed")
        time.value = 129
        clipboard.expireIfDue()
        try check(writer.value == "fictional-first", "Do not expire before deadline")
        time.value = 130
        clipboard.expireIfDue()
        try check(writer.value == nil, "Expire at deadline")

        clipboard.copy("fictional-second", lifetime: 15)
        writer.externalCopy("user-owned-copy")
        time.value = 145
        clipboard.expireIfDue()
        clipboard.clearOwned()
        try check(writer.value == "user-owned-copy", "Expiration and lock must preserve a changed clipboard")

        clipboard.copy("same-fictional-value", lifetime: 15)
        writer.externalCopy("same-fictional-value")
        clipboard.clearOwned()
        try check(writer.value == "same-fictional-value", "Compare ownership, not clipboard text")

        clipboard.copy("old", lifetime: 15)
        time.value = 150
        clipboard.copy("new", lifetime: 30)
        time.value = 160
        clipboard.expireIfDue()
        try check(writer.value == "new", "Older deadline must not clear a new copy")
        time.value = 180
        clipboard.expireIfDue()
        try check(writer.value == nil, "New copy has its own deadline")

        for invalid in [0, -1, 61, .infinity, .nan] as [TimeInterval] {
            try check(!clipboard.copy("fictional", lifetime: invalid), "Reject unsafe clipboard timeout")
        }
        writer.rejectWrites = true
        try check(!clipboard.copy("fictional", lifetime: 30), "Report clipboard write failure")
        writer.externalCopy("after-failed-write")
        clipboard.clearOwned()
        try check(writer.value == "after-failed-write", "Failed write must not claim clipboard ownership")
    }

    private static func namedPasteboardMarkers() throws {
        let pasteboard = NSPasteboard.withUniqueName()
        defer { pasteboard.releaseGlobally() }
        let writer = SystemClipboard(pasteboard: pasteboard)
        let clipboard = SafeClipboard(writer: writer)
        try check(clipboard.copy("isolated-fictional-password", lifetime: 30), "Native pasteboard write")
        let types = Set(pasteboard.types ?? [])
        try check(types.contains(.string) && types.contains(SystemClipboard.concealed)
            && types.contains(SystemClipboard.transient) && types.contains(SystemClipboard.excludeUniversal), "Clipboard exclusion markers must be present")
        clipboard.clearOwned()
        try check(pasteboard.string(forType: .string) == nil, "Clear the isolated owned pasteboard")
    }

    private static func inactivityAndCategories() throws {
        let time = TestClock()
        let core = CoreAdapter(clock: { time.value })
        core.unlockDemo()
        core.selectedID = "demo-docs"
        core.category = .cards
        try check(core.visibleItems.isEmpty && core.selectedID == nil, "Type filter must clear an excluded selection")
        try check(core.categoryCounts[.all] == 3 && core.categoryCounts[.passwords] == 3
            && core.categoryCounts[.passkeys] == 0 && core.categoryCounts[.cards] == 0, "Demo categories must report actual metadata")
        core.query = "example.net"
        core.category = .passwords
        try check(core.visibleItems.count == 1, "Type category and Rust search combine")
        try check(core.categoryCounts[.all] == 3 && core.categoryCounts[.passwords] == 3, "Tile totals are independent of the search query")
        time.value = 399
        try check(!core.lockIfInactive(timeout: 300), "Remain unlocked before timeout")
        time.value = 400
        try check(core.lockIfInactive(timeout: 300), "Lock at timeout")
        try check(core.query.isEmpty && core.category == .all && core.items.isEmpty && core.categoryCounts.isEmpty, "Idle lock clears visible state and counts")
        core.unlockDemo()
        time.value = 650
        core.recordActivity()
        time.value = 949
        try check(!core.lockIfInactive(timeout: 300), "Activity extends unlock")
        time.value = 950
        try check(core.lockIfInactive(timeout: 300), "Lock after extended deadline")
        core.unlockDemo()
        time.value = 1250
        try check(core.lockIfInactive(timeout: .infinity), "Invalid timeout defaults to five minutes")
    }

    private static func typedCategoryCounts() throws {
        func item(_ kind: ItemKind, passkey: Bool = false, totp: Bool = false) -> ItemSummary {
            ItemSummary(id: "synthetic", title: "Fictional", username: "", website: "",
                favorite: false, kind: kind, hasPasskey: passkey, hasTotp: totp)
        }
        let counts = VaultCategory.counts(in: [
            item(.login, passkey: true, totp: true), item(.secureNote), item(.card),
            item(.identity), item(.sshKey),
        ])
        try check(counts[.all] == 5, "All category counts every item once")
        for category in VaultCategory.allCases where category != .all {
            try check(counts[category] == 1, "Each type/capability must have the correct count")
        }
        let malformed = item(.secureNote, passkey: true, totp: true)
        try check(!VaultCategory.passkeys.matches(malformed) && !VaultCategory.codes.matches(malformed), "Login capabilities must not misclassify other kinds")
    }

    private static func middleColumnSortingAndSelection() throws {
        let core = CoreAdapter()
        core.unlockDemo()
        try check(core.visibleItems.map(\.id) == ["demo-lab", "demo-docs", "demo-example"], "Default middle-column sort is name ascending")
        core.selectedID = "demo-docs"
        core.toggleReveal()
        core.sortOrder = .titleDescending
        try check(core.visibleItems.map(\.id) == ["demo-example", "demo-docs", "demo-lab"], "Name descending reorders the middle column")
        try check(core.selectedItem?.id == "demo-docs" && core.revealedPassword != nil, "Sort preserves the selected right-column item")
        core.sortOrder = .username
        try check(core.visibleItems.map(\.id) == ["demo-example", "demo-lab", "demo-docs"], "Sort by username")
        core.sortOrder = .website
        try check(core.visibleItems.map(\.id) == ["demo-example", "demo-lab", "demo-docs"], "Sort by website")
        core.query = "example.org"
        try check(core.visibleItems.count == 1 && core.selectedItem?.id == "demo-docs", "Search and sort preserve a still-visible selection")
        core.category = .cards
        try check(core.visibleItems.isEmpty && core.selectedItem == nil && core.revealedPassword == nil, "Changing to an excluding tile clears the right-column detail")

        func item(_ id: String) -> ItemSummary {
            ItemSummary(id: id, title: "Same title", username: "", website: "",
                favorite: false, kind: .login, hasPasskey: false, hasTotp: false)
        }
        for order in ItemSortOrder.allCases {
            try check(order.sorted([item("b"), item("a")]).map(\.id) == ["a", "b"], "Equal sort values use deterministic ID ordering")
        }
    }

    private static func settingsAndQuickAccess() throws {
        let name = "org.vaultwardenclient.tests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: name) else {
            throw InteractionCheckFailed(message: "Cannot create isolated preferences")
        }
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(-1, forKey: "idleLockSeconds")
        defaults.set(999, forKey: "clipboardSeconds")
        defaults.set("invalid", forKey: "quickAccessShortcut")
        let preferences = Preferences(defaults: defaults)
        try check(preferences.idleLock == .fiveMinutes && preferences.clipboardInterval == .thirtySeconds
            && preferences.shortcut == .controlShiftSpace, "Invalid saved preferences use secure defaults")
        preferences.idleLock = .oneMinute
        preferences.clipboardInterval = .fifteenSeconds
        preferences.shortcut = .controlOptionSpace
        preferences.globalShortcutEnabled = false
        let reloaded = Preferences(defaults: defaults)
        try check(reloaded.idleLock == .oneMinute && reloaded.clipboardInterval == .fifteenSeconds
            && reloaded.shortcut == .controlOptionSpace && !reloaded.globalShortcutEnabled, "Preferences survive relaunch")

        let time = TestClock()
        let core = CoreAdapter(clock: { time.value })
        let writer = MemoryClipboard()
        let clipboard = SafeClipboard(writer: writer, clock: { time.value })
        let copier = CopyCoordinator(core: core, clipboard: clipboard, preferences: preferences, clock: { time.value })
        let quick = QuickAccessModel(core: core, copier: copier)
        quick.open()
        try check(!quick.isUnlocked && quick.items.isEmpty, "Quick access must not unlock implicitly")
        try check(!quick.copySelection(.password) && writer.value == nil, "Locked quick access cannot copy")
        quick.unlockDemo()
        try check(quick.isUnlocked && quick.items.count == 3 && quick.selectedID != nil, "Explicit demo unlock populates picker")
        core.selectedID = "demo-docs"
        try check(core.selectedItem?.id == "demo-docs" && writer.value == nil && core.revealedPassword == nil,
            "Middle-column selection shows details without copying or revealing")
        let first = quick.selectedID
        quick.moveSelection(-1)
        try check(quick.selectedID == first, "Arrow selection clamps at first item")
        quick.moveSelection(100)
        try check(quick.selectedID == quick.items.last?.id, "Arrow selection clamps at last item")
        core.query = "example.net"
        quick.query = "reader@"
        try check(quick.items.count == 1 && quick.selectedID == "demo-docs" && core.query == "example.net", "Quick search does not mutate main-window search")
        try check(quick.copySelection(.username) && writer.value == "reader@example.org", "Copy selected username through Rust")
        try check(!(copier.feedback ?? "").contains("reader@"), "Feedback must not contain copied values")
        quick.query = "missing"
        try check(quick.items.isEmpty && quick.selectedID == nil && !quick.copySelection(.password), "No stale selection after unmatched search")
        quick.query = ""
        quick.category = .cards
        try check(quick.items.isEmpty && quick.selectedID == nil
            && !quick.copyItem(id: "demo-example", field: .password), "Filtered-out rows cannot be clicked to copy")
        quick.category = .passwords
        try check(quick.items.count == 3 && quick.categoryCounts[.passwords] == 3, "Quick-access category filtering")
        try check(quick.copyItem(id: "demo-example", field: .password)
            && quick.selectedID == "demo-example" && writer.value?.hasPrefix("DEMO-ONLY") == true, "Clicking a visible item copies without revealing UI")
        try check(core.revealedPassword == nil, "Copy should not reveal password in main window")
        core.lock()
        try check(writer.value == nil && copier.feedback == nil, "Lock clears owned clipboard immediately")
        try check(!quick.isUnlocked && quick.items.isEmpty && quick.query.isEmpty && quick.selectedID == nil
            && quick.category == .all && quick.categoryCounts.isEmpty
            && !quick.copyItem(id: "demo-example", field: .password), "Lock revokes open picker state and click actions")
        core.unlockDemo()
        quick.category = .all
        quick.query = "example.com"
        quick.copySelection(.password)
        writer.externalCopy("user-keeps-this")
        core.lock()
        try check(writer.value == "user-keeps-this", "Lock preserves later user copy")
        quick.close()
        try check(!quick.isPresented && quick.items.isEmpty && quick.selectedID == nil && quick.query.isEmpty
            && !quick.copyItem(id: "demo-example", field: .password), "Dismissal clears picker query, results, and click actions")
    }

    private static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw InteractionCheckFailed(message: message) }
    }
}
