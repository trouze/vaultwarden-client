import Combine
import Foundation

/// Network and KDF operations run on worker tasks; list/field calls are in-memory.
@MainActor
final class CoreAdapter: ObservableObject {
    private let client = VaultClient()
    private let clock: () -> TimeInterval
    private var lastActivity: TimeInterval
    private var requestID = UUID()
    private let persistence: (any VaultPersistence)?
    private var didInspectCache = false
    private var isForgetting = false

    init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }, persistence: (any VaultPersistence)? = nil) {
        self.clock = clock
        self.lastActivity = clock()
        self.persistence = persistence
    }

    @Published private(set) var session = Session(state: .locked, generation: 0)
    @Published private(set) var items: [ItemSummary] = []
    @Published private(set) var categoryCounts: [VaultCategory: Int] = [:]
    @Published private(set) var revealedPassword: String?
    @Published private(set) var errorMessage: String?
    @Published private(set) var isBusy = false
    @Published private(set) var hasCachedVault = false
    @Published private(set) var canSync = false
    @Published private(set) var omittedItems: UInt32 = 0
    @Published private(set) var twoFactorProviders: [UInt32] = []
    @Published private(set) var fieldDescriptors: [FieldInfo] = []
    @Published private(set) var displayedFields: [String: String] = [:]
    @Published private(set) var hasStoredCache = false
    @Published private(set) var cacheSaved = false
    @Published private(set) var recoveredCache = false
    @Published private(set) var cacheWarning: String?
    @Published private(set) var biometricsEnrolled = false
    @Published private(set) var biometricsAvailable = false
    @Published var rememberVault = false
    @Published var selectedID: String? {
        didSet {
            revealedPassword = nil
            loadSelectedFields()
            recordActivity()
        }
    }
    @Published var query = "" {
        didSet {
            recordActivity()
            refresh()
        }
    }
    @Published var category: VaultCategory = .all {
        didSet {
            recordActivity()
            if !visibleItems.contains(where: { $0.id == selectedID }) {
                selectedID = nil
            }
        }
    }
    @Published var sortOrder: ItemSortOrder = .titleAscending {
        didSet { recordActivity() }
    }

    var isUnlocked: Bool { session.state != .locked }
    var persistenceAvailable: Bool { persistence != nil }
    var isDemo: Bool { session.state == .demoUnlocked }
    var visibleItems: [ItemSummary] { sortOrder.sorted(items.filter { category.matches($0) }) }
    var selectedItem: ItemSummary? { visibleItems.first { $0.id == selectedID } }

    func unlockDemo() {
        guard !isForgetting else { return }
        guard !hasCachedVault && !hasStoredCache else {
            errorMessage = "Sign out and discard the saved account before entering demo mode."
            return
        }
        lock()
        do {
            session = try client.unlockDemo()
            updateAccountStatus()
            recordActivity()
            errorMessage = nil
            revealedPassword = nil
            refresh()
        } catch {
            failClosed(error)
        }
    }

    func lock() {
        persistence?.cancelAuthentication()
        requestID = UUID()
        isBusy = isForgetting
        twoFactorProviders = []
        // Clear Swift-visible copies even if the core has failed.
        items = []
        categoryCounts = [:]
        selectedID = nil
        revealedPassword = nil
        fieldDescriptors = []
        displayedFields = [:]
        session = Session(state: .locked, generation: session.generation)
        query = ""
        category = .all
        do {
            session = try client.lock()
            updateAccountStatus()
            errorMessage = nil
        } catch {
            errorMessage = "The core is unavailable. Quit and restart Vaultwarden."
        }
    }

    func refresh() {
        guard isUnlocked else { return }
        do {
            let allItems = try client.search(query: "")
            items = query.isEmpty ? allItems : try client.search(query: query)
            categoryCounts = VaultCategory.counts(in: allItems)
            if !visibleItems.contains(where: { $0.id == selectedID }) {
                selectedID = nil
            }
            errorMessage = nil
            loadSelectedFields()
        } catch {
            items = []
            selectedID = nil
            errorMessage = "Search could not be completed. Use a shorter query."
        }
    }

    func toggleReveal() {
        toggleField("password")
    }

    func toggleField(_ fieldID: String) {
        recordActivity()
        if displayedFields[fieldID] != nil {
            displayedFields[fieldID] = nil
            if fieldID == "password" { revealedPassword = nil }
            return
        }
        guard let selectedID, isUnlocked else { return }
        do {
            let value = try client.readField(id: selectedID, fieldId: fieldID, expectedGeneration: session.generation)
            displayedFields[fieldID] = value
            if fieldID == "password" { revealedPassword = value }
        } catch {
            failClosed(error)
        }
    }

    func matchingCredentials(services: [String], recordID: String?) throws -> [ItemSummary] {
        guard isUnlocked else { throw CoreError.Locked }
        var matches: [ItemSummary]
        if services.isEmpty {
            matches = try client.search(query: "")
        } else {
            var unique: [String: ItemSummary] = [:]
            for service in services {
                for item in (try? client.matchService(service: service)) ?? [] {
                    unique[item.id] = item
                }
            }
            matches = unique.values.sorted { $0.title < $1.title }
        }
        if let recordID { matches = matches.filter { $0.id == recordID } }
        return matches
    }

    func passwordForSelection(id: String) throws -> String {
        try client.revealPassword(id: id, expectedGeneration: session.generation)
    }

    func readField(id: String, fieldID: String) throws -> String {
        try client.readField(id: id, fieldId: fieldID, expectedGeneration: session.generation)
    }

    private func loadSelectedFields() {
        fieldDescriptors = []
        displayedFields = [:]
        revealedPassword = nil
        guard isUnlocked, let item = selectedItem else { return }
        do {
            fieldDescriptors = try client.fields(id: item.id)
            for field in fieldDescriptors where !field.isSecret {
                displayedFields[field.id] = try readField(id: item.id, fieldID: field.id)
            }
        } catch {
            fieldDescriptors = []
            displayedFields = [:]
            errorMessage = "Could not read the selected item."
        }
    }

    private func updateAccountStatus() {
        guard let status = try? client.accountStatus() else { return }
        hasCachedVault = status.hasCachedVault
        canSync = status.canSync
        omittedItems = status.omittedItems
        cacheSaved = status.cacheSaved
        recoveredCache = status.recoveredCache
        hasStoredCache = persistence?.hasStoredCache ?? false
        biometricsAvailable = persistence?.biometricsAvailable ?? false
        biometricsEnrolled = persistence?.biometricsEnrolled ?? false
    }

    func login(server: String, email: String, password: String, code: String?, expectedGeneration: UInt64? = nil) async {
        guard !isForgetting else { return }
        if let expectedGeneration, expectedGeneration != session.generation { return }
        lock()
        let request = requestID
        let generation = session.generation
        let client = client
        isBusy = true
        errorMessage = nil
        do {
            let newSession = try await Task.detached(priority: .userInitiated) {
                try client.login(server: server, email: email, password: password,
                    twoFactorCode: code, expectedGeneration: generation)
            }.value
            guard request == requestID else { return }
            applyLoadedSession(newSession)
            if rememberVault { await saveLocalCache() }
        } catch {
            guard request == requestID else { return }
            isBusy = false
            updateAccountStatus()
            if let coreError = error as? CoreError, case let .TwoFactorRequired(providers) = coreError {
                twoFactorProviders = providers
            }
            errorMessage = safeMessage(error)
        }
    }

    func unlockCached(password: String, expectedGeneration: UInt64? = nil) async {
        guard !isForgetting else { return }
        if let expectedGeneration, expectedGeneration != session.generation { return }
        lock()
        let request = requestID
        let generation = session.generation
        let client = client
        isBusy = true
        do {
            let newSession = try await Task.detached(priority: .userInitiated) {
                try client.unlockCached(password: password, expectedGeneration: generation)
            }.value
            guard request == requestID else { return }
            applyLoadedSession(newSession)
        } catch {
            guard request == requestID else { return }
            isBusy = false
            errorMessage = safeMessage(error)
        }
    }

    func sync() async {
        guard canSync, isUnlocked, !isBusy else { return }
        let request = UUID()
        requestID = request
        let generation = session.generation
        let client = client
        isBusy = true
        do {
            let newSession = try await Task.detached(priority: .userInitiated) {
                try client.sync(expectedGeneration: generation)
            }.value
            guard request == requestID else { return }
            applyLoadedSession(newSession)
            if rememberVault { await saveLocalCache() }
        } catch {
            guard request == requestID else { return }
            isBusy = false
            if let coreError = error as? CoreError, case .SessionExpired = coreError { lock() }
            errorMessage = safeMessage(error)
        }
    }

    func logout() async {
        guard !isForgetting else { return }
        isForgetting = true
        lock()
        isBusy = true
        let client = client
        var failed = false
        do {
            // Forget is a security operation that completes even if sleep/manual
            // lock occurs. New authentication is blocked until cleanup finishes.
            let newSession = try await Task.detached { try client.logout() }.value
            session = newSession
        } catch {
            if let newSession = try? client.session() { session = newSession }
            failed = true
        }
        // Key deletion is attempted even if cache deletion failed. Never silently
        // claim that saved credentials/data were removed when the OS denied it.
        do { try await persistence?.forget(client: client, generation: session.generation) } catch { failed = true }
        rememberVault = false
        isForgetting = false
        isBusy = false
        updateAccountStatus()
        cacheWarning = failed ? "Some saved cache or Keychain data could not be removed. Do not assume this account was fully forgotten." : nil
        errorMessage = cacheWarning
    }

    func inspectSavedCache() async {
        guard !didInspectCache, let persistence else { return }
        didInspectCache = true
        hasStoredCache = persistence.hasStoredCache
        biometricsAvailable = persistence.biometricsAvailable
        biometricsEnrolled = persistence.biometricsEnrolled
        if hasStoredCache { await restoreSavedCache(allowInteraction: false) }
    }

    func restoreSavedCache(allowInteraction: Bool = true) async {
        guard let persistence, !isUnlocked, !hasCachedVault, !isBusy else { return }
        let request = requestID
        let generation = session.generation
        isBusy = true
        do {
            let restored = try await persistence.restore(client: client, generation: generation, allowInteraction: allowInteraction)
            guard request == requestID else { return }
            session = restored
            updateAccountStatus()
            rememberVault = true
            isBusy = false
            cacheWarning = recoveredCache ? "Recovered the previous authenticated cache. It may be older; sign in and sync to refresh it." : nil
            errorMessage = nil
        } catch {
            guard request == requestID else { return }
            isBusy = false
            cacheWarning = safeMessage(error)
        }
    }

    func saveLocalCache() async {
        guard let persistence, isUnlocked, !isDemo, !isBusy else { return }
        let request = requestID
        let generation = session.generation
        isBusy = true
        do {
            try await persistence.save(client: client, generation: generation)
            guard request == requestID else { return }
            isBusy = false
            updateAccountStatus()
            rememberVault = true
            cacheWarning = nil
        } catch {
            guard request == requestID else { return }
            isBusy = false
            cacheWarning = "The vault is open, but it was not safely saved: \(safeMessage(error))"
        }
    }

    func enableBiometrics() async {
        guard let persistence, isUnlocked, !isDemo, !isBusy else { return }
        if !cacheSaved { await saveLocalCache() }
        guard cacheSaved, isUnlocked else { return }
        let request = requestID
        let generation = session.generation
        isBusy = true
        do {
            try await persistence.enrollBiometrics(client: client, generation: generation)
            guard request == requestID else { return }
            biometricsEnrolled = persistence.biometricsEnrolled
            isBusy = false
            cacheWarning = nil
        } catch {
            guard request == requestID else { return }
            isBusy = false
            cacheWarning = safeMessage(error)
        }
    }

    func unlockWithBiometrics() async {
        guard let persistence, hasCachedVault, !isUnlocked, !isBusy else { return }
        let request = requestID
        let generation = session.generation
        isBusy = true
        do {
            let newSession = try await persistence.unlockBiometrics(client: client, generation: generation)
            guard request == requestID else { return }
            applyLoadedSession(newSession)
            cacheWarning = nil
        } catch {
            guard request == requestID else { return }
            isBusy = false
            errorMessage = safeMessage(error)
        }
    }

    func disableBiometrics() async {
        guard let persistence, !isBusy else { return }
        do {
            try await persistence.disableBiometrics()
            biometricsEnrolled = false
        } catch { cacheWarning = safeMessage(error) }
    }

    private func applyLoadedSession(_ session: Session) {
        updateAccountStatus()
        self.session = session
        isBusy = false
        twoFactorProviders = []
        errorMessage = nil
        recordActivity()
        refresh()
    }

    private func safeMessage(_ error: Error) -> String {
        // Never display transport errors, which may include private URLs/bodies.
        if let error = error as? CoreError { return error.localizedDescription }
        if let error = error as? PersistenceError { return error.localizedDescription }
        return "The vault operation failed. Lock and retry sign-in."
    }

    func item(id: String) throws -> ItemSummary {
        try client.item(id: id)
    }

    func searchSummaries(query: String) throws -> [ItemSummary] {
        try client.search(query: query)
    }

    func recordActivity() {
        if isUnlocked { lastActivity = clock() }
    }

    /// App interaction inactivity, not system-wide input monitoring. Invalid
    /// settings fall back to five minutes rather than silently disabling lock.
    @discardableResult
    func lockIfInactive(timeout: TimeInterval) -> Bool {
        guard isUnlocked else { return false }
        let timeout = timeout.isFinite && timeout >= 60 && timeout <= 900 ? timeout : 300
        if clock() - lastActivity >= timeout {
            lock()
            return true
        }
        return false
    }

    private func failClosed(_ error: Error) {
        lock()
        errorMessage = "The request failed. Unlock the vault and try again."
    }
}
