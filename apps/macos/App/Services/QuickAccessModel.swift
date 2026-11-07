import Combine
import Foundation

@MainActor
final class QuickAccessModel: ObservableObject {
    private let core: CoreAdapter
    private let copier: CopyCoordinator
    private var sessionSubscription: AnyCancellable?
    @Published private(set) var isPresented = false
    @Published private(set) var isUnlocked = false
    var isDemo: Bool { core.isDemo }
    var hasCachedVault: Bool { core.hasCachedVault }
    @Published private(set) var presentation = 0
    @Published private(set) var items: [ItemSummary] = []
    @Published private(set) var categoryCounts: [VaultCategory: Int] = [:]
    @Published private(set) var errorMessage: String?
    @Published var selectedID: String? {
        didSet { core.recordActivity() }
    }
    @Published var query = "" {
        didSet {
            core.recordActivity()
            refresh()
        }
    }
    @Published var category: VaultCategory = .all {
        didSet {
            core.recordActivity()
            refresh()
        }
    }

    init(core: CoreAdapter, copier: CopyCoordinator) {
        self.core = core
        self.copier = copier
        sessionSubscription = core.$session.sink { [weak self] session in
            guard let self else { return }
            self.isUnlocked = session.state != .locked
            if !self.isUnlocked {
                self.query = ""
                self.selectedID = nil
                self.category = .all
            }
            self.refresh()
        }
    }

    func open() {
        isPresented = true
        presentation += 1
        query = ""
        refresh()
        core.recordActivity()
    }

    func close() {
        isPresented = false
        query = ""
        items = []
        categoryCounts = [:]
        selectedID = nil
        errorMessage = nil
    }

    func unlockDemo() { core.unlockDemo() }

    func moveSelection(_ delta: Int) {
        guard !items.isEmpty else { return }
        let current = items.firstIndex { $0.id == selectedID } ?? 0
        let index = max(0, min(items.count - 1, current + delta))
        selectedID = items[index].id
    }

    @discardableResult
    func copySelection(_ field: CopyField) -> Bool {
        guard let selectedID else { return false }
        return copyItem(id: selectedID, field: field)
    }

    @discardableResult
    func copyItem(id: String, field: CopyField) -> Bool {
        guard isPresented, isUnlocked, items.contains(where: { $0.id == id }) else { return false }
        selectedID = id
        if field == .password, let item = items.first(where: { $0.id == id }), item.kind != .login {
            let fieldID: String
            let label: String
            switch item.kind {
            case .secureNote: fieldID = "notes"; label = "Notes"
            case .card: fieldID = "number"; label = "Card number"
            case .identity: fieldID = "email"; label = "Email"
            case .sshKey: fieldID = "publicKey"; label = "Public key"
            case .login: fieldID = "password"; label = "Password"
            }
            return copier.copyField(id: id, fieldID: fieldID, label: label)
        }
        return copier.copy(field, id: id)
    }

    private func refresh() {
        guard isPresented, isUnlocked else {
            items = []
            categoryCounts = [:]
            selectedID = nil
            return
        }
        do {
            let allItems = try core.searchSummaries(query: "")
            let results = query.isEmpty ? allItems : try core.searchSummaries(query: query)
            items = results.filter { category.matches($0) }
            categoryCounts = VaultCategory.counts(in: allItems)
            if !items.contains(where: { $0.id == selectedID }) { selectedID = items.first?.id }
            errorMessage = nil
        } catch {
            items = []
            selectedID = nil
            errorMessage = "Search could not be completed. Use a shorter query."
        }
    }
}
