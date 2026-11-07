import Foundation

/// Native-style categories driven by Rust item metadata, never inferred from
/// a title or URL. Passkeys/codes are login capabilities, not cipher kinds.
enum VaultCategory: String, CaseIterable, Identifiable {
    case all, passwords, passkeys, codes, notes, cards, identities, sshKeys
    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All"
        case .passwords: "Passwords"
        case .passkeys: "Passkeys"
        case .codes: "Codes"
        case .notes: "Notes"
        case .cards: "Cards"
        case .identities: "Identities"
        case .sshKeys: "SSH Keys"
        }
    }

    var symbol: String {
        switch self {
        case .all: "square.grid.2x2.fill"
        case .passwords: "key.fill"
        case .passkeys: "person.badge.key.fill"
        case .codes: "number.square.fill"
        case .notes: "note.text"
        case .cards: "creditcard.fill"
        case .identities: "person.text.rectangle.fill"
        case .sshKeys: "terminal.fill"
        }
    }

    func matches(_ item: ItemSummary) -> Bool {
        switch self {
        case .all: true
        case .passwords: item.kind == .login
        case .passkeys: item.kind == .login && item.hasPasskey
        case .codes: item.kind == .login && item.hasTotp
        case .notes: item.kind == .secureNote
        case .cards: item.kind == .card
        case .identities: item.kind == .identity
        case .sshKeys: item.kind == .sshKey
        }
    }

    static func counts(in items: [ItemSummary]) -> [VaultCategory: Int] {
        Dictionary(uniqueKeysWithValues: allCases.map { category in
            (category, items.filter { category.matches($0) }.count)
        })
    }

    static func primaryCategory(for item: ItemSummary) -> VaultCategory {
        switch item.kind {
        case .login: .passwords
        case .secureNote: .notes
        case .card: .cards
        case .identity: .identities
        case .sshKey: .sshKeys
        }
    }
}
