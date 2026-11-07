import Foundation

enum ItemSortOrder: String, CaseIterable, Identifiable {
    case titleAscending, titleDescending, username, website
    var id: String { rawValue }

    var title: String {
        switch self {
        case .titleAscending: "Name (A–Z)"
        case .titleDescending: "Name (Z–A)"
        case .username: "Username"
        case .website: "Website"
        }
    }

    func sorted(_ items: [ItemSummary]) -> [ItemSummary] {
        items.sorted { lhs, rhs in
            let comparison = value(for: lhs).localizedStandardCompare(value(for: rhs))
            if comparison == .orderedSame { return lhs.id < rhs.id }
            return self == .titleDescending ? comparison == .orderedDescending : comparison == .orderedAscending
        }
    }

    private func value(for item: ItemSummary) -> String {
        switch self {
        case .titleAscending, .titleDescending: item.title
        case .username: item.username
        case .website: item.website
        }
    }
}
