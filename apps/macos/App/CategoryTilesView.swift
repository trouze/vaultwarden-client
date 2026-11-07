import SwiftUI

struct CategoryTilesView: View {
    @Binding var selection: VaultCategory
    let counts: [VaultCategory: Int]
    var columns = 2

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: columns), spacing: 8) {
            ForEach(VaultCategory.allCases) { category in
                Button { selection = category } label: {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: category.symbol)
                                .foregroundStyle(selection == category ? Color.accentColor : .secondary)
                            Spacer(minLength: 4)
                            Text("\(counts[category, default: 0])")
                                .font(.system(.body, design: .rounded).weight(.semibold))
                        }
                        Text(category.title).font(.caption.weight(.medium)).lineLimit(1)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(selection == category ? Color.accentColor.opacity(0.12) : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10)
                        .stroke(selection == category ? Color.accentColor.opacity(0.6) : Color.secondary.opacity(0.15), lineWidth: 1))
                    .contentShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(category.title), \(counts[category, default: 0]) items")
                .accessibilityAddTraits(selection == category ? .isSelected : [])
                .help("Show \(category.title.lowercased())")
            }
        }
    }
}
