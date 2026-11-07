import Combine
import SwiftUI

@MainActor
private final class CopyFieldInteraction: ObservableObject {
    @Published var hovered = false
}

/// The entire credential field is an accessible native button. No nested
/// copy/reveal controls, and no plaintext password in accessibility metadata.
struct CopyFieldBox: View {
    let title: String
    let value: String
    var isSecret = false
    let copy: () -> Void
    @StateObject private var interaction = CopyFieldInteraction()

    var body: some View {
        Button(action: copy) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(title).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text("Click to copy").font(.caption).foregroundStyle(.secondary)
                        .opacity(interaction.hovered ? 1 : 0)
                }
                Text(value)
                    .lineLimit(8)
                    .font(isSecret ? .system(.body, design: .monospaced) : .body)
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10)
                .stroke(interaction.hovered ? Color.accentColor.opacity(0.6) : Color.secondary.opacity(0.2), lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .onHover { interaction.hovered = $0 }
        .help("Copy \(title.lowercased())")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(isSecret ? "Sensitive field" : value)
        .accessibilityHint("Activate to copy \(title.lowercased()) to the clipboard")
    }
}
