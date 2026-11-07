import AppKit
import SwiftUI

struct QuickAccessView: View {
    @ObservedObject var model: QuickAccessModel
    @ObservedObject var copier: CopyCoordinator
    let dismiss: () -> Void
    let openVault: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Vaultwarden", systemImage: "lock.shield").font(.title2.weight(.semibold))
                Spacer()
                Text(model.isDemo ? "DEMO" : "READ-ONLY").font(.caption).foregroundStyle(.secondary)
                Button("Close", systemImage: "xmark", action: dismiss).labelStyle(.iconOnly)
            }
            if model.isUnlocked {
                QuickSearchField(model: model, copy: copy, dismiss: dismiss)
                    .frame(height: 28)
                CategoryTilesView(selection: $model.category, counts: model.categoryCounts, columns: 4)
                if model.items.isEmpty {
                    ContentUnavailableView("No matches", systemImage: "magnifyingglass", description: Text(model.errorMessage ?? "Try another title, username, or website."))
                } else {
                    List(selection: $model.selectedID) {
                        ForEach(model.items, id: \.id) { item in
                            Button {
                                let field: CopyField = NSApp.currentEvent?.modifierFlags.contains(.option) == true ? .username : .password
                                if model.copyItem(id: item.id, field: field) { dismiss() }
                            } label: {
                                HStack {
                                    Image(systemName: VaultCategory.primaryCategory(for: item).symbol).foregroundStyle(.secondary)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(item.title)
                                        Text(item.username).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Text(item.website).font(.caption).foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.vertical, 5)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .tag(item.id)
                            .help("Click to copy the primary field; Option-click copies a login username")
                            .accessibilityHint("Activate to copy the primary field")
                        }
                    }
                    .listStyle(.plain)
                }
                Text("Click or Return copies the primary field · ⌥click or ⌥Return copies a login username · ↑↓ select · Escape closes")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Spacer()
                Text("Vault is locked").font(.title3)
                Text("Sign in or unlock securely in the main window. Quick access never unlocks a real vault implicitly.")
                    .foregroundStyle(.secondary)
                Button("Open Vaultwarden") { dismiss(); openVault() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                Spacer()
            }
            if let feedback = copier.feedback {
                Text(feedback).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(20)
        .frame(width: 580, height: 520)
        .onExitCommand(perform: dismiss)
        .onKeyPress(.downArrow) { model.moveSelection(1); return .handled }
        .onKeyPress(.upArrow) { model.moveSelection(-1); return .handled }
        .onKeyPress(keys: [.return]) { press in
            guard model.isUnlocked else { return .ignored }
            copy(press.modifiers.contains(.option) ? .username : .password)
            return .handled
        }
    }

    private func copy(_ field: CopyField) {
        if model.copySelection(field) { dismiss() }
    }
}
