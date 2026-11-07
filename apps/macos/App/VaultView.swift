import SwiftUI

private struct VaultSearchActionKey: FocusedValueKey {
    typealias Value = () -> Void
}

extension FocusedValues {
    var vaultSearchAction: (() -> Void)? {
        get { self[VaultSearchActionKey.self] }
        set { self[VaultSearchActionKey.self] = newValue }
    }
}

struct VaultView: View {
    @ObservedObject var core: CoreAdapter
    @ObservedObject var copier: CopyCoordinator
    @FocusState private var searchFocused: Bool

    var body: some View {
        Group {
            if core.isUnlocked {
                NavigationSplitView {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Categories").font(.headline)
                            CategoryTilesView(selection: $core.category, counts: core.categoryCounts)
                            Text(core.isDemo ? "Fictional demo vault" : "Personal vault · Read-only")
                                .font(.caption).foregroundStyle(.secondary)
                            if core.hasCachedVault {
                                Button("Sign Out") { Task { await core.logout() } }
                                    .buttonStyle(.borderless)
                            }
                        }
                        .padding(14)
                    }
                    .navigationTitle("Vaultwarden")
                    .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 320)
                } content: {
                    itemList
                        .navigationSplitViewColumnWidth(min: 270, ideal: 320, max: 440)
                } detail: {
                    if let item = core.selectedItem {
                        detail(item)
                    } else {
                        ContentUnavailableView(core.visibleItems.isEmpty ? "No items in \(core.category.title)" : "Select an item",
                            systemImage: core.category.symbol,
                            description: Text(core.visibleItems.isEmpty ? "No supported personal items match this category and search." : "Click a credential field to copy it."))
                    }
                }
                .navigationSplitViewStyle(.balanced)
                .toolbar {
                    ToolbarItemGroup(placement: .primaryAction) {
                        GlassEffectContainer(spacing: 10) {
                            HStack(spacing: 10) {
                                HStack(spacing: 0) {
                                    Button("Add Item", systemImage: "plus") {}
                                        .labelStyle(.iconOnly).buttonStyle(.plain)
                                        .frame(width: 36, height: 32).disabled(true)
                                        .help("Creating items is not available in this read-only build")
                                    Divider().frame(height: 18)
                                    Menu {
                                        Picker("Sort items", selection: $core.sortOrder) {
                                            ForEach(ItemSortOrder.allCases) { Text($0.title).tag($0) }
                                        }
                                    } label: {
                                        Label("Sort Items", systemImage: "arrow.up.arrow.down").labelStyle(.iconOnly)
                                            .frame(width: 36, height: 32)
                                    }
                                    .menuStyle(.borderlessButton).fixedSize()
                                    .help("Sort by \(core.sortOrder.title.lowercased())")
                                }
                                .padding(.horizontal, 5)
                                .glassEffect(.regular.interactive(), in: Capsule())
                                TextField("Search vault", text: $core.query)
                                    .textFieldStyle(.plain)
                                    .focused($searchFocused)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .frame(width: 280)
                                    .glassEffect(.regular.interactive(), in: Capsule())
                                    .accessibilityLabel("Search vault items")
                                Button {
                                    Task { await core.sync() }
                                } label: {
                                    Image(systemName: "arrow.trianglehead.2.clockwise.rotate.90")
                                }
                                .buttonStyle(.glass).buttonBorderShape(.circle)
                                .disabled(!core.canSync || core.isBusy)
                                .accessibilityLabel("Sync vault")
                                .help(core.canSync ? "Download encrypted vault changes" : "Sign in again to resume online sync")
                                Button("Lock", systemImage: "lock") { core.lock() }
                                    .labelStyle(.iconOnly)
                                    .buttonStyle(.glass)
                                    .buttonBorderShape(.circle)
                                    .help("Lock vault (⌘L)")
                            }
                        }
                    }
                    .sharedBackgroundVisibility(.hidden)
                }
                .safeAreaInset(edge: .bottom) {
                    statusBanner
                }
            } else {
                LoginView(core: core)
            }
        }
        .focusedSceneValue(\.vaultSearchAction, core.isUnlocked ? { searchFocused = true } : nil)
    }

    private var itemList: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(core.category.title).font(.headline)
                    Text("\(core.visibleItems.count) item\(core.visibleItems.count == 1 ? "" : "s")")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(14)
            Divider()
            if core.visibleItems.isEmpty {
                ContentUnavailableView("No items", systemImage: core.category.symbol,
                    description: Text(core.query.isEmpty ? "No supported items in this category." : "No items match your search."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $core.selectedID) {
                    ForEach(core.visibleItems, id: \.id) { item in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: VaultCategory.primaryCategory(for: item).symbol)
                                .foregroundStyle(.secondary).padding(.top, 2)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.title).font(.body.weight(.medium)).lineLimit(1)
                                Text(item.username).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                Text(item.website).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                            }
                        }
                        .padding(.vertical, 6)
                        .tag(item.id)
                        .contextMenu {
                            Button("Copy Username") { copier.copy(.username, id: item.id) }
                            Button("Copy Password") { copier.copy(.password, id: item.id) }
                            Button("Copy Website") { copier.copy(.website, id: item.id) }
                        }
                    }
                }
                .listStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var statusBanner: some View {
        HStack {
            Label(core.isDemo ? "DEMO · Fictional data" : "READ-ONLY · \(core.canSync ? "Signed-in session" : "In-memory offline snapshot")",
                  systemImage: "lock.shield")
            if core.omittedItems > 0 {
                Text("\(core.omittedItems) organization/protected/unsupported records omitted")
            }
            Spacer()
            if core.isBusy { ProgressView().controlSize(.small) }
            if let message = copier.feedback ?? core.errorMessage { Text(message) }
            else if let warning = core.cacheWarning { Text(warning).foregroundStyle(.orange) }
        }
        .font(.caption)
        .padding(10)
        .background(.bar)
    }

    private func detail(_ item: ItemSummary) -> some View {
        Form {
            Section {
                Text(item.title).font(.title)
                ForEach(core.fieldDescriptors, id: \.id) { field in
                    HStack(spacing: 12) {
                        CopyFieldBox(title: field.label, value: core.displayedFields[field.id] ?? "••••••••••••", isSecret: field.isSecret) {
                            copier.copyField(id: item.id, fieldID: field.id, label: field.label)
                        }
                        if field.isSecret {
                            Button(core.displayedFields[field.id] == nil ? "Reveal \(field.label)" : "Hide \(field.label)",
                                   systemImage: core.displayedFields[field.id] == nil ? "eye" : "eye.slash") { core.toggleField(field.id) }
                                .labelStyle(.iconOnly)
                                .help(core.displayedFields[field.id] == nil ? "Reveal field" : "Hide field")
                        }
                    }
                }
            }
            Section("Implementation status") {
                Text("Read-only personal vault reader. Organization and reprompt-protected records are omitted. Optional encrypted local cache and protected Touch ID unlock are available in Settings. Editing, attachments, verification-code generation, passkey authentication, and SSH agent remain unimplemented.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .id(item.id)
    }
}
