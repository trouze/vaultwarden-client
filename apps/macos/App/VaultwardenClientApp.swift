import AppKit
import SwiftUI

@main
struct VaultwardenClientApp: App {
    @StateObject private var core: CoreAdapter
    @StateObject private var runtime: AppRuntime
    @Environment(\.openWindow) private var openWindow
    @FocusedValue(\.vaultSearchAction) private var focusSearch

    init() {
        let core = CoreAdapter(persistence: LocalVaultPersistence.applicationDefault())
        _core = StateObject(wrappedValue: core)
        _runtime = StateObject(wrappedValue: AppRuntime(core: core))
    }

    var body: some Scene {
        Window("Vaultwarden", id: "vault") {
            VaultView(core: core, copier: runtime.copier)
                .frame(minWidth: 1020, minHeight: 520)
                .onAppear {
                    let open = openWindow
                    runtime.openMainWindow = {
                        open(id: "vault")
                        NSApplication.shared.activate(ignoringOtherApps: true)
                    }
                    runtime.start()
                }
        }
        .defaultSize(width: 1200, height: 680)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Lock Vault") { core.lock() }
                    .keyboardShortcut("l", modifiers: .command)
                    .disabled(!core.isUnlocked)
            }
            CommandMenu("Vault") {
                Button("Search") { focusSearch?() }
                    .keyboardShortcut("f", modifiers: .command)
                    .disabled(focusSearch == nil)
                Button("Quick Access") { runtime.toggleQuickAccess() }
                    .keyboardShortcut("k", modifiers: .command)
                Divider()
                Button("Copy Username") { runtime.copier.copy(.username, id: core.selectedID) }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(core.selectedItem == nil)
                Button("Copy Password") { runtime.copier.copy(.password, id: core.selectedID) }
                    .keyboardShortcut("c", modifiers: [.command, .option])
                    .disabled(core.selectedItem == nil)
                Button("Copy Website") { runtime.copier.copy(.website, id: core.selectedID) }
                    .keyboardShortcut("c", modifiers: [.command, .option, .shift])
                    .disabled(core.selectedItem == nil)
            }
        }

        MenuBarExtra("Vaultwarden", systemImage: "lock.shield") {
            Text(core.isDemo ? "Fictional demo vault" : "Read-only vault reader")
            Button("Quick Access") { runtime.toggleQuickAccess() }
                .keyboardShortcut("k", modifiers: .command)
            if core.isUnlocked {
                Text("\(core.visibleItems.count) matching items")
                Button("Lock Vault") { core.lock() }
                    .keyboardShortcut("l", modifiers: .command)
            } else {
                Text("Vault is locked — open the main window to sign in or unlock")
            }
            Divider()
            Button("Show Vault") {
                openWindow(id: "vault")
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
            Button("Quit") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q", modifiers: .command)
        }

        Settings {
            SettingsView(preferences: runtime.preferences, shortcut: runtime.shortcut, core: core)
        }
    }
}
