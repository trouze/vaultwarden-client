import SwiftUI

struct SettingsView: View {
    @ObservedObject var preferences: Preferences
    @ObservedObject var shortcut: GlobalShortcut
    @ObservedObject var core: CoreAdapter

    var body: some View {
        Form {
            Section("Quick access") {
                Toggle("Enable global shortcut", isOn: $preferences.globalShortcutEnabled)
                Picker("Shortcut", selection: $preferences.shortcut) {
                    ForEach(QuickAccessShortcut.allCases) { Text($0.label).tag($0) }
                }.disabled(!preferences.globalShortcutEnabled)
                Text("The shortcut opens a search-and-copy panel without needing Accessibility or Input Monitoring permissions.")
                    .font(.caption).foregroundStyle(.secondary)
                if let error = shortcut.errorMessage { Text(error).foregroundStyle(.red) }
            }
            Section("Security behavior") {
                Picker("Lock after inactivity", selection: $preferences.idleLock) {
                    ForEach(IdleLockInterval.allCases) { Text($0.label).tag($0) }
                }
                Picker("Clear copied credentials after", selection: $preferences.clipboardInterval) {
                    ForEach(ClipboardInterval.allCases) { Text($0.label).tag($0) }
                }
                Text("Only activity in Vaultwarden extends unlock. Lock clears its clipboard copy if the pasteboard change-count still matches; later copies are left alone. Clipboard-manager exclusion markers are best effort.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Read-only early build") {
                Text("Password and authenticator-code login; encrypted personal sync. Local cache is opt-in. Use disposable test accounts until security/interoperability review is complete.")
                LabeledContent("Backend", value: "Rust + UniFFI")
                LabeledContent("Native AutoFill / passkey provider", value: "Deferred — requires paid signing")
                LabeledContent("Developer ID / browser extension", value: "Not planned")
                LabeledContent("SSH / editing", value: "Future implementation")
            }
            Section("Local encrypted vault") {
                LabeledContent("Cache", value: core.cacheSaved ? "Saved on this Mac" : "Not saved")
                Button("Save Encrypted Cache on This Mac") { Task { await core.saveLocalCache() } }
                    .disabled(!core.isUnlocked || core.isDemo || core.isBusy || !core.persistenceAvailable)
                if core.biometricsEnrolled {
                    Button("Disable Touch ID Unlock") { Task { await core.disableBiometrics() } }.disabled(core.isBusy)
                } else {
                    Button("Enable Touch ID Unlock") { Task { await core.enableBiometrics() } }
                        .disabled(!core.isUnlocked || core.isDemo || core.isBusy || !core.biometricsAvailable)
                }
                Text("Touch ID enrollment also saves the encrypted cache. Its user key is stored only behind a biometryCurrentSet Keychain ACL; unsupported signing configurations fail closed. Fingerprint changes require master-password unlock and re-enrollment.")
                    .font(.caption).foregroundStyle(.secondary)
                if let warning = core.cacheWarning { Text(warning).font(.caption).foregroundStyle(.orange) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 560, height: 720)
    }
}
