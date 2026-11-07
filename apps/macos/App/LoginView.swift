import Combine
import SwiftUI

@MainActor
private final class LoginForm: ObservableObject {
    @Published var server = ""
    @Published var email = ""
    @Published var password = ""
    @Published var code = ""
    @Published var needsCode = false
}

struct LoginView: View {
    @ObservedObject var core: CoreAdapter
    @StateObject private var form = LoginForm()

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield").font(.system(size: 48)).foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Vaultwarden").font(.largeTitle)
            Text(core.hasCachedVault ? "Unlock your vault" : "Sign in to your server")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 12) {
                if !core.hasCachedVault {
                    TextField("Server URL (HTTPS)", text: $form.server)
                        .textContentType(.URL).autocorrectionDisabled()
                    TextField("Email", text: $form.email)
                        .textContentType(.username).autocorrectionDisabled()
                }
                SecureField("Master password", text: $form.password)
                    .textContentType(.password)
                if form.needsCode || core.twoFactorProviders.contains(0) {
                    SecureField("Authenticator verification code", text: $form.code)
                        .textContentType(.oneTimeCode)
                    Text("Re-enter your master password and the current authenticator code.")
                        .font(.caption).foregroundStyle(.secondary)
                } else if !core.twoFactorProviders.isEmpty {
                    Text("This account requires an unsupported 2FA provider. Only authenticator codes are supported in this build.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .textFieldStyle(.roundedBorder)
            .disabled(core.isBusy)
            if core.isBusy {
                ProgressView("Authenticating and decrypting…")
                Button("Cancel") { core.lock(); form.password = ""; form.code = ""; form.needsCode = false }
            } else {
                Button(core.hasCachedVault ? "Unlock" : "Sign In") { submit() }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(form.password.isEmpty || (!core.hasCachedVault && (core.hasStoredCache || form.server.isEmpty || form.email.isEmpty)))
            }
            if let message = core.errorMessage {
                Text(message).foregroundStyle(.red).font(.callout).multilineTextAlignment(.center)
            }
            if let warning = core.cacheWarning {
                Text(warning).foregroundStyle(.orange).font(.caption).multilineTextAlignment(.center)
            }
            if core.hasCachedVault {
                if core.biometricsEnrolled && !core.isBusy {
                    Button("Unlock with Touch ID", systemImage: "touchid") { Task { await core.unlockWithBiometrics() } }
                        .buttonStyle(.glass)
                }
                Button("Forget Account / Sign Out") { Task { await core.logout() }; form.password = ""; form.code = "" }
                    .disabled(core.isBusy)
                Text(core.cacheSaved ? "Your encrypted local cache can be unlocked offline after restart. Sign in again to resume online sync." : "This snapshot is in memory only. Sign in again to resume online sync after locking.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            } else {
                if core.hasStoredCache {
                    Button("Allow Keychain Access / Open Saved Cache") { Task { await core.restoreSavedCache() } }
                        .disabled(core.isBusy)
                    Button("Discard Saved Cache") { Task { await core.logout() } }.disabled(core.isBusy)
                } else {
                    Toggle("Remember encrypted vault on this Mac", isOn: $core.rememberVault)
                        .toggleStyle(.checkbox).disabled(core.isBusy || !core.persistenceAvailable)
                    Button("Explore with Fictional Demo Data") { form.password = ""; form.code = ""; core.unlockDemo() }
                        .disabled(core.isBusy)
                }
            }
            Text("Read-only early build. Local persistence is opt-in and encrypted. Master passwords and tokens are never saved.\nUse a disposable test account until interoperability/security review is complete.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .padding(32)
        .frame(width: 440)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onChange(of: core.twoFactorProviders) { _, providers in
            if providers.contains(0) { form.needsCode = true }
        }
        .onChange(of: form.server) { _, _ in form.needsCode = false }
        .onChange(of: form.email) { _, _ in form.needsCode = false }
        .onDisappear {
            form.password = ""; form.code = ""; form.server = ""; form.email = ""
            form.needsCode = false
            if !core.isUnlocked { core.lock() }
        }
    }

    private func submit() {
        let password = form.password
        let code = form.code.trimmingCharacters(in: .whitespacesAndNewlines)
        form.password = ""
        form.code = ""
        let server = form.server.trimmingCharacters(in: .whitespacesAndNewlines)
        let email = form.email.trimmingCharacters(in: .whitespacesAndNewlines)
        let generation = core.session.generation
        Task {
            if core.hasCachedVault {
                await core.unlockCached(password: password, expectedGeneration: generation)
            } else {
                await core.login(server: server, email: email, password: password, code: code.isEmpty ? nil : code, expectedGeneration: generation)
            }
        }
    }
}
