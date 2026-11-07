import Foundation
import LocalAuthentication

/// Context configuration/evaluation stays on the main actor before transfer.
/// A worker uses it only for SecItem access; concurrent invalidate() is the
/// framework-supported cancellation mechanism, not arbitrary context mutation.
private final class AuthenticationContextHandle: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
}

@MainActor
final class LocalVaultPersistence: VaultPersistence {
    private let directory: URL
    private let keys: KeychainVaultKeys
    private var authenticationContext: LAContext?
    private var biometricOperationActive = false

    init(directory: URL, namespace: String) {
        self.directory = directory
        self.keys = KeychainVaultKeys(namespace: namespace)
    }

    static func applicationDefault() -> LocalVaultPersistence? {
        guard let support = try? FileManager.default.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true) else { return nil }
        return LocalVaultPersistence(directory: support.appendingPathComponent("Vaultwarden", isDirectory: true),
            namespace: Bundle.main.bundleIdentifier ?? "org.vaultwardenclient.desktop")
    }

    var hasStoredCache: Bool {
        ["vault.cache", "vault.previous"].contains {
            FileManager.default.fileExists(atPath: directory.appendingPathComponent($0).path)
        }
    }
    var biometricsEnrolled: Bool { keys.hasBiometricItem }
    var biometricsAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    func restore(client: VaultClient, generation: UInt64, allowInteraction: Bool) async throws -> Session {
        let path = directory.path
        let keys = keys
        return try await Task.detached(priority: .userInitiated) {
            var key = try keys.cacheKey(create: false, allowInteraction: allowInteraction, client: client)
            defer { key.resetBytes(in: key.startIndex..<key.endIndex) }
            try client.configureCache(directory: path, deviceKey: key, expectedGeneration: generation)
            return try client.restoreCache(expectedGeneration: generation)
        }.value
    }

    func save(client: VaultClient, generation: UInt64) async throws {
        let path = directory.path
        let keys = keys
        let existing = hasStoredCache
        try await Task.detached(priority: .userInitiated) {
            // Never generate a replacement key for an existing unreadable cache.
            var key = try keys.cacheKey(create: !existing, allowInteraction: true, client: client)
            defer { key.resetBytes(in: key.startIndex..<key.endIndex) }
            try client.configureCache(directory: path, deviceKey: key, expectedGeneration: generation)
            try client.saveCache(expectedGeneration: generation)
        }.value
        // Backup exclusion is metadata-only; cache file contents are always AEAD.
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var folder = directory
        try? folder.setResourceValues(values)
    }

    func enrollBiometrics(client: VaultClient, generation: UInt64) async throws {
        guard !biometricOperationActive else { throw PersistenceError.unsafeState }
        guard biometricsAvailable else { throw PersistenceError.biometricUnavailable }
        biometricOperationActive = true
        defer { biometricOperationActive = false }
        let keys = keys
        // Query only capability/item metadata, never credential bytes, and
        // stop before asking the user to touch the sensor if signing denies it.
        try await Task.detached { try keys.preflightBiometrics() }.value
        let session = try client.session()
        guard session.generation == generation && session.state == .unlocked else {
            throw PersistenceError.unsafeState
        }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        authenticationContext = context
        defer {
            context.invalidate()
            if authenticationContext === context { authenticationContext = nil }
        }
        let approved = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Enable Touch ID unlock for this Vaultwarden account")
        guard approved else { throw PersistenceError.cancelled }
        let handle = AuthenticationContextHandle(context)
        try await Task.detached(priority: .userInitiated) {
            var bytes = try client.biometricMaterial(expectedGeneration: generation)
            defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
            try keys.storeBiometric(bytes, context: handle.context)
            let session = try client.session()
            if session.generation != generation || session.state != .unlocked {
                try keys.delete(biometric: true)
                throw PersistenceError.unsafeState
            }
        }.value
    }

    func unlockBiometrics(client: VaultClient, generation: UInt64) async throws -> Session {
        guard !biometricOperationActive else { throw PersistenceError.unsafeState }
        biometricOperationActive = true
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.localizedReason = "Unlock Vaultwarden"
        authenticationContext = context
        defer {
            context.invalidate()
            if authenticationContext === context { authenticationContext = nil }
            biometricOperationActive = false
        }
        let keys = keys
        let handle = AuthenticationContextHandle(context)
        return try await Task.detached(priority: .userInitiated) {
            // The Keychain ACL itself authenticates retrieval. No stand-alone LA
            // dialog followed by access to an unprotected credential.
            var bytes = try keys.readBiometric(context: handle.context)
            defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
            return try client.unlockBiometric(material: bytes, expectedGeneration: generation)
        }.value
    }

    func disableBiometrics() async throws {
        cancelAuthentication()
        guard !biometricOperationActive else { throw PersistenceError.unsafeState }
        let keys = keys
        try await Task.detached { try keys.delete(biometric: true) }.value
    }

    func forget(client: VaultClient, generation: UInt64) async throws {
        cancelAuthentication()
        let keys = keys
        let path = directory.path
        try await Task.detached {
            var failed = false
            do { try keys.forget() } catch { failed = true }
            do { try client.discardSavedCache(directory: path, expectedGeneration: generation) } catch { failed = true }
            if failed { throw PersistenceError.keychainUnavailable }
        }.value
    }

    func cancelAuthentication() { authenticationContext?.invalidate() }
}
