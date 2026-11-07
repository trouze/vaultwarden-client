import Foundation
import LocalAuthentication
import Security

/// The legacy login Keychain holds only a device cache-encryption key, never
/// master passwords/user keys/tokens. Rebuilt ad-hoc binaries may need user ACL
/// approval. This is not a claim of hardware-bound storage or migration immunity.
/// Biometric material goes ONLY to the Data Protection Keychain with a real
/// biometryCurrentSet ACL. Missing entitlements/policy support fail closed.
final class KeychainVaultKeys: @unchecked Sendable {
    private let namespace: String
    init(namespace: String) { self.namespace = namespace }

    private func query(biometric: Bool) -> [String: Any] {
        var result: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: namespace + (biometric ? ".biometric.v1" : ".cache.v1"),
         kSecAttrAccount as String: biometric ? "protected-user-key" : "cache-protection-key",
         kSecUseDataProtectionKeychain as String: biometric]
        // Synchronizability is unnecessary for device-only biometric ACL items.
        // Keep that query minimal, rather than mixing unrelated item options.
        if !biometric { result[kSecAttrSynchronizable as String] = false }
        return result
    }

    func cacheKey(create: Bool, allowInteraction: Bool, client: VaultClient) throws -> Data {
        var request = query(biometric: false)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        if !allowInteraction {
            let context = LAContext()
            context.interactionNotAllowed = true
            request[kSecUseAuthenticationContext as String] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecSuccess {
            guard let data = result as? Data, data.count == 32 else { throw PersistenceError.invalidKeychainData }
            return data
        }
        guard status == errSecItemNotFound else {
            throw PersistenceError.keychainFailure(operation: .readCacheKey, status: status)
        }
        guard create else { throw PersistenceError.cacheKeyMissing }
        var bytes = try client.newCacheKey()
        defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
        var add = query(biometric: false)
        add[kSecValueData as String] = Data(bytes)
        let added = SecItemAdd(add as CFDictionary, nil)
        if added == errSecDuplicateItem { return try cacheKey(create: false, allowInteraction: allowInteraction, client: client) }
        guard added == errSecSuccess else { throw PersistenceError.keychainFailure(operation: .storeCacheKey, status: added) }
        return bytes
    }

    var hasBiometricItem: Bool {
        biometricMetadataStatus() == errSecSuccess
    }

    private func biometricMetadataStatus() -> OSStatus {
        var request = query(biometric: true)
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext()
        context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        return SecItemCopyMatching(request as CFDictionary, nil)
    }

    func preflightBiometrics() throws {
        try Self.validateBiometricPreflight(biometricMetadataStatus())
    }

    static func validateBiometricPreflight(_ status: OSStatus) throws {
        // A missing item means the protected Keychain channel is accessible.
        // InteractionRequired can mean an existing ACL-protected item; do not
        // attempt to retrieve its bytes during capability detection.
        guard status == errSecSuccess || status == errSecItemNotFound || status == errSecInteractionNotAllowed else {
            throw PersistenceError.keychainFailure(operation: .biometricPreflight, status: status)
        }
    }

    func storeBiometric(_ bytes: Data, context: LAContext) throws {
        guard bytes.count == 104 else { throw PersistenceError.unsafeState }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet, &error) else { throw PersistenceError.biometricUnavailable }
        try delete(biometric: true)
        var add = query(biometric: true)
        add[kSecAttrAccessControl as String] = access
        add[kSecValueData as String] = Data(bytes)
        add[kSecUseAuthenticationContext as String] = context
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            // NEVER fall back to an ordinary/unprotected user-key entry.
            throw PersistenceError.keychainFailure(operation: .storeBiometricKey, status: status)
        }
    }

    func readBiometric(context: LAContext) throws -> Data {
        var request = query(biometric: true)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        request[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecUserCanceled { throw PersistenceError.cancelled }
        guard status == errSecSuccess else {
            throw PersistenceError.keychainFailure(operation: .readBiometricKey, status: status)
        }
        guard let data = result as? Data, data.count == 104 else { throw PersistenceError.invalidKeychainData }
        return data
    }

    func delete(biometric: Bool) throws {
        let status = SecItemDelete(query(biometric: biometric) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            // Some ad-hoc builds cannot access DP Keychain at all. No item could
            // have been enrolled by this build; normal cache deletion still works.
            if biometric && status == errSecMissingEntitlement { return }
            throw PersistenceError.keychainFailure(operation: biometric ? .deleteBiometricKey : .deleteCacheKey, status: status)
        }
    }

    func forget() throws {
        // Remove the credential-equivalent biometric key before metadata key.
        try delete(biometric: true)
        try delete(biometric: false)
    }
}
