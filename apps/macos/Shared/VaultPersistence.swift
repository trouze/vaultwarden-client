import Foundation

/// OS storage policy is injected; smoke tests and the provider experiment do
/// not touch the user's filesystem or Keychain. Rust owns cache crypto/I/O.
@MainActor
protocol VaultPersistence: AnyObject {
    var hasStoredCache: Bool { get }
    var biometricsEnrolled: Bool { get }
    var biometricsAvailable: Bool { get }
    func restore(client: VaultClient, generation: UInt64, allowInteraction: Bool) async throws -> Session
    func save(client: VaultClient, generation: UInt64) async throws
    func enrollBiometrics(client: VaultClient, generation: UInt64) async throws
    func unlockBiometrics(client: VaultClient, generation: UInt64) async throws -> Session
    func disableBiometrics() async throws
    func forget(client: VaultClient, generation: UInt64) async throws
    func cancelAuthentication()
}

enum PersistenceError: Error, LocalizedError {
    case keychainUnavailable, cacheKeyMissing, biometricUnavailable, cancelled, unsafeState, invalidKeychainData
    case keychainFailure(operation: KeychainOperation, status: Int32)
    var errorDescription: String? {
        switch self {
        case .keychainUnavailable: "Keychain access failed. No unprotected key was stored. Allow access or use master-password unlock."
        case .cacheKeyMissing: "The local cache protection key is missing. The saved cache was not opened. Sign out to discard it and sign in again."
        case .biometricUnavailable: "Touch ID-protected Keychain access is unavailable with this device or signing configuration. Use the master password."
        case .cancelled: "Authentication was cancelled."
        case .unsafeState: "The vault changed during authentication. Unlock and retry."
        case .invalidKeychainData: "The Keychain item has an unexpected format or size. It was not used or automatically replaced."
        case let .keychainFailure(operation, status):
            "\(operation.label) failed (OSStatus \(status)). \(Self.keychainExplanation(status)) No weaker storage policy was used."
        }
    }

    private static func keychainExplanation(_ status: Int32) -> String {
        switch status {
        case -34018: "This build lacks the signing/access-group authorization required by macOS for protected Keychain access. Touch ID hardware working does not grant that authorization. Use master-password unlock."
        case -25291: "The requested Keychain is currently unavailable. Use master-password unlock."
        case -25308: "macOS requires Keychain interaction that is not currently allowed. Retry from the unlocked main window."
        case -25293: "Keychain authorization failed; changed fingerprints or Keychain permissions may require re-enrollment."
        case -50: "macOS rejected the Keychain query or access policy. This is not a failed fingerprint match."
        case -128: "The Keychain operation was cancelled."
        default: "macOS refused the Keychain operation. Use master-password unlock."
        }
    }
}

/// Static operation names only: diagnostics never include identifiers, paths,
/// endpoint URLs, stored bytes, passwords, or raw OS exception descriptions.
enum KeychainOperation {
    case readCacheKey, storeCacheKey, biometricPreflight, storeBiometricKey, readBiometricKey, deleteBiometricKey, deleteCacheKey
    var label: String {
        switch self {
        case .readCacheKey: "Reading cache protection key"
        case .storeCacheKey: "Saving cache protection key"
        case .biometricPreflight: "Protected Keychain capability check"
        case .storeBiometricKey: "Saving Touch ID-protected credential"
        case .readBiometricKey: "Reading Touch ID-protected credential"
        case .deleteBiometricKey: "Removing previous Touch ID-protected credential"
        case .deleteCacheKey: "Removing cache protection key"
        }
    }
}
