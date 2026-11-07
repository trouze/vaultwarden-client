import Foundation

private struct CheckFailed: Error {
    let message: String
}

/// Executable smoke tests exercise real generated bindings and the Swift adapter.
/// No mocked Swift backend, UI automation, network, or signing credentials.
@main
struct BridgeSmoke {
    @MainActor
    static func main() async throws {
        let client = VaultClient()
        try check(try client.session().state == .locked, "Initial session must be locked")
        try expect(.Locked) { _ = try client.search(query: "") }
        let session = try client.unlockDemo()
        let items = try client.search(query: "")
        try check(items.count == 3, "Rust demo must contain three items")
        try check(try client.search(query: "READER@").first?.id == "demo-docs", "Search must reach Rust")
        try check(try client.item(id: "demo-example").favorite, "Item details must round-trip")
        try expect(.NotFound) { _ = try client.item(id: "unknown") }
        try expect(.InvalidQuery) { _ = try client.search(query: String(repeating: "x", count: 257)) }
        try check(try client.matchService(service: "example.com").count == 1, "Exact domain must match")
        try check(try client.matchService(service: "example.com.evil.test").isEmpty, "Suffix attack must not match")
        try expect(.InvalidService) { _ = try client.matchService(service: "http://example.com") }
        try check(try client.revealPassword(id: "demo-example", expectedGeneration: session.generation).hasPrefix("DEMO-ONLY"), "Explicit reveal must round-trip")
        _ = try client.lock()
        try expect(.Locked) { _ = try client.revealPassword(id: "demo-example", expectedGeneration: session.generation) }
        _ = try client.unlockDemo()
        try expect(.StaleSession) { _ = try client.revealPassword(id: "demo-example", expectedGeneration: session.generation) }

        let core = CoreAdapter()
        try check(!core.isUnlocked && core.items.isEmpty, "Swift adapter must start locked")
        core.unlockDemo()
        core.selectedID = "demo-example"
        core.toggleReveal()
        try check(core.revealedPassword != nil, "Explicit Swift reveal must work")
        core.selectedID = "demo-docs"
        try check(core.revealedPassword == nil, "Selection change must clear revealed password")
        core.query = "example.org"
        try check(core.items.count == 1, "Swift search must update results")
        core.toggleReveal()
        core.lock()
        try check(!core.isUnlocked && core.items.isEmpty && core.selectedID == nil && core.revealedPassword == nil && core.query.isEmpty, "Lock must clear Swift-visible state")

        core.unlockDemo()
        try check(try core.matchingCredentials(services: ["example.com", "https://example.com/login"], recordID: nil).count == 1, "Provider matching must deduplicate")
        try check(try core.matchingCredentials(services: ["evil.test"], recordID: nil).isEmpty, "Provider must not fall back to unrelated credentials")
        try check(try core.matchingCredentials(services: ["example.com"], recordID: "demo-docs").isEmpty, "Record IDs must not bypass service matching")
        let otherProcess = CoreAdapter()
        try expect(.Locked) { _ = try otherProcess.passwordForSelection(id: "demo-example") }
        core.lock()
        try InteractionChecks.run()
        try await InteractionChecks.persistenceChecks()
        await core.login(server: "http://example.com", email: "public@example.com", password: "public-fixture", code: nil)
        try check(!core.isUnlocked && !core.isBusy && !core.hasCachedVault, "Invalid HTTPS configuration fails closed off the main actor")
        try check(!(core.errorMessage ?? "").contains("example.com"), "Errors must not disclose endpoint values")
        let cancelledGeneration = core.session.generation
        core.lock()
        await core.login(server: "https://example.com", email: "public@example.com", password: "public-fixture", code: nil,
            expectedGeneration: cancelledGeneration)
        try check(!core.isUnlocked && !core.isBusy, "A queued UI login cannot begin after cancellation")
        print("Swift → UniFFI → Rust bridge and adapter smoke tests passed")
    }

    private static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw CheckFailed(message: message) }
    }

    private static func expect(_ expected: CoreError, action: () throws -> Void) throws {
        do {
            try action()
            throw CheckFailed(message: "Expected a structured core error")
        } catch let error as CoreError {
            try check(error == expected, "Wrong structured core error")
        }
    }
}
