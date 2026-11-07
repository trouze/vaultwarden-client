import AppKit

@MainActor
protocol ClipboardWriting: AnyObject {
    var changeCount: Int { get }
    func writeConcealed(_ value: String) -> Bool
    func clear()
}

@MainActor
final class SystemClipboard: ClipboardWriting {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    static let excludeUniversal = NSPasteboard.PasteboardType("org.nspasteboard.excludeFromUniversalClipboard")
    private let pasteboard: NSPasteboard

    init(pasteboard: NSPasteboard = .general) { self.pasteboard = pasteboard }
    var changeCount: Int { pasteboard.changeCount }

    func writeConcealed(_ value: String) -> Bool {
        let item = NSPasteboardItem()
        guard item.setString(value, forType: .string),
              item.setString("", forType: Self.concealed),
              item.setString("", forType: Self.transient),
              item.setString("", forType: Self.excludeUniversal) else { return false }
        pasteboard.clearContents()
        return pasteboard.writeObjects([item])
    }

    func clear() { pasteboard.clearContents() }
}

/// Owns only a pasteboard change-count and deadline, never a retained secret.
/// Expiration/lock must not erase something the user copied afterwards.
@MainActor
final class SafeClipboard {
    private let writer: any ClipboardWriting
    private let clock: () -> TimeInterval
    private var ownedChangeCount: Int?
    private var expiration: TimeInterval?

    init(writer: any ClipboardWriting, clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.writer = writer
        self.clock = clock
    }

    @discardableResult
    func copy(_ value: String, lifetime: TimeInterval) -> Bool {
        guard !value.isEmpty, lifetime.isFinite, lifetime > 0, lifetime <= 60 else { return false }
        // Revoke any older copy first, but only while still owned by this app.
        clearOwned()
        guard writer.writeConcealed(value) else { return false }
        ownedChangeCount = writer.changeCount
        expiration = clock() + lifetime
        return true
    }

    func expireIfDue() {
        guard let expiration, clock() >= expiration else { return }
        clearOwned()
    }

    func clearOwned() {
        if let ownedChangeCount, writer.changeCount == ownedChangeCount {
            writer.clear()
        }
        ownedChangeCount = nil
        expiration = nil
    }
}
