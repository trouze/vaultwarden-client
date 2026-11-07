import AppKit
import AuthenticationServices
import SwiftUI

/// Synthetic password provider only. Does not share or unlock any real vault.
/// A fresh request always needs an explicit user action, even in a reused process.
@MainActor
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let core = CoreAdapter()
    private var hostingController: NSHostingController<ProviderView>?

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 380))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        present(services: serviceIdentifiers.map(\.identifier))
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        // Mixed picker: offer passwords only; never synthesize a passkey response.
        present(services: serviceIdentifiers.map(\.identifier))
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        core.lock()
        cancel(credentialRequest.type == .password ? .userInteractionRequired : .failed)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard credentialRequest.type == .password,
              let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let recordID = identity.recordIdentifier else {
            core.lock()
            cancel(.credentialIdentityNotFound)
            return
        }
        present(services: [identity.serviceIdentifier.identifier], recordID: recordID)
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        core.lock()
        cancel(.failed) // Passkeys are not implemented or advertised.
    }

    private func present(services: [String], recordID: String? = nil) {
        core.lock()
        loadViewIfNeeded()
        if let hostingController {
            hostingController.view.removeFromSuperview()
            hostingController.removeFromParent()
        }
        let host = NSHostingController(rootView: ProviderView(
            core: core, services: services, recordID: recordID,
            complete: { [weak self] item in self?.complete(item, services: services, recordID: recordID) },
            cancel: { [weak self] in
                self?.core.lock()
                self?.cancel(.userCanceled)
            }
        ))
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        hostingController = host
    }

    private func complete(_ item: ItemSummary, services: [String], recordID: String?) {
        do {
            // Revalidate at completion, not only when the picker was rendered.
            let matches = try core.matchingCredentials(services: services, recordID: recordID)
            guard matches.contains(where: { $0.id == item.id }) else {
                core.lock()
                cancel(.credentialIdentityNotFound)
                return
            }
            let password = try core.passwordForSelection(id: item.id)
            let credential = ASPasswordCredential(user: item.username, password: password)
            core.lock()
            extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        } catch {
            core.lock()
            cancel(.failed)
        }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }
}

private struct ProviderView: View {
    @ObservedObject var core: CoreAdapter
    let services: [String]
    let recordID: String?
    let complete: (ItemSummary) -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Synthetic Credential Provider", systemImage: "key").font(.title2)
            Text("Development only. No real authentication or saved vault. Only example.com/.org/.net demo accounts are available.")
                .font(.callout).foregroundStyle(.secondary)
            if core.isUnlocked {
                let matches = (try? core.matchingCredentials(services: services, recordID: recordID)) ?? []
                if matches.isEmpty {
                    Text("No demo credentials match this request.")
                } else {
                    ForEach(matches, id: \.id) { item in
                        Button { complete(item) } label: {
                            VStack(alignment: .leading) {
                                Text("Use \(item.title)")
                                Text(item.username).font(.caption)
                            }
                        }
                    }
                }
            } else {
                Button("Load Fictional Demo Credentials") { core.unlockDemo() }
                    .buttonStyle(.borderedProminent)
            }
            Spacer()
            Button("Cancel", action: cancel)
        }
        .padding(24)
        .frame(minWidth: 440, minHeight: 340)
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(
            for: NSWorkspace.willSleepNotification
        )) { _ in core.lock() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(
            for: NSWorkspace.sessionDidResignActiveNotification
        )) { _ in core.lock() }
        .onDisappear { core.lock() }
    }
}
