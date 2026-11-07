import AppKit
import SwiftUI

/// Handle field-editor commands directly so arrow/Return/Escape behavior does
/// not depend on SwiftUI key bubbling or steal ordinary search-text editing.
struct QuickSearchField: NSViewRepresentable {
    @ObservedObject var model: QuickAccessModel
    let copy: (CopyField) -> Void
    let dismiss: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = "Search demo vault"
        field.setAccessibilityLabel("Search demo vault")
        field.sendsSearchStringImmediately = true
        field.recentsAutosaveName = nil
        field.maximumRecents = 0
        field.delegate = context.coordinator
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != model.query { field.stringValue = model.query }
        if context.coordinator.focusedPresentation != model.presentation {
            context.coordinator.focusedPresentation = model.presentation
            DispatchQueue.main.async { [weak field] in
                guard let field, let window = field.window, window.isVisible else { return }
                window.makeFirstResponder(field)
            }
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: QuickSearchField
        var focusedPresentation: Int?
        init(parent: QuickSearchField) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            parent.model.query = field.stringValue
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
            guard !textView.hasMarkedText() else { return false }
            switch NSStringFromSelector(commandSelector) {
            case "moveDown:": parent.model.moveSelection(1)
            case "moveUp:": parent.model.moveSelection(-1)
            case "insertNewline:", "insertNewlineIgnoringFieldEditor:", "insertLineBreak:":
                let field: CopyField = NSApp.currentEvent?.modifierFlags.contains(.option) == true ? .username : .password
                parent.copy(field)
            case "cancelOperation:": parent.dismiss()
            default: return false
            }
            return true
        }
    }
}
