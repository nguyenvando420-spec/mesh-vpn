import SwiftUI
import UIKit

/// Presents `UIActivityViewController` for a temporary bugreport `.tar` and runs cleanup.
struct ShareSheetView: UIViewControllerRepresentable {
    let fileURL: URL
    let onFinish: @MainActor @Sendable (URL) -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(
            activityItems: [fileURL],
            applicationActivities: nil
        )
        let urlCopy = fileURL
        let completionCallback = onFinish
        controller.completionWithItemsHandler = { _, _, _, _ in
            Task { @MainActor in
                completionCallback(urlCopy)
            }
        }
        return controller
    }

    func updateUIViewController(
        _ uiViewController: UIActivityViewController,
        context: Context
    ) {}
}
