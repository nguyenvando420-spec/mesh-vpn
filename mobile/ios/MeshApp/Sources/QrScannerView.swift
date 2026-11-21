@preconcurrency import AVFoundation
import MeshCoreKit
import SwiftUI
import UIKit

/// Serializes `AVCaptureSession` start/stop off the main thread for Swift 6 safety.
private final class CaptureSessionRunner: @unchecked Sendable {
    // SAFETY-SENDABLE: `session` lifecycle operations are serialized on `sessionQueue`.
    private let sessionQueue = DispatchQueue(label: "dev.meshvpn.ios.qr-camera")
    let session = AVCaptureSession()

    func configureAndStart(
        delegate: AVCaptureMetadataOutputObjectsDelegate & Sendable,
        onUnavailable: @escaping @MainActor @Sendable (String) -> Void
    ) {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        switch status {
        case .authorized:
            startPipeline(delegate: delegate, onUnavailable: onUnavailable)
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                if granted {
                    self.startPipeline(delegate: delegate, onUnavailable: onUnavailable)
                } else {
                    Task { @MainActor in
                        onUnavailable(
                            "Camera access was denied. Paste the token or enter manually."
                        )
                    }
                }
            }
        default:
            Task { @MainActor in
                onUnavailable("Camera permission is disabled in iOS Settings.")
            }
        }
    }

    func stop() {
        sessionQueue.async { [self] in
            if self.session.isRunning {
                self.session.stopRunning()
            }
        }
    }

    private func startPipeline(
        delegate: AVCaptureMetadataOutputObjectsDelegate & Sendable,
        onUnavailable: @escaping @MainActor @Sendable (String) -> Void
    ) {
        sessionQueue.async { [self] in
            guard let device = AVCaptureDevice.default(for: .video) else {
                Task { @MainActor in
                    onUnavailable("No camera device available. Use Paste or Manual Entry.")
                }
                return
            }
            do {
                self.session.beginConfiguration()
                let input = try AVCaptureDeviceInput(device: device)
                if self.session.canAddInput(input) {
                    self.session.addInput(input)
                }
                let output = AVCaptureMetadataOutput()
                if self.session.canAddOutput(output) {
                    self.session.addOutput(output)
                    output.setMetadataObjectsDelegate(delegate, queue: .main)
                    if output.availableMetadataObjectTypes.contains(.qr) {
                        output.metadataObjectTypes = [.qr]
                    }
                }
                self.session.commitConfiguration()
                if !self.session.isRunning {
                    self.session.startRunning()
                }
            } catch {
                self.session.commitConfiguration()
                Task { @MainActor in
                    onUnavailable("Unable to start QR camera scanner.")
                }
            }
        }
    }
}

private final class QrMetadataDelegate: NSObject, AVCaptureMetadataOutputObjectsDelegate, Sendable {
    private let handled = LockedBox(false)
    private let onDecoded: @MainActor @Sendable (String) -> Void

    init(onDecoded: @escaping @MainActor @Sendable (String) -> Void) {
        self.onDecoded = onDecoded
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let codeObj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              codeObj.type == .qr,
              let rawValue = codeObj.stringValue else {
            return
        }
        let isFirstScan = handled.withLock { alreadyHandled -> Bool in
            guard !alreadyHandled else { return false }
            alreadyHandled = true
            return true
        }
        guard isFirstScan else { return }
        let callback = onDecoded
        Task { @MainActor in
            callback(rawValue)
        }
    }
}

/// UIKit camera scanner view controller for `mesh://join?...` QR payloads.
private final class QrScannerController: UIViewController {
    private let runner = CaptureSessionRunner()
    private let metadataDelegate: QrMetadataDelegate
    private let statusLabel = UILabel()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    init(onDecoded: @escaping @MainActor @Sendable (String) -> Void) {
        self.metadataDelegate = QrMetadataDelegate(onDecoded: onDecoded)
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let layer = AVCaptureVideoPreviewLayer(session: runner.session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        self.previewLayer = layer

        statusLabel.textColor = .white
        statusLabel.numberOfLines = 0
        statusLabel.textAlignment = .center
        statusLabel.font = .preferredFont(forTextStyle: .callout)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)
        NSLayoutConstraint.activate([
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            statusLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24)
        ])

        runner.configureAndStart(delegate: metadataDelegate) { [weak self] message in
            self?.statusLabel.text = message
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        runner.stop()
    }
}

/// SwiftUI wrapper presenting the live `AVFoundation` QR scanner (`US-091`).
@MainActor
struct QrScannerSheetView: View {
    let onScan: @MainActor @Sendable (String) -> Void
    let onCancel: @MainActor () -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        NavigationView {
            QrScannerRepresentable(onScan: onScan)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle(Text(L10n.tr("onboarding.tab.scan_qr", locale: locale)))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(L10n.tr("generic.cancel", locale: locale), action: onCancel)
                    }
                }
        }
    }
}

private struct QrScannerRepresentable: UIViewControllerRepresentable {
    let onScan: @MainActor @Sendable (String) -> Void

    func makeUIViewController(context: Context) -> QrScannerController {
        QrScannerController(onDecoded: onScan)
    }

    func updateUIViewController(_ uiViewController: QrScannerController, context: Context) {}
}
