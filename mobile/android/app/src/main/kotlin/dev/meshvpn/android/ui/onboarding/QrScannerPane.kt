package dev.meshvpn.android.ui.onboarding

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import dev.meshvpn.android.data.diagnostics.SafeLogger
import java.util.concurrent.Executors

/**
 * Pure CameraX + `com.google.zxing:core` QR scanner (`US-084`, `ADR-018`) with zero ML Kit / GMS.
 */
@Composable
fun QrScannerPane(
    paused: Boolean,
    onQrDecoded: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var cameraError by remember { mutableStateOf<String?>(null) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) {
            cameraError = "Camera permission is required to scan join QR codes."
        }
    }

    if (!hasCameraPermission) {
        CameraPermissionCard(
            errorMessage = cameraError,
            onRequestPermission = { permissionLauncher.launch(Manifest.permission.CAMERA) },
            modifier = modifier,
        )
        return
    }

    CameraPreviewScanner(
        paused = paused,
        onQrDecoded = onQrDecoded,
        onCameraError = { cameraError = it },
        errorMessage = cameraError,
        modifier = modifier,
    )
}

@Composable
private fun CameraPermissionCard(
    errorMessage: String?,
    onRequestPermission: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Camera permission needed",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = errorMessage
                    ?: "Mesh VPN scans the administrator QR offline on-device using CameraX.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = onRequestPermission) {
                Text("Grant Camera Permission")
            }
        }
    }
}

@Composable
private fun CameraPreviewScanner(
    paused: Boolean,
    onQrDecoded: (String) -> Unit,
    onCameraError: (String) -> Unit,
    errorMessage: String?,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    val pausedRef = remember { booleanArrayOf(paused) }.apply { this[0] = paused }

    DisposableEffect(lifecycleOwner) {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val reader = createQrReader()

        val listener = Runnable {
            try {
                val provider = providerFuture.get()
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(analysisExecutor) { image ->
                    decodeImageProxy(
                        image = image,
                        reader = reader,
                        paused = pausedRef[0],
                        onDecoded = { decoded ->
                            mainExecutor.execute { onQrDecoded(decoded) }
                        },
                    )
                }
                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            } catch (err: Exception) {
                SafeLogger.w("QrScannerPane", "Unable to start CameraX preview", err)
                onCameraError("Camera preview unavailable; use Paste URI or Manual tab.")
            }
        }
        providerFuture.addListener(listener, mainExecutor)

        onDispose {
            runCatching { providerFuture.get().unbindAll() }
            analysisExecutor.shutdown()
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(260.dp)
            .clip(RoundedCornerShape(16.dp))
            .border(2.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(16.dp)),
        contentAlignment = Alignment.BottomCenter,
    ) {
        AndroidView(
            factory = { previewView },
            modifier = Modifier.fillMaxSize(),
        )
        Text(
            text = errorMessage ?: if (paused) {
                "Review detected server details..."
            } else {
                "Point camera at Mesh administrator QR code"
            },
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onPrimary,
            modifier = Modifier.padding(12.dp),
        )
    }
}

private fun createQrReader(): MultiFormatReader {
    val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
    )
    return MultiFormatReader().apply { setHints(hints) }
}

private fun decodeImageProxy(
    image: ImageProxy,
    reader: MultiFormatReader,
    paused: Boolean,
    onDecoded: (String) -> Unit,
) {
    try {
        if (paused) {
            return
        }
        val yPlane = image.planes.getOrNull(0) ?: return
        val yBytes = extractLuminanceBytes(
            buffer = yPlane.buffer,
            rowStride = yPlane.rowStride,
            width = image.width,
            height = image.height,
        )
        val source = PlanarYUVLuminanceSource(
            yBytes,
            image.width,
            image.height,
            0,
            0,
            image.width,
            image.height,
            false,
        )
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val text = reader.decodeWithState(bitmap).text
        if (!text.isNullOrBlank()) {
            onDecoded(text)
        }
    } catch (_: NotFoundException) {
        // Expected on frames that do not contain a complete QR code.
    } catch (_: ReaderException) {
        // Ignore transient malformed frames.
    } finally {
        reader.reset()
        image.close()
    }
}

private fun extractLuminanceBytes(
    buffer: java.nio.ByteBuffer,
    rowStride: Int,
    width: Int,
    height: Int,
): ByteArray {
    buffer.rewind()
    val out = ByteArray(width * height)
    if (rowStride == width && buffer.remaining() >= out.size) {
        buffer.get(out, 0, out.size)
        return out
    }
    val rowBuf = ByteArray(rowStride)
    for (row in 0 until height) {
        val toRead = minOf(rowStride, buffer.remaining())
        if (toRead <= 0) {
            break
        }
        buffer.get(rowBuf, 0, toRead)
        val copyLen = minOf(width, toRead)
        rowBuf.copyInto(out, destinationOffset = row * width, endIndex = copyLen)
    }
    return out
}
