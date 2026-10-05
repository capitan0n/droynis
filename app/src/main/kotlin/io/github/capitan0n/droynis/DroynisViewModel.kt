package io.github.capitan0n.droynis

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.capitan0n.droynis.checks.base.DeviceSummary
import io.github.capitan0n.droynis.checks.base.NetworkSnapshot
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.platform.PermissionOverview
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.report.MarkdownReport
import io.github.capitan0n.droynis.ui.theme.ThemeMode
import java.io.IOException
import java.time.LocalDate
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A finished scan. */
data class ScanResult(
    val context: ScanContext,
    /** In catalog order. */
    val findings: List<Finding>,
    val index: HardeningIndex,
)

data class UiState(
    val scanning: Boolean = false,
    val total: Int = 0,
    /** Results by check id: the scan in progress, or the last one once [scanning] is false. */
    val findings: Map<String, Finding> = emptyMap(),
    /** The last finished scan; null until the first one finishes. */
    val result: ScanResult? = null,
    val device: DeviceSummary? = null,
    /** Null until first read. */
    val network: Reading<NetworkSnapshot?>? = null,
    val permissions: Reading<PermissionOverview>? = null,
    val refreshingTools: Boolean = false,
) {
    val done: Int get() = findings.size
}

class DroynisViewModel(application: Application) : AndroidViewModel(application) {

    private val platform = AndroidPlatform(application)
    private val prefs = application.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // Each tier module contributes its registry here (adbChecks, shizukuChecks, ...).
    private val checks = baseChecks(platform)
    private val scanner = Scanner()

    /** Every check in display order, whether or not it has run. */
    val catalog: List<CheckSpec> = checks.map { it.spec }

    private val _state = MutableStateFlow(UiState(total = checks.size))
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _themeMode = MutableStateFlow(readThemeMode())
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)

    /** One-off messages for the snackbar. */
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var scanJob: Job? = null

    init {
        scan()
        refreshTools()
    }

    fun scan() {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val started = TimeSource.Monotonic.markNow()
            val context = platform.newScanContext()
            _state.update { it.copy(scanning = true, findings = emptyMap()) }
            scanner.scan(checks, context).collect { finding ->
                _state.update { it.copy(findings = it.findings + (finding.spec.id to finding)) }
            }
            // Cosmetic only: a scan takes a fraction of a second, too short to see that it ran.
            delay(MIN_VISIBLE_SCAN - started.elapsedNow())
            val findings = catalog.mapNotNull { _state.value.findings[it.id] }
            _state.update {
                it.copy(scanning = false, result = ScanResult(context, findings, HardeningIndex.of(findings)))
            }
        }
    }

    /** Re-reads the device, network and permission facts shown on the Tools screen. */
    fun refreshTools() {
        if (_state.value.refreshingTools) return
        _state.update { it.copy(refreshingTools = true) }
        viewModelScope.launch {
            val device = withContext(Dispatchers.IO) { platform.build.device() }
            val network = withContext(Dispatchers.IO) { platform.network.activeNetwork() }
            val permissions = withContext(Dispatchers.IO) { platform.permissionAudit.overview() }
            _state.update {
                it.copy(device = device, network = network, permissions = permissions, refreshingTools = false)
            }
        }
    }

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME, mode.name).apply()
        _themeMode.value = mode
    }

    /** Markdown for the last finished scan, or null before the first one finishes. */
    fun reportMarkdown(): String? {
        val result = _state.value.result ?: return null
        val device = _state.value.device ?: platform.build.device()
        return MarkdownReport.render(
            context = result.context,
            findings = result.findings,
            index = result.index,
            facts = reportFacts(device),
            appVersion = BuildConfig.VERSION_NAME,
        )
    }

    fun reportFileName(): String {
        val date = _state.value.result?.context?.startedAt?.toLocalDate() ?: LocalDate.now()
        return "droynis-report-$date.md"
    }

    /** Writes the report to a document the user picked. */
    fun writeReport(uri: Uri) {
        val text = reportMarkdown() ?: return
        val resolver = getApplication<Application>().contentResolver
        viewModelScope.launch {
            val saved = withContext(Dispatchers.IO) {
                try {
                    resolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray()) } != null
                } catch (e: IOException) {
                    false
                } catch (e: SecurityException) {
                    false
                }
            }
            message(if (saved) R.string.report_saved else R.string.report_save_failed)
        }
    }

    fun message(resId: Int) {
        _messages.tryEmit(getApplication<Application>().getString(resId))
    }

    private fun readThemeMode(): ThemeMode {
        val name = prefs.getString(KEY_THEME, null)
        return ThemeMode.entries.firstOrNull { it.name == name } ?: ThemeMode.SYSTEM
    }

    companion object {
        private const val PREFS = "settings"
        private const val KEY_THEME = "theme"
        private val MIN_VISIBLE_SCAN = 700.milliseconds

        /** Device facts for reports: deliberately no serial number, IMEI, phone number or account. */
        fun reportFacts(device: DeviceSummary): List<Pair<String, String>> = listOfNotNull(
            "Manufacturer" to device.manufacturer,
            "Model" to device.model,
            "Android" to "${device.androidVersion} (API ${device.sdkInt})",
            "Security patch" to device.securityPatch,
            "Build" to device.buildId,
            device.kernel?.let { "Kernel" to it },
        )
    }
}
