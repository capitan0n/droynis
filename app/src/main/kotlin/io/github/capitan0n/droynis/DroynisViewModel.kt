package io.github.capitan0n.droynis

import android.app.Application
import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.capitan0n.droynis.checks.adb.adbChecks
import io.github.capitan0n.droynis.checks.base.DeviceSummary
import io.github.capitan0n.droynis.checks.base.NetworkSnapshot
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.checks.root.rootChecks
import io.github.capitan0n.droynis.checks.shizuku.shizukuChecks
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.platform.PermissionOverview
import io.github.capitan0n.droynis.platform.root.RootState
import io.github.capitan0n.droynis.platform.root.RootStatus
import io.github.capitan0n.droynis.platform.shizuku.ShizukuState
import io.github.capitan0n.droynis.platform.shizuku.ShizukuStatus
import io.github.capitan0n.droynis.report.DeviceFact
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.report.JsonReport
import io.github.capitan0n.droynis.report.MarkdownReport
import io.github.capitan0n.droynis.ui.theme.ThemeMode
import java.io.IOException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
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

enum class ReportFormat(val extension: String, val mimeType: String) {
    MARKDOWN("md", "text/markdown"),
    JSON("json", "application/json"),
}

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
    /** Grants held right now; a scan uses what was held when it started. */
    val grants: Set<Grant> = emptySet(),
    /** Ids of checks the user muted: they still run, but the score and counts leave them out. */
    val muted: Set<String> = emptySet(),
    /** Null until first read. */
    val shizuku: ShizukuStatus? = null,
    /** Null until first read. */
    val root: RootStatus? = null,
    /** Reports leave out IP addresses, DNS and proxy servers and trusted computers; on by default. */
    val hidePersonal: Boolean = true,
) {
    val done: Int get() = findings.size
}

class DroynisViewModel(application: Application) : AndroidViewModel(application) {

    private val platform = AndroidPlatform(application)
    private val prefs = application.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // Each tier module contributes its registry here; checks above the detected tier show as N/A.
    private val checks = baseChecks(platform) + adbChecks(platform) + shizukuChecks(platform) + rootChecks(platform)
    private val scanner = Scanner()

    /** Every check in display order, whether or not it has run. */
    val catalog: List<CheckSpec> = checks.map { it.spec }

    private val _state = MutableStateFlow(
        UiState(total = checks.size, muted = readMuted(), hidePersonal = prefs.getBoolean(KEY_HIDE_PERSONAL, true)),
    )
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _themeMode = MutableStateFlow(readThemeMode())
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)

    /** One-off messages for the snackbar. */
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var scanJob: Job? = null

    /** Whether Droynis already scanned again for the Shizuku that runs now. */
    private var rescannedForShizuku = false

    /** Shizuku started or stopped, answered the permission request, or connected the shell. */
    private val onShizukuChanged: () -> Unit = {
        viewModelScope.launch {
            val status = refreshShizuku()
            when (status.state) {
                // Shizuku just became usable (started, or Droynis was allowed): scan so its checks run.
                ShizukuState.ALLOWED -> if (!rescannedForShizuku) {
                    rescannedForShizuku = true
                    scan()
                }
                ShizukuState.NOT_RUNNING, ShizukuState.NOT_INSTALLED -> rescannedForShizuku = false
                else -> Unit
            }
        }
    }

    init {
        platform.root.enabled = prefs.getBoolean(KEY_ROOT, false)
        platform.shizuku.addListener(onShizukuChanged)
        scan()
        refreshTools()
    }

    override fun onCleared() {
        platform.shizuku.removeListener(onShizukuChanged)
        platform.close()
    }

    fun scan() {
        val previous = scanJob
        previous?.cancel()
        scanJob = viewModelScope.launch {
            // Let a cancelled scan close its root shell first, so it can't close this scan's.
            previous?.join()
            val started = TimeSource.Monotonic.markNow()
            // Starting the Shizuku shell can take a few seconds, so show the scan as running first.
            _state.update { it.copy(scanning = true, findings = emptyMap()) }
            val context = withContext(Dispatchers.IO) { platform.newScanContext() }
            _state.update { it.copy(grants = context.capabilities.grants) }
            refreshShizuku()
            refreshRoot()
            try {
                scanner.scan(checks, context).collect { finding ->
                    _state.update { it.copy(findings = it.findings + (finding.spec.id to finding)) }
                }
            } finally {
                // The root shell lives only as long as a scan, even a cancelled one.
                withContext(NonCancellable + Dispatchers.IO) { platform.scanFinished() }
            }
            // Cosmetic only: a scan takes a fraction of a second, too short to see that it ran.
            delay(MIN_VISIBLE_SCAN - started.elapsedNow())
            val findings = catalog.mapNotNull { _state.value.findings[it.id] }
            _state.update {
                val index = HardeningIndex.of(findings, it.muted)
                it.copy(scanning = false, result = ScanResult(context, findings, index))
            }
        }
    }

    /** Re-reads the device, network, permission and grant facts shown on the Tools screen. */
    fun refreshTools() {
        if (_state.value.refreshingTools) return
        _state.update { it.copy(refreshingTools = true) }
        viewModelScope.launch {
            val device = withContext(Dispatchers.IO) { platform.build.device() }
            val network = withContext(Dispatchers.IO) { platform.network.activeNetwork() }
            val permissions = withContext(Dispatchers.IO) { platform.permissionAudit.overview() }
            val grants = withContext(Dispatchers.IO) { platform.detectGrants() }
            refreshShizuku()
            refreshRoot()
            _state.update {
                it.copy(
                    device = device,
                    network = network,
                    permissions = permissions,
                    grants = grants,
                    refreshingTools = false,
                )
            }
        }
    }

    /** Shows Shizuku's dialog asking to allow Droynis; once allowed, Droynis scans again. */
    fun requestShizuku() {
        viewModelScope.launch {
            val shown = withContext(Dispatchers.IO) { platform.shizuku.requestPermission() }
            if (!shown) message(R.string.shizuku_not_reachable)
        }
    }

    /** Turns the root tier on and scans, so the root manager asks the user. */
    fun enableRoot() {
        prefs.edit().putBoolean(KEY_ROOT, true).apply()
        platform.root.enabled = true
        viewModelScope.launch {
            scan()
            scanJob?.join()
            if (refreshRoot().state != RootState.GRANTED) message(R.string.root_not_granted)
        }
    }

    /** Turns the root tier off: Droynis runs su no more. */
    fun disableRoot() {
        prefs.edit().putBoolean(KEY_ROOT, false).apply()
        viewModelScope.launch {
            withContext(Dispatchers.IO) { platform.root.disable() }
            refreshRoot()
            message(R.string.root_turned_off)
        }
    }

    private suspend fun refreshRoot(): RootStatus {
        val (status, grants) = withContext(Dispatchers.IO) { platform.root.status() to platform.detectGrants() }
        _state.update { if (it.scanning) it.copy(root = status) else it.copy(root = status, grants = grants) }
        return status
    }

    /** Re-reads Shizuku's state and the grants it brings. */
    private suspend fun refreshShizuku(): ShizukuStatus {
        val (status, grants) = withContext(Dispatchers.IO) { platform.shizuku.status() to platform.detectGrants() }
        // A running scan keeps the grants it started with.
        _state.update { if (it.scanning) it.copy(shizuku = status) else it.copy(shizuku = status, grants = grants) }
        return status
    }

    /** Mutes or unmutes one check. The score updates at once; no new scan is needed. */
    fun setMuted(checkId: String, muted: Boolean) {
        saveMuted(if (muted) _state.value.muted + checkId else _state.value.muted - checkId)
        message(if (muted) R.string.check_muted else R.string.check_unmuted)
    }

    /** Unmutes every check at once. */
    fun unmuteAll() {
        if (_state.value.muted.isEmpty()) return
        saveMuted(emptySet())
        message(R.string.all_unmuted)
    }

    private fun saveMuted(ids: Set<String>) {
        prefs.edit().putStringSet(KEY_MUTED, ids).apply()
        _state.update { state ->
            state.copy(
                muted = ids,
                result = state.result?.let { it.copy(index = HardeningIndex.of(it.findings, ids)) },
            )
        }
    }

    /** Whether saved, shared and copied reports leave out personal details. */
    fun setHidePersonal(hide: Boolean) {
        prefs.edit().putBoolean(KEY_HIDE_PERSONAL, hide).apply()
        _state.update { it.copy(hidePersonal = hide) }
        message(if (hide) R.string.personal_hidden else R.string.personal_included)
    }

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME, mode.name).apply()
        _themeMode.value = mode
    }

    /** The last finished scan as a report, or null before the first one finishes. */
    fun report(format: ReportFormat): String? {
        val result = _state.value.result ?: return null
        val facts = reportFacts(_state.value.device ?: platform.build.device())
        val render = when (format) {
            ReportFormat.MARKDOWN -> MarkdownReport::render
            ReportFormat.JSON -> JsonReport::render
        }
        return render(result.context, result.findings, result.index, facts, BuildConfig.VERSION_NAME, _state.value.hidePersonal)
    }

    /** e.g. droynis-report-2026-10-05-1402.json, so several scans a day sort and never collide. */
    fun reportFileName(format: ReportFormat): String {
        val time = _state.value.result?.context?.startedAt ?: ZonedDateTime.now()
        return "droynis-report-${time.format(FILE_TIME)}.${format.extension}"
    }

    /** Writes the report to a document the user picked. */
    fun writeReport(uri: Uri, format: ReportFormat) {
        val text = report(format) ?: return
        val resolver = getApplication<Application>().contentResolver
        viewModelScope.launch {
            val saved = withContext(Dispatchers.IO) {
                val bytes = text.toByteArray()
                // "wt" truncates a file the user picked over; a few document providers only take "w",
                // which is safe for the new, empty file the picker creates.
                write(resolver, uri, "wt", bytes) || write(resolver, uri, "w", bytes)
            }
            message(if (saved) R.string.report_saved else R.string.report_save_failed)
        }
    }

    /** False on any failure: a document provider's own exception must not crash the app. */
    private fun write(resolver: ContentResolver, uri: Uri, mode: String, bytes: ByteArray): Boolean =
        try {
            resolver.openOutputStream(uri, mode)?.use { it.write(bytes) } != null
        } catch (e: IOException) {
            false
        } catch (e: SecurityException) {
            false
        } catch (e: IllegalArgumentException) {
            false // e.g. a provider that rejects the mode
        } catch (e: UnsupportedOperationException) {
            false
        }

    fun message(resId: Int) {
        _messages.tryEmit(getApplication<Application>().getString(resId))
    }

    /** Ids of checks that no longer exist are dropped, so a removed check can't stay muted. */
    private fun readMuted(): Set<String> {
        val known = catalog.mapTo(HashSet()) { it.id }
        return prefs.getStringSet(KEY_MUTED, null).orEmpty().filterTo(HashSet()) { it in known }
    }

    private fun readThemeMode(): ThemeMode {
        val name = prefs.getString(KEY_THEME, null)
        return ThemeMode.entries.firstOrNull { it.name == name } ?: ThemeMode.SYSTEM
    }

    companion object {
        private const val PREFS = "settings"
        private const val KEY_THEME = "theme"
        private const val KEY_MUTED = "muted_checks"
        private const val KEY_HIDE_PERSONAL = "hide_personal"
        private const val KEY_ROOT = "root_tier"
        private val MIN_VISIBLE_SCAN = 700.milliseconds

        private val FILE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmm")

        /** Device facts for reports: deliberately no serial number, IMEI, phone number or account. */
        fun reportFacts(device: DeviceSummary): List<DeviceFact> = listOfNotNull(
            DeviceFact("manufacturer", "Manufacturer", device.manufacturer),
            DeviceFact("model", "Model", device.model),
            DeviceFact("androidVersion", "Android", "${device.androidVersion} (API ${device.sdkInt})"),
            DeviceFact("securityPatch", "Security patch", device.securityPatch),
            DeviceFact("buildId", "Build", device.buildId),
            DeviceFact("buildType", "Build type", "${device.buildType} (${device.buildTags})"),
            device.kernel?.let { DeviceFact("kernel", "Kernel", it) },
        )
    }
}
