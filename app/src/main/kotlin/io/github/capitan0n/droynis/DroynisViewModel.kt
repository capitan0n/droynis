package io.github.capitan0n.droynis

import android.app.Application
import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.capitan0n.droynis.checks.base.DeviceSummary
import io.github.capitan0n.droynis.checks.base.NetworkSnapshot
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.core.Trust
import io.github.capitan0n.droynis.platform.PermissionOverview
import io.github.capitan0n.droynis.platform.root.RootState
import io.github.capitan0n.droynis.platform.root.RootStatus
import io.github.capitan0n.droynis.platform.shizuku.ShizukuState
import io.github.capitan0n.droynis.platform.shizuku.ShizukuStatus
import io.github.capitan0n.droynis.report.DeviceFact
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.report.JsonReport
import io.github.capitan0n.droynis.report.MarkdownReport
import io.github.capitan0n.droynis.schedule.ScanHistory
import io.github.capitan0n.droynis.schedule.ScanInterval
import io.github.capitan0n.droynis.schedule.ScanNotifier
import io.github.capitan0n.droynis.schedule.ScanSnapshot
import io.github.capitan0n.droynis.schedule.ScheduleSettings
import io.github.capitan0n.droynis.schedule.ScheduledScans
import io.github.capitan0n.droynis.ui.theme.ThemeAccent
import io.github.capitan0n.droynis.ui.theme.ThemeMode
import java.io.IOException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.coroutines.cancellation.CancellationException
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    /** Packages of apps the user trusts: every check still lists them, but none counts them. */
    val trusted: Set<String> = emptySet(),
    /** Labels of the [trusted] apps by package; the package name when the app is gone. */
    val trustedLabels: Map<String, String> = emptyMap(),
    /** Null until first read. */
    val shizuku: ShizukuStatus? = null,
    /** Null until first read. */
    val root: RootStatus? = null,
    /** Reports leave out IP addresses, DNS and proxy servers and trusted computers; on by default. */
    val hidePersonal: Boolean = true,
    /** How often Droynis scans in the background; off by default. */
    val schedule: ScanInterval = ScanInterval.OFF,
    /** Every scheduled scan notifies; off by default, and the only thing that asks for the permission. */
    val notify: Boolean = false,
    /** The notification lists the changes; otherwise only the score and the previous one. */
    val verbose: Boolean = true,
    /** Whether Android lets Droynis post notifications. */
    val notificationsAllowed: Boolean = true,
    /** When the last scheduled scan finished, in epoch milliseconds; null before the first. */
    val lastScheduledScan: Long? = null,
    /** What the last scheduled scan found, e.g. "Score 78/100, 1 new problem"; null without a score. */
    val lastScheduledResult: String? = null,
    /** A scheduled scan started from the app ("Run one now") is running. */
    val runningScheduledScan: Boolean = false,
    /** Android restricts Droynis in the background, so scheduled scans wait until the app opens. */
    val backgroundRestricted: Boolean = false,
    /** The last scheduled scan ran late, or the next one is overdue. */
    val scheduleLate: Boolean = false,
    /** This version's changelog, shown once after an update; null when there is nothing to show. */
    val whatsNew: String? = null,
) {
    val done: Int get() = findings.size
}

class DroynisViewModel(application: Application) : AndroidViewModel(application) {

    // Shared with scheduled scans in this process, so the two never run separate shells.
    private val platform = SharedPlatform.acquire(application)
    private val prefs = application.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val schedule = ScheduleSettings(application)

    // Each tier module contributes its registry here; checks above the detected tier show as N/A.
    private val checks = allChecks(platform)
    private val scanner = Scanner()

    /** Every check in display order, whether or not it has run. */
    val catalog: List<CheckSpec> = checks.map { it.spec }

    private val _state = MutableStateFlow(
        UiState(
            total = checks.size,
            muted = readMuted(),
            trusted = readTrusted(),
            hidePersonal = prefs.getBoolean(KEY_HIDE_PERSONAL, true),
            schedule = schedule.interval,
            notify = schedule.notify,
            verbose = schedule.verbose,
            notificationsAllowed = ScanNotifier.canNotify(application),
            lastScheduledScan = schedule.lastRun,
            lastScheduledResult = scheduledResult(schedule.lastScore, schedule.lastNewIssues),
            backgroundRestricted = ScheduledScans.backgroundRestricted(application),
            scheduleLate = schedule.late(System.currentTimeMillis()),
            whatsNew = WhatsNew.pending(application, prefs),
            // Build constants only, so the dashboard's device card is filled from the start.
            device = platform.build.device(),
        ),
    )
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _themeMode = MutableStateFlow(readThemeMode())
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _accent = MutableStateFlow(readAccent())
    val accent: StateFlow<ThemeAccent> = _accent.asStateFlow()

    // Read from the package manager, not saved: the enabled launcher entry is the setting itself.
    private val _appIcon = MutableStateFlow(AppIcon.current(application))
    val appIcon: StateFlow<AppIcon> = _appIcon.asStateFlow()

    /** One icon switch at a time. */
    private val appIconLock = Mutex()

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
        refreshTrustedLabels()
        // Brings the schedule back after a force stop, which cancels it; a matching job is left alone.
        val interval = schedule.interval
        if (interval != ScanInterval.OFF) {
            viewModelScope.launch(Dispatchers.IO) { ScheduledScans.apply(application, interval) }
        }
        // The Device screen's permission overview loads the label of every app, which needs the same
        // package manager and resource locks as the scan's checks: started together, it slows the
        // first scan. Read it once the first scan is done; the Device screen also refreshes itself
        // whenever it opens.
        val firstScan = scanJob
        viewModelScope.launch {
            firstScan?.join()
            refreshTools()
        }
    }

    override fun onCleared() {
        platform.shizuku.removeListener(onShizukuChanged)
        SharedPlatform.release(platform)
    }

    fun scan() {
        val previous = scanJob
        previous?.cancel()
        // Off the main thread from start to end: when the app opens, the main thread is busy drawing
        // the first frame, and every step of the scan would otherwise wait for it. The state is a
        // StateFlow, safe to update from any thread.
        scanJob = viewModelScope.launch(Dispatchers.IO) {
            // Let a cancelled scan close its root shell first, so it can't close this scan's.
            previous?.join()
            val started = TimeSource.Monotonic.markNow()
            // Starting the Shizuku shell can take a few seconds, so show the scan as running first.
            _state.update { it.copy(scanning = true, findings = emptyMap()) }
            // A scheduled scan may be running on the same platform: wait for it to finish.
            val context = SharedPlatform.scanLock.withLock {
                val scanContext = platform.newScanContext().copy(trustedApps = _state.value.trusted)
                // Read after newScanContext, which connects Shizuku and opens root, and shown in one update.
                val shizuku = platform.shizuku.status()
                val root = platform.root.status()
                _state.update { it.copy(grants = scanContext.capabilities.grants, shizuku = shizuku, root = root) }
                try {
                    scanner.scan(checks, scanContext).collect { finding ->
                        _state.update { it.copy(findings = it.findings + (finding.spec.id to finding)) }
                    }
                } finally {
                    // The root shell lives only as long as a scan, even a cancelled one.
                    withContext(NonCancellable) { platform.scanFinished() }
                }
                scanContext
            }
            // Cosmetic only: a scan takes a fraction of a second, too short to see that it ran.
            delay(MIN_VISIBLE_SCAN - started.elapsedNow())
            val findings = catalog.mapNotNull { _state.value.findings[it.id] }
            _state.update {
                val index = HardeningIndex.of(findings, it.muted)
                it.copy(scanning = false, result = ScanResult(context, findings, index))
            }
            // What the next scheduled scan compares against: the results the user has seen.
            _state.value.result?.let { recordBaseline(it) }
        }
    }

    /** Re-reads the device, network, permission and grant facts shown on the Device screen. */
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
            refreshSchedule()
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

    /**
     * Turns the root tier off: Droynis runs su no more. Scans again, so the root checks show as N/A
     * instead of keeping the results root read, on screen and in reports.
     */
    fun disableRoot() {
        prefs.edit().putBoolean(KEY_ROOT, false).apply()
        viewModelScope.launch {
            withContext(Dispatchers.IO) { platform.root.disable() }
            refreshRoot()
            message(R.string.root_turned_off)
            scan()
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

    /**
     * Trusts [packageName] in every check, or stops trusting it. The checks that list the app run
     * again at once, so their results and the score follow; the rest of the scan stays as it is.
     */
    fun setTrusted(packageName: String, trusted: Boolean) {
        val current = _state.value.trusted
        if ((packageName in current) == trusted) return
        saveTrusted(if (trusted) current + packageName else current - packageName)
        message(if (trusted) R.string.app_trusted else R.string.app_untrusted)
        recheck(checksListing(setOf(packageName)))
    }

    /** Stops trusting every app, and runs the checks that listed one again. */
    fun untrustAll() {
        val trusted = _state.value.trusted
        if (trusted.isEmpty()) return
        saveTrusted(emptySet())
        message(R.string.all_untrusted)
        recheck(checksListing(trusted))
    }

    /** Ids of the checks whose last result lists one of [packages] as an app it counts or trusts. */
    private fun checksListing(packages: Set<String>): Set<String> =
        _state.value.findings.values
            .filter { finding -> finding.evidence.any { it.trust in TRUSTABLE && it.packageName in packages } }
            .mapTo(HashSet()) { it.spec.id }

    private fun saveTrusted(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_TRUSTED, packages).apply()
        _state.update { it.copy(trusted = packages) }
        refreshTrustedLabels()
    }

    /** Loads the label of every trusted app, off the main thread: each one opens that app's resources. */
    private fun refreshTrustedLabels() {
        val packages = _state.value.trusted.toList()
        viewModelScope.launch(Dispatchers.IO) {
            val labels = packages.associateWith { platform.packages.label(it) }
            _state.update { it.copy(trustedLabels = labels) }
        }
    }

    /**
     * Runs only the checks in [checkIds] again, with the trusted apps as they are now, and puts their
     * results into the last scan. While a full scan runs, or before the first one, it scans instead.
     */
    private fun recheck(checkIds: Set<String>) {
        // A running scan started with the old trust, and may not have reached these checks yet.
        if (_state.value.scanning || _state.value.result == null) {
            scan()
            return
        }
        val subset = checks.filter { it.spec.id in checkIds }
        if (subset.isEmpty()) {
            // No check lists these apps, so no result changes; reports still name the trusted apps.
            _state.update { state ->
                state.copy(result = state.result?.let { it.copy(context = it.context.copy(trustedApps = state.trusted)) })
            }
            return
        }
        val previous = scanJob
        scanJob = viewModelScope.launch(Dispatchers.IO) {
            // Let an earlier recheck close its root shell first, so it can't close this one's.
            previous?.join()
            val fresh = HashMap<String, Finding>()
            // Like a full scan, it waits for a scheduled scan on the same platform to finish.
            val context = SharedPlatform.scanLock.withLock {
                val scanContext = platform.newScanContext().copy(trustedApps = _state.value.trusted)
                try {
                    scanner.scan(subset, scanContext).collect { fresh[it.spec.id] = it }
                } finally {
                    withContext(NonCancellable) { platform.scanFinished() }
                }
                scanContext
            }
            _state.update { state ->
                val findings = state.findings + fresh
                val result = state.result?.let { last ->
                    val ordered = catalog.mapNotNull { findings[it.id] }
                    last.copy(
                        // Reports list the trusted apps from the scan's context.
                        context = last.context.copy(trustedApps = context.trustedApps),
                        findings = ordered,
                        index = HardeningIndex.of(ordered, state.muted),
                    )
                }
                state.copy(findings = findings, result = result)
            }
            // Trusting an app is the user's choice, not a change for the next scheduled scan to report.
            _state.value.result?.let { recordBaseline(it) }
        }
    }

    /** Whether saved, shared and copied reports leave out personal details. */
    fun setHidePersonal(hide: Boolean) {
        prefs.edit().putBoolean(KEY_HIDE_PERSONAL, hide).apply()
        _state.update { it.copy(hidePersonal = hide) }
        message(if (hide) R.string.personal_hidden else R.string.personal_included)
    }

    /** The "What's new" dialog was closed: not shown again for this version. */
    fun dismissWhatsNew() {
        WhatsNew.markSeen(prefs)
        _state.update { it.copy(whatsNew = null) }
    }

    /** Turns the scheduled scan on, changes how often it runs, or turns it off. */
    fun setSchedule(interval: ScanInterval) {
        schedule.interval = interval
        _state.update { it.copy(schedule = interval) }
        val app = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            if (!ScheduledScans.apply(app, interval)) message(R.string.schedule_failed)
            if (interval == ScanInterval.OFF) {
                // Nothing of the scans is kept while no schedule needs it.
                ScanHistory.clear(app)
            } else {
                // The first scheduled scan compares against the results on screen now.
                _state.value.result?.let { recordBaseline(it) }
            }
            // A new job, or none, starts its timing afresh.
            refreshSchedule()
        }
    }

    /** Turns scheduled scan notifications on or off; the activity asks for the permission first. */
    fun setNotify(on: Boolean) {
        schedule.notify = on
        _state.update { it.copy(notify = on) }
    }

    /** A detailed notification, or only the score and the previous one. */
    fun setVerbose(verbose: Boolean) {
        schedule.verbose = verbose
        _state.update { it.copy(verbose = verbose) }
    }

    /**
     * Runs a scheduled scan now, to see what one does: with notifications on it notifies, with them
     * off its result shows in the snackbar.
     */
    fun runScheduledScan() {
        if (_state.value.runningScheduledScan) return
        _state.update { it.copy(runningScheduledScan = true) }
        val app = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val summary = ScheduledScans.runScan(app)
                when {
                    !schedule.notify -> scheduledResult(summary.score, summary.newIssues)?.let { _messages.tryEmit(it) }
                    !ScanNotifier.canNotify(app) -> message(R.string.schedule_notifications_off)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                message(R.string.schedule_run_failed)
            } finally {
                _state.update { it.copy(runningScheduledScan = false) }
                refreshSchedule()
            }
        }
    }

    /**
     * Re-reads whether Droynis may notify and run in the background, when the last scheduled scan ran,
     * what it found, and whether scans run late.
     */
    fun refreshSchedule() {
        val app = getApplication<Application>()
        val result = scheduledResult(schedule.lastScore, schedule.lastNewIssues)
        val late = schedule.late(System.currentTimeMillis())
        _state.update {
            it.copy(
                notificationsAllowed = ScanNotifier.canNotify(app),
                lastScheduledScan = schedule.lastRun,
                lastScheduledResult = result,
                backgroundRestricted = ScheduledScans.backgroundRestricted(app),
                scheduleLate = late,
            )
        }
    }

    /** "Score 78/100, 1 new problem" or "Score 78/100, nothing got worse"; null without a score. */
    private fun scheduledResult(score: Int?, newIssues: Int): String? {
        if (score == null) return null
        val res = getApplication<Application>().resources
        return if (newIssues == 0) {
            res.getString(R.string.schedule_result_unchanged, score)
        } else {
            res.getQuantityString(R.plurals.schedule_result_new_issues, newIssues, score, newIssues)
        }
    }

    private fun recordBaseline(result: ScanResult) {
        if (schedule.interval == ScanInterval.OFF) return
        val snapshot = ScanSnapshot.of(result.findings, result.index.score, System.currentTimeMillis())
        ScanHistory.record(getApplication(), snapshot)
    }

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME, mode.name).apply()
        _themeMode.value = mode
    }

    fun setAccent(accent: ThemeAccent) {
        prefs.edit().putString(KEY_ACCENT, accent.name).apply()
        _accent.value = accent
    }

    /** Switches the launcher icon; the launcher may take a few seconds to show it. */
    fun setAppIcon(icon: AppIcon) {
        if (icon == _appIcon.value) return
        _appIcon.value = icon
        val app = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            appIconLock.withLock {
                // Quick taps may get here out of order, so each switch applies the latest pick.
                if (!AppIcon.apply(app, _appIcon.value)) {
                    _appIcon.value = AppIcon.current(app)
                    message(R.string.app_icon_failed)
                }
            }
        }
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

    /**
     * Ids of checks that no longer exist are dropped, so a removed check can't stay muted. A check
     * that moved to another category stays muted under its new id ([CheckSpec.RENAMED]), which is
     * saved so the old id doesn't linger.
     */
    private fun readMuted(): Set<String> {
        val known = catalog.mapTo(HashSet()) { it.id }
        val stored = prefs.getStringSet(KEY_MUTED, null).orEmpty()
        val muted = stored.map { CheckSpec.currentId(it) }.filterTo(HashSet()) { it in known }
        if (stored.any { it in CheckSpec.RENAMED }) prefs.edit().putStringSet(KEY_MUTED, muted).apply()
        return muted
    }

    /** A copy: Android's returned set must not be changed. */
    private fun readTrusted(): Set<String> = prefs.getStringSet(KEY_TRUSTED, null).orEmpty().toSet()

    private fun readThemeMode(): ThemeMode {
        val name = prefs.getString(KEY_THEME, null)
        return ThemeMode.entries.firstOrNull { it.name == name } ?: ThemeMode.SYSTEM
    }

    private fun readAccent(): ThemeAccent {
        val name = prefs.getString(KEY_ACCENT, null)
        return ThemeAccent.entries.firstOrNull { it.name == name && it.available } ?: ThemeAccent.TEAL
    }

    companion object {
        // Scheduled scans read the same file.
        internal const val PREFS = "settings"
        private const val KEY_THEME = "theme"
        private const val KEY_ACCENT = "accent"
        internal const val KEY_MUTED = "muted_checks"
        internal const val KEY_TRUSTED = "trusted_apps"

        /** Evidence whose result changes with trust; a NOT_COUNTED app never counts anyway. */
        private val TRUSTABLE = setOf(Trust.COUNTED, Trust.TRUSTED)
        private const val KEY_HIDE_PERSONAL = "hide_personal"
        internal const val KEY_ROOT = "root_tier"
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
