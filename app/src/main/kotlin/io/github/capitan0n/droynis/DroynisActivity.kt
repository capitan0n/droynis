package io.github.capitan0n.droynis

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.SettingsTarget
import io.github.capitan0n.droynis.platform.shizuku.ShizukuShell
import io.github.capitan0n.droynis.schedule.ScanInterval
import io.github.capitan0n.droynis.schedule.ScanNotifier
import io.github.capitan0n.droynis.ui.AppActions
import io.github.capitan0n.droynis.ui.DroynisApp
import io.github.capitan0n.droynis.ui.theme.DroynisTheme
import io.github.capitan0n.droynis.ui.theme.ThemeAccent
import io.github.capitan0n.droynis.ui.theme.ThemeMode

class DroynisActivity : ComponentActivity(), AppActions {

    private val viewModel: DroynisViewModel by viewModels()

    // The Storage Access Framework picks the file, so Droynis needs no storage permission.
    private val createMarkdown = createDocument(ReportFormat.MARKDOWN)
    private val createJson = createDocument(ReportFormat.JSON)

    // Android 13+ asks the user before an app may notify; only the scheduled scan's switch asks.
    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) viewModel.setNotify(true) else viewModel.message(R.string.schedule_notifications_denied)
            viewModel.refreshSchedule()
        }

    private fun createDocument(format: ReportFormat) =
        registerForActivityResult(ActivityResultContracts.CreateDocument(format.mimeType)) { uri ->
            if (uri != null) viewModel.writeReport(uri, format)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Created here rather than in the first composition, so the first scan runs while the first
        // frame is being drawn.
        val viewModel = viewModel
        setContent {
            val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
            val accent by viewModel.accent.collectAsStateWithLifecycle()
            val appIcon by viewModel.appIcon.collectAsStateWithLifecycle()
            val darkTheme = when (themeMode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            // Keep status and navigation bar icons readable when the app theme differs from the system's.
            DisposableEffect(darkTheme) {
                val style = if (darkTheme) {
                    SystemBarStyle.dark(Color.TRANSPARENT)
                } else {
                    SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                }
                enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
                onDispose {}
            }
            DroynisTheme(darkTheme = darkTheme, accent = accent) {
                val state by viewModel.state.collectAsStateWithLifecycle()
                DroynisApp(
                    state = state,
                    catalog = viewModel.catalog,
                    themeMode = themeMode,
                    accent = accent,
                    appIcon = appIcon,
                    appVersion = BuildConfig.VERSION_NAME,
                    messages = viewModel.messages,
                    actions = this,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // The user may have allowed or blocked notifications in Settings meanwhile.
        viewModel.refreshSchedule()
    }

    /** Opened from a scheduled scan's notification: scan again, so the app shows what it says. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(ScanNotifier.EXTRA_RESCAN, false)) viewModel.scan()
    }

    override fun scan() = viewModel.scan()

    override fun refreshTools() = viewModel.refreshTools()

    override fun setThemeMode(mode: ThemeMode) = viewModel.setThemeMode(mode)

    override fun setAccent(accent: ThemeAccent) = viewModel.setAccent(accent)

    override fun setAppIcon(icon: AppIcon) = viewModel.setAppIcon(icon)

    override fun setMuted(checkId: String, muted: Boolean) = viewModel.setMuted(checkId, muted)

    override fun unmuteAll() = viewModel.unmuteAll()

    override fun setTrusted(packageName: String, trusted: Boolean) = viewModel.setTrusted(packageName, trusted)

    override fun untrustAll() = viewModel.untrustAll()

    override fun setHidePersonal(hide: Boolean) = viewModel.setHidePersonal(hide)

    override fun requestShizuku() = viewModel.requestShizuku()

    override fun enableRoot() = viewModel.enableRoot()

    override fun disableRoot() = viewModel.disableRoot()

    override fun openShizuku() {
        val launch = packageManager.getLaunchIntentForPackage(ShizukuShell.MANAGER_PACKAGE)
        if (launch == null) {
            openLink(AppInfo.SHIZUKU_URL)
            return
        }
        try {
            startActivity(launch)
        } catch (e: ActivityNotFoundException) {
            openLink(AppInfo.SHIZUKU_URL)
        }
    }

    /**
     * Droynis never changes a setting itself; it opens the screen where the user can, scrolled to the
     * switch named by [highlightKey] where the Settings app supports that.
     */
    override fun openSettings(actions: List<String>, highlightKey: String?) {
        val route = SettingsActions.route(
            actions = actions,
            sdkInt = Build.VERSION.SDK_INT,
            highlightKey = highlightKey,
            developerOptionsOn = developerOptionsOn(),
            hasFeature = { packageManager.hasSystemFeature(it) },
        )
        for (target in route.targets) {
            val intent = settingsIntent(target) ?: continue
            if (tryStart(intent)) {
                // A toast, not a snackbar: it shows over About phone, where the user needs it.
                if (route.developerOptionsOff && target.target == SettingsActions.DEVICE_INFO) {
                    Toast.makeText(this, R.string.developer_options_off, Toast.LENGTH_LONG).show()
                }
                return
            }
        }
        viewModel.message(R.string.settings_not_opened)
    }

    override fun openAppSettings(actions: List<String>, packageName: String) {
        val app = Uri.fromParts("package", packageName, null)
        for (action in actions + SettingsActions.APP_DETAILS) {
            if (SettingsActions.opensOn(action, Build.VERSION.SDK_INT) && tryStart(Intent(action, app))) return
        }
        viewModel.message(R.string.settings_not_opened)
    }

    /**
     * An action, or an explicit Settings activity, with the switch to highlight. AOSP reads the key from
     * the screen's arguments, and recent releases from the intent too; other Settings apps ignore both.
     */
    private fun settingsIntent(target: SettingsTarget): Intent? {
        val intent = if (target.isComponent) {
            val component = ComponentName.unflattenFromString(target.target) ?: return null
            Intent(Intent.ACTION_MAIN).setComponent(component)
        } else {
            Intent(target.target)
        }
        target.highlightKey?.let { key ->
            intent.putExtra(SettingsActions.EXTRA_FRAGMENT_ARG_KEY, key)
            intent.putExtra(
                SettingsActions.EXTRA_SHOW_FRAGMENT_ARGUMENTS,
                Bundle().apply { putString(SettingsActions.EXTRA_FRAGMENT_ARG_KEY, key) },
            )
        }
        return intent
    }

    /**
     * Read when the user taps, as Settings reads it: unset means off, except on engineering builds.
     * Null where the setting can't be read, so Developer options open as usual.
     */
    private fun developerOptionsOn(): Boolean? =
        try {
            val default = if (Build.TYPE == "eng") 1 else 0
            Settings.Global.getInt(contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, default) != 0
        } catch (e: SecurityException) {
            null
        }

    private fun tryStart(intent: Intent): Boolean =
        try {
            startActivity(intent)
            true
        } catch (e: ActivityNotFoundException) {
            false
        } catch (e: SecurityException) {
            false // some vendors do not export every Settings screen
        }

    override fun saveReport(format: ReportFormat) {
        if (viewModel.report(format) == null) {
            viewModel.message(R.string.report_not_ready)
            return
        }
        val launcher = when (format) {
            ReportFormat.MARKDOWN -> createMarkdown
            ReportFormat.JSON -> createJson
        }
        try {
            launcher.launch(viewModel.reportFileName(format))
        } catch (e: ActivityNotFoundException) {
            viewModel.message(R.string.report_save_failed)
        }
    }

    override fun shareReport() {
        val report = viewModel.report(ReportFormat.MARKDOWN)
        if (report == null) {
            viewModel.message(R.string.report_not_ready)
            return
        }
        val send = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.report_subject))
            .putExtra(Intent.EXTRA_TEXT, report)
        startActivity(Intent.createChooser(send, getString(R.string.menu_share_report)))
    }

    override fun copyReport() {
        val report = viewModel.report(ReportFormat.MARKDOWN)
        if (report == null) {
            viewModel.message(R.string.report_not_ready)
            return
        }
        copyText(getString(R.string.report_subject), report, R.string.report_copied, sensitive = true)
    }

    override fun copy(label: String, text: String) = copyText(label, text, R.string.copied)

    /** Opens a web page in the user's browser; Droynis itself never goes online. */
    override fun openLink(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: ActivityNotFoundException) {
            copyText(url, url, R.string.no_app_for_link, explain = true)
        }
    }

    override fun setSchedule(interval: ScanInterval) = viewModel.setSchedule(interval)

    /** Turning notifications on asks for the permission first, on Android 13+ when not yet granted. */
    override fun setNotify(on: Boolean) {
        if (on &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            viewModel.setNotify(on)
        }
    }

    override fun setVerbose(verbose: Boolean) = viewModel.setVerbose(verbose)

    override fun runScheduledScan() = viewModel.runScheduledScan()

    override fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
        if (!tryStart(intent)) openAppSettings(emptyList(), packageName)
    }

    /**
     * App info: Android has no public action for one app's battery page, and asking to skip battery
     * optimization directly would need REQUEST_IGNORE_BATTERY_OPTIMIZATIONS.
     */
    override fun openBatterySettings() = openAppSettings(emptyList(), packageName)

    override fun dismissWhatsNew() = viewModel.dismissWhatsNew()

    override fun sendFeedback() {
        val subject = getString(R.string.feedback_subject, BuildConfig.VERSION_NAME)
        val mailto = Uri.parse("mailto:${AppInfo.FEEDBACK_EMAIL}?subject=${Uri.encode(subject)}")
        try {
            startActivity(Intent(Intent.ACTION_SENDTO, mailto))
        } catch (e: ActivityNotFoundException) {
            copyText(AppInfo.FEEDBACK_EMAIL, AppInfo.FEEDBACK_EMAIL, R.string.no_email_app, explain = true)
        }
    }

    /**
     * [explain] shows [message] even where Android 13+ confirms the copy itself. A [sensitive] copy
     * stays out of the clipboard preview and keyboard suggestions.
     */
    private fun copyText(label: String, text: String, message: Int, explain: Boolean = false, sensitive: Boolean = false) {
        val clipboard = getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(label, text)
        if (sensitive) clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        clipboard.setPrimaryClip(clip)
        if (explain || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) viewModel.message(message)
    }

    private companion object {
        /** `ClipDescription.EXTRA_IS_SENSITIVE` (API 33); the literal also works on older releases. */
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
    }
}
