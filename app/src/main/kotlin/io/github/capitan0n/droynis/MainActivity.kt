package io.github.capitan0n.droynis

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
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
import io.github.capitan0n.droynis.platform.shizuku.ShizukuShell
import io.github.capitan0n.droynis.ui.AppActions
import io.github.capitan0n.droynis.ui.DroynisApp
import io.github.capitan0n.droynis.ui.theme.DroynisTheme
import io.github.capitan0n.droynis.ui.theme.ThemeMode

class MainActivity : ComponentActivity(), AppActions {

    private val viewModel: DroynisViewModel by viewModels()

    // The Storage Access Framework picks the file, so Droynis needs no storage permission.
    private val createMarkdown = createDocument(ReportFormat.MARKDOWN)
    private val createJson = createDocument(ReportFormat.JSON)

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
            DroynisTheme(darkTheme = darkTheme) {
                val state by viewModel.state.collectAsStateWithLifecycle()
                DroynisApp(
                    state = state,
                    catalog = viewModel.catalog,
                    themeMode = themeMode,
                    appVersion = BuildConfig.VERSION_NAME,
                    messages = viewModel.messages,
                    actions = this,
                )
            }
        }
    }

    override fun scan() = viewModel.scan()

    override fun refreshTools() = viewModel.refreshTools()

    override fun setThemeMode(mode: ThemeMode) = viewModel.setThemeMode(mode)

    override fun setMuted(checkId: String, muted: Boolean) = viewModel.setMuted(checkId, muted)

    override fun unmuteAll() = viewModel.unmuteAll()

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

    /** Droynis never changes a setting itself; it opens the screen where the user can. */
    override fun openSettings(actions: List<String>) {
        for (action in actions + SettingsActions.SETTINGS) {
            try {
                startActivity(Intent(action))
                return
            } catch (e: ActivityNotFoundException) {
                continue
            } catch (e: SecurityException) {
                continue // some vendors do not export every Settings screen
            }
        }
        viewModel.message(R.string.settings_not_opened)
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
