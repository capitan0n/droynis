package io.github.capitan0n.droynis

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
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
import io.github.capitan0n.droynis.ui.AppActions
import io.github.capitan0n.droynis.ui.DroynisApp
import io.github.capitan0n.droynis.ui.theme.DroynisTheme
import io.github.capitan0n.droynis.ui.theme.ThemeMode

class MainActivity : ComponentActivity(), AppActions {

    private val viewModel: DroynisViewModel by viewModels()

    // The Storage Access Framework picks the file, so Droynis needs no storage permission.
    private val createReport = registerForActivityResult(ActivityResultContracts.CreateDocument(MARKDOWN)) { uri ->
        if (uri != null) viewModel.writeReport(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
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

    override fun saveReport() {
        if (viewModel.reportMarkdown() == null) {
            viewModel.message(R.string.report_not_ready)
            return
        }
        try {
            createReport.launch(viewModel.reportFileName())
        } catch (e: ActivityNotFoundException) {
            viewModel.message(R.string.report_save_failed)
        }
    }

    override fun shareReport() {
        val report = viewModel.reportMarkdown()
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
        val report = viewModel.reportMarkdown()
        if (report == null) {
            viewModel.message(R.string.report_not_ready)
            return
        }
        copyText(getString(R.string.report_subject), report, R.string.report_copied)
    }

    override fun copy(label: String, text: String) = copyText(label, text, R.string.copied)

    private fun copyText(label: String, text: String, confirmation: Int) {
        val clipboard = getSystemService(ClipboardManager::class.java) ?: return
        clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
        // Android 13+ confirms clipboard writes on its own.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) viewModel.message(confirmation)
    }

    private companion object {
        const val MARKDOWN = "text/markdown"
    }
}
