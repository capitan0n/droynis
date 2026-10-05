package io.github.capitan0n.droynis.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.FactCheck
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.FactCheck
import androidx.compose.material.icons.automirrored.rounded.Help
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Dashboard
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.UiState
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.issues
import io.github.capitan0n.droynis.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow

/** Everything the UI asks the platform to do. Implemented by the activity. */
@Stable
interface AppActions {
    fun scan()
    fun refreshTools()
    fun setThemeMode(mode: ThemeMode)

    /** Opens the first Settings screen in [actions] that this phone has. */
    fun openSettings(actions: List<String>)
    fun saveReport()
    fun shareReport()
    fun copyReport()
    fun copy(label: String, text: String)
}

enum class Tab(val labelRes: Int, val icon: ImageVector, val selectedIcon: ImageVector) {
    DASHBOARD(R.string.tab_dashboard, Icons.Outlined.Dashboard, Icons.Rounded.Dashboard),
    CHECKS(R.string.tab_checks, Icons.AutoMirrored.Outlined.FactCheck, Icons.AutoMirrored.Rounded.FactCheck),
    TOOLS(R.string.tab_tools, Icons.Outlined.Build, Icons.Rounded.Build),
    HELP(R.string.tab_help, Icons.AutoMirrored.Outlined.HelpOutline, Icons.AutoMirrored.Rounded.Help),
}

/** The verdict filter of the Checks screen. */
enum class CheckFilter(val verdicts: Set<Verdict>?) {
    ALL(null),
    ISSUES(setOf(Verdict.ATTENTION, Verdict.CRITICAL)),
    PASSED(setOf(Verdict.PASSED)),
    ATTENTION(setOf(Verdict.ATTENTION)),
    CRITICAL(setOf(Verdict.CRITICAL)),
    UNVERIFIED(setOf(Verdict.UNKNOWN, Verdict.NOT_AVAILABLE)),
    ;

    /** A check still running (null verdict) only shows under [ALL]. */
    fun matches(verdict: Verdict?): Boolean = verdicts == null || verdict in verdicts
}

private enum class AppDialog { THEME, ABOUT }

/** Tag of the Checks list, for UI tests. */
const val CHECKS_LIST_TAG = "checks_list"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DroynisApp(
    state: UiState,
    catalog: List<CheckSpec>,
    themeMode: ThemeMode,
    appVersion: String,
    messages: Flow<String>,
    actions: AppActions,
    /** Where the app opens; for previews and deep links. */
    initialTab: Tab = Tab.DASHBOARD,
    initialCheckId: String? = null,
) {
    var tab by rememberSaveable { mutableStateOf(initialTab) }
    var openCheckId by rememberSaveable { mutableStateOf(initialCheckId) }
    var filter by rememberSaveable { mutableStateOf(CheckFilter.ALL) }
    var category by rememberSaveable { mutableStateOf<Category?>(null) }
    var dialog by rememberSaveable { mutableStateOf<AppDialog?>(null) }
    val snackbar = remember { SnackbarHostState() }
    val tabStates = rememberSaveableStateHolder()

    LaunchedEffect(messages) { messages.collect { snackbar.showSnackbar(it) } }
    BackHandler(enabled = openCheckId != null) { openCheckId = null }
    BackHandler(enabled = openCheckId == null && tab != Tab.DASHBOARD) { tab = Tab.DASHBOARD }

    val openSpec = catalog.firstOrNull { it.id == openCheckId }
    val issueCount = state.result?.findings?.issues()?.size ?: 0
    val showChecks = { newFilter: CheckFilter, newCategory: Category? ->
        filter = newFilter
        category = newCategory
        tab = Tab.CHECKS
    }
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            if (openSpec != null) {
                TopAppBar(
                    title = {
                        Text(stringResource(openSpec.category.labelRes), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    },
                    navigationIcon = {
                        IconButton(onClick = { openCheckId = null }) {
                            Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.navigate_back))
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            } else {
                MainTopBar(
                    scanning = state.scanning,
                    reportReady = state.result != null,
                    actions = actions,
                    onHelp = { tab = Tab.HELP },
                    onDialog = { dialog = it },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        bottomBar = {
            if (openSpec == null) {
                NavigationBar {
                    for (item in Tab.entries) {
                        NavigationBarItem(
                            selected = tab == item,
                            onClick = { tab = item },
                            icon = {
                                val icon = if (tab == item) item.selectedIcon else item.icon
                                if (item == Tab.CHECKS && issueCount > 0) {
                                    BadgedBox(badge = { Badge { Text("$issueCount") } }) { Icon(icon, null) }
                                } else {
                                    Icon(icon, null)
                                }
                            },
                            label = { Text(stringResource(item.labelRes)) },
                        )
                    }
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Crossfade(targetState = openSpec ?: tab, label = "screen") { target ->
                when (target) {
                    is CheckSpec -> CheckDetailScreen(
                        spec = target,
                        finding = state.findings[target.id],
                        onOpenSettings = actions::openSettings,
                        onCopy = actions::copy,
                    )
                    is Tab -> tabStates.SaveableStateProvider(target.name) {
                        when (target) {
                            Tab.DASHBOARD -> DashboardScreen(
                                state = state,
                                catalog = catalog,
                                onScan = actions::scan,
                                onOpenCheck = { openCheckId = it },
                                onShowChecks = showChecks,
                                onShowTools = { tab = Tab.TOOLS },
                            )
                            Tab.CHECKS -> ChecksScreen(
                                catalog = catalog,
                                findings = state.findings,
                                filter = filter,
                                onFilter = { filter = it },
                                category = category,
                                onCategory = { category = it },
                                onOpenCheck = { openCheckId = it },
                            )
                            Tab.TOOLS -> ToolsScreen(state = state, actions = actions)
                            Tab.HELP -> HelpScreen(catalog = catalog, appVersion = appVersion)
                        }
                    }
                }
            }
        }
    }

    when (dialog) {
        AppDialog.THEME -> ThemeDialog(
            current = themeMode,
            onPick = {
                actions.setThemeMode(it)
                dialog = null
            },
            onDismiss = { dialog = null },
        )
        AppDialog.ABOUT -> AboutDialog(appVersion = appVersion, onDismiss = { dialog = null })
        null -> Unit
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainTopBar(
    scanning: Boolean,
    reportReady: Boolean,
    actions: AppActions,
    onHelp: () -> Unit,
    onDialog: (AppDialog) -> Unit,
    scrollBehavior: TopAppBarScrollBehavior,
) {
    var menuOpen by remember { mutableStateOf(false) }
    TopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Rounded.Shield,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp),
                )
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge)
                    Text(
                        stringResource(R.string.app_tagline),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        actions = {
            IconButton(onClick = actions::scan, enabled = !scanning) {
                Icon(Icons.Rounded.Refresh, stringResource(R.string.menu_scan_again))
            }
            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Icon(Icons.Rounded.MoreVert, stringResource(R.string.more_options))
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    MenuItem(R.string.menu_scan_again, Icons.Rounded.Refresh, enabled = !scanning) {
                        menuOpen = false
                        actions.scan()
                    }
                    HorizontalDivider()
                    MenuItem(R.string.menu_save_report, Icons.Rounded.Save, enabled = reportReady) {
                        menuOpen = false
                        actions.saveReport()
                    }
                    MenuItem(R.string.menu_share_report, Icons.Rounded.Share, enabled = reportReady) {
                        menuOpen = false
                        actions.shareReport()
                    }
                    MenuItem(R.string.menu_copy_report, Icons.Rounded.ContentCopy, enabled = reportReady) {
                        menuOpen = false
                        actions.copyReport()
                    }
                    HorizontalDivider()
                    MenuItem(R.string.menu_theme, Icons.Rounded.Palette) {
                        menuOpen = false
                        onDialog(AppDialog.THEME)
                    }
                    MenuItem(R.string.menu_help, Icons.AutoMirrored.Rounded.Help) {
                        menuOpen = false
                        onHelp()
                    }
                    MenuItem(R.string.menu_about, Icons.Rounded.Info) {
                        menuOpen = false
                        onDialog(AppDialog.ABOUT)
                    }
                }
            }
        },
        scrollBehavior = scrollBehavior,
    )
}

@Composable
private fun MenuItem(labelRes: Int, icon: ImageVector, enabled: Boolean = true, onClick: () -> Unit) {
    DropdownMenuItem(
        text = { Text(stringResource(labelRes)) },
        onClick = onClick,
        leadingIcon = { Icon(icon, contentDescription = null) },
        enabled = enabled,
    )
}

@Composable
private fun ThemeDialog(current: ThemeMode, onPick: (ThemeMode) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Rounded.Palette, contentDescription = null) },
        title = { Text(stringResource(R.string.menu_theme)) },
        text = {
            Column(Modifier.selectableGroup()) {
                for (mode in ThemeMode.entries) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = mode == current, onClick = { onPick(mode) }, role = Role.RadioButton)
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = mode == current, onClick = null)
                        Spacer(Modifier.width(12.dp))
                        Text(
                            stringResource(
                                when (mode) {
                                    ThemeMode.SYSTEM -> R.string.theme_system
                                    ThemeMode.LIGHT -> R.string.theme_light
                                    ThemeMode.DARK -> R.string.theme_dark
                                },
                            ),
                        )
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.dialog_close)) } },
    )
}

@Composable
private fun AboutDialog(appVersion: String, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                Icons.Rounded.Shield,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(40.dp),
            )
        },
        title = { Text(stringResource(R.string.about_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.about_version, appVersion), style = MaterialTheme.typography.labelLarge)
                Text(stringResource(R.string.about_body))
                Text(stringResource(R.string.about_privacy))
                Text(
                    stringResource(R.string.about_license),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.dialog_close)) } },
    )
}
