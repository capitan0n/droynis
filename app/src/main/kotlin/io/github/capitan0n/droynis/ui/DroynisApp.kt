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
import androidx.compose.material.icons.automirrored.rounded.ListAlt
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DataObject
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
import io.github.capitan0n.droynis.ReportFormat
import io.github.capitan0n.droynis.UiState
import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.issues
import io.github.capitan0n.droynis.report.withoutMuted
import io.github.capitan0n.droynis.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow

/** Everything the UI asks the platform to do. Implemented by the activity. */
@Stable
interface AppActions {
    fun scan()
    fun refreshTools()
    fun setThemeMode(mode: ThemeMode)

    /** A muted check still runs and shows its result, but the score and counts leave it out. */
    fun setMuted(checkId: String, muted: Boolean)

    /** Unmutes every muted check. */
    fun unmuteAll()

    /** Shows Shizuku's own dialog asking the user to allow Droynis. */
    fun requestShizuku()

    /** Opens the Shizuku app, or its download page when it is not installed. */
    fun openShizuku()

    /** Turns the root tier on; the root manager asks the user at the scan that follows. */
    fun enableRoot()

    /** Turns the root tier off: Droynis runs su no more. */
    fun disableRoot()

    /** Opens the first Settings screen in [actions] that this phone has. */
    fun openSettings(actions: List<String>)
    fun saveReport(format: ReportFormat)
    fun shareReport()
    fun copyReport()
    fun copy(label: String, text: String)

    /** Opens [url] in the browser; Droynis itself has no internet access. */
    fun openLink(url: String)
    fun sendFeedback()
}

enum class Tab(val labelRes: Int, val icon: ImageVector, val selectedIcon: ImageVector) {
    DASHBOARD(R.string.tab_dashboard, Icons.Outlined.Dashboard, Icons.Rounded.Dashboard),
    CHECKS(R.string.tab_checks, Icons.AutoMirrored.Outlined.FactCheck, Icons.AutoMirrored.Rounded.FactCheck),
    TOOLS(R.string.tab_tools, Icons.Outlined.Build, Icons.Rounded.Build),
    HELP(R.string.tab_help, Icons.AutoMirrored.Outlined.HelpOutline, Icons.AutoMirrored.Rounded.Help),
}

/** The verdict filter of the Checks screen. */
enum class CheckFilter(val verdicts: Set<Verdict>) {
    ALL(emptySet()),
    ISSUES(setOf(Verdict.ATTENTION, Verdict.CRITICAL)),
    PASSED(setOf(Verdict.PASSED)),
    ATTENTION(setOf(Verdict.ATTENTION)),
    CRITICAL(setOf(Verdict.CRITICAL)),
    UNVERIFIED(setOf(Verdict.UNKNOWN, Verdict.NOT_AVAILABLE)),
    MUTED(emptySet()),
    ;

    /**
     * Muted checks show only under [ALL] and [MUTED], so the other counts match the score. A check
     * still running (null verdict) only shows under [ALL].
     */
    fun matches(verdict: Verdict?, muted: Boolean): Boolean = when (this) {
        ALL -> true
        MUTED -> muted
        else -> !muted && verdict in verdicts
    }
}

/** The About page, shown full screen over the tabs. */
private object AboutPage

/** The check catalog, shown full screen over the tabs. */
private object CatalogPage

/** Tags of the scrolling lists and the check search, for UI tests. */
const val CHECKS_LIST_TAG = "checks_list"
const val CATALOG_LIST_TAG = "catalog_list"
const val CHECKS_SEARCH_TAG = "checks_search"

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
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(CheckFilter.ALL) }
    var category by rememberSaveable { mutableStateOf<Category?>(null) }
    var tier by rememberSaveable { mutableStateOf<Tier?>(null) }
    var showAbout by rememberSaveable { mutableStateOf(false) }
    var showCatalog by rememberSaveable { mutableStateOf(false) }
    // Kept while the catalog is closed, so it fades out and reopens on the same tab.
    var catalogTier by rememberSaveable { mutableStateOf(Tier.BASE) }
    var showTheme by rememberSaveable { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val tabStates = rememberSaveableStateHolder()

    LaunchedEffect(messages) { messages.collect { snackbar.showSnackbar(it) } }
    // Back closes the topmost page: About, then a check, then the catalog, then a tab.
    BackHandler(enabled = openCheckId == null && !showCatalog && tab != Tab.DASHBOARD) { tab = Tab.DASHBOARD }
    BackHandler(enabled = openCheckId == null && showCatalog) { showCatalog = false }
    BackHandler(enabled = openCheckId != null) { openCheckId = null }
    BackHandler(enabled = showAbout) { showAbout = false }

    val openSpec = catalog.firstOrNull { it.id == openCheckId }
    val issueCount = state.result?.findings?.withoutMuted(state.muted)?.issues()?.size ?: 0
    val showChecks = { newFilter: CheckFilter, newCategory: Category? ->
        // A search left from before would hide some of what the dashboard points to.
        query = ""
        filter = newFilter
        category = newCategory
        tier = null
        tab = Tab.CHECKS
    }
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            if (showAbout) {
                TopAppBar(
                    title = { Text(stringResource(R.string.about_title)) },
                    navigationIcon = {
                        IconButton(onClick = { showAbout = false }) {
                            Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.navigate_back))
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            } else if (openSpec != null || showCatalog) {
                TopAppBar(
                    title = {
                        Text(
                            stringResource(openSpec?.category?.labelRes ?: R.string.catalog_title),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = { if (openSpec != null) openCheckId = null else showCatalog = false }) {
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
                    showAboutButton = tab == Tab.HELP,
                    onTheme = { showTheme = true },
                    onAbout = { showAbout = true },
                    onCatalog = { showCatalog = true },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        bottomBar = {
            if (openSpec == null && !showAbout && !showCatalog) {
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
            val screen: Any = when {
                showAbout -> AboutPage
                openSpec != null -> openSpec
                showCatalog -> CatalogPage
                else -> tab
            }
            Crossfade(targetState = screen, label = "screen") { target ->
                when (target) {
                    AboutPage -> AboutScreen(
                        appVersion = appVersion,
                        onOpenLink = actions::openLink,
                        onFeedback = actions::sendFeedback,
                    )
                    CatalogPage -> CatalogScreen(
                        catalog = catalog,
                        findings = state.findings,
                        muted = state.muted,
                        grants = state.grants,
                        shizuku = state.shizuku,
                        root = state.root,
                        selected = catalogTier,
                        onSelect = { catalogTier = it },
                        scanning = state.scanning,
                        actions = actions,
                        onOpenCheck = { openCheckId = it },
                    )
                    is CheckSpec -> CheckDetailScreen(
                        spec = target,
                        finding = state.findings[target.id],
                        onOpenSettings = actions::openSettings,
                        onCopy = actions::copy,
                        muted = target.id in state.muted,
                        onMute = { actions.setMuted(target.id, it) },
                        onSetUpTier = if (Capabilities(state.grants).missingFor(target).isEmpty()) {
                            null
                        } else {
                            {
                                openCheckId = null
                                catalogTier = target.requiredTier
                                showCatalog = true
                            }
                        },
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
                                muted = state.muted,
                                query = query,
                                onQuery = { query = it },
                                filter = filter,
                                onFilter = { filter = it },
                                category = category,
                                onCategory = { category = it },
                                tier = tier,
                                onTier = { tier = it },
                                onOpenCheck = { openCheckId = it },
                                onUnmuteAll = {
                                    actions.unmuteAll()
                                    // Nothing is muted any more, so the Muted filter would show nothing.
                                    filter = CheckFilter.ALL
                                },
                            )
                            Tab.TOOLS -> ToolsScreen(state = state, actions = actions)
                            Tab.HELP -> HelpScreen(
                                checkCount = catalog.size,
                                appVersion = appVersion,
                                onAbout = { showAbout = true },
                                onCatalog = { showCatalog = true },
                            )
                        }
                    }
                }
            }
        }
    }

    if (showTheme) {
        ThemeDialog(
            current = themeMode,
            onPick = {
                actions.setThemeMode(it)
                showTheme = false
            },
            onDismiss = { showTheme = false },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainTopBar(
    scanning: Boolean,
    reportReady: Boolean,
    actions: AppActions,
    onHelp: () -> Unit,
    showAboutButton: Boolean,
    onTheme: () -> Unit,
    onAbout: () -> Unit,
    onCatalog: () -> Unit,
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
            if (showAboutButton) {
                IconButton(onClick = onAbout) { Icon(Icons.Rounded.Info, stringResource(R.string.menu_about)) }
            }
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
                        actions.saveReport(ReportFormat.MARKDOWN)
                    }
                    MenuItem(R.string.menu_save_json, Icons.Rounded.DataObject, enabled = reportReady) {
                        menuOpen = false
                        actions.saveReport(ReportFormat.JSON)
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
                    MenuItem(R.string.catalog_title, Icons.AutoMirrored.Rounded.ListAlt) {
                        menuOpen = false
                        onCatalog()
                    }
                    MenuItem(R.string.menu_theme, Icons.Rounded.Palette) {
                        menuOpen = false
                        onTheme()
                    }
                    MenuItem(R.string.menu_help, Icons.AutoMirrored.Rounded.Help) {
                        menuOpen = false
                        onHelp()
                    }
                    MenuItem(R.string.menu_about, Icons.Rounded.Info) {
                        menuOpen = false
                        onAbout()
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
