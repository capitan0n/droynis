package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps that may make Termux or Tasker run something for them. Each defines a dangerous permission
 * for it ([Bridge.permission]), so another app gets it only when the user allows it, and the
 * granted flag reads without any privilege.
 *
 * Not seen: the switch in Termux or Tasker that must also accept outside apps (`allow-external-apps`
 * in Termux's private `termux.properties`, Tasker's Allow External Access), so a holder *may* run
 * commands. Termux's plugins (Termux:API, Termux:Boot…) share its uid and run as Termux anyway: they
 * are left out by uid, not by name, so an app that only calls itself `com.termux.something` still counts.
 */
class CommandBridgeCheck(
    private val permissions: PermissionProbe,
    private val packages: PackageInventory,
) : Check {

    /** An app that runs things for other apps, and the permission it hands out for that. */
    enum class Bridge(
        val permission: String,
        /** The app's packages: Tasker has a Play Store and an older direct-download package. */
        val providers: List<String>,
        val app: String,
        /** What a holder may do, after "may". */
        val does: String,
        /** Evidence label for a holder. */
        val label: String,
    ) {
        TERMUX(
            "com.termux.permission.RUN_COMMAND",
            listOf("com.termux"),
            "Termux",
            "run commands in Termux",
            "Termux commands",
        ),
        TASKER(
            "net.dinglisch.android.tasker.PERMISSION_RUN_TASKS",
            listOf("net.dinglisch.android.taskerm", "net.dinglisch.android.tasker"),
            "Tasker",
            "start Tasker tasks",
            "Tasker tasks",
        ),
    }

    override val spec = CheckSpec(
        id = "APPS-4019",
        category = Category.APPS,
        title = "Apps that can run commands through Termux or Tasker",
        severity = Severity.NOTICE,
        explanation = "Termux and Tasker run things for other apps you allow. An app with Termux's \"Run " +
            "commands in Termux environment\" permission can run any shell command as Termux, with " +
            "everything Termux and its Termux:API add-on may do, such as sending SMS, reading your location " +
            "or using the camera. An app with Tasker's \"Run Tasker tasks\" permission can start your tasks, " +
            "and with them whatever Tasker may do. Termux accepts such commands only while " +
            "allow-external-apps is on in its settings file, and Tasker only while Allow External Access is " +
            "on; Droynis can't read either, so a listed app may run them. One installed from outside an app " +
            "store is a warning.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › Permissions › Additional permissions and set \"Run " +
                "commands in Termux environment\" or \"Run Tasker tasks\" to Don't allow for apps that don't " +
                "need it. If no app needs it, set allow-external-apps = false in ~/.termux/termux.properties, " +
                "and turn off Allow External Access in Tasker's Preferences › Misc.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "another app may run commands in Termux or start Tasker tasks (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val granted = permissions.holders(Bridge.entries.mapTo(linkedSetOf()) { it.permission })
        if (granted !is Reading.Value) {
            val subject = "which apps may run commands in Termux or start Tasker tasks"
            return Outcome.unknown("Could not read $subject", listOf(granted.toEvidence("Permissions")))
        }
        val installed = packages.installedApps()
        val inventory = (installed as? Reading.Value)?.value?.associateBy { it.packageName }

        // The bridge apps themselves, and anything sharing their uid, hold no power they don't already have.
        val ownUids = Bridge.entries.associateWith { bridge -> bridge.providers.mapNotNullTo(mutableSetOf()) { inventory?.get(it)?.uid } }
        fun isPartOf(pkg: String, bridge: Bridge): Boolean =
            pkg in bridge.providers || inventory?.get(pkg)?.uid?.let { it in ownUids.getValue(bridge) } == true

        val reach: Map<String, List<Bridge>> = granted.value.mapNotNull { (pkg, held) ->
            Bridge.entries.filter { it.permission in held && !isPartOf(pkg, it) }.takeIf { it.isNotEmpty() }?.let { pkg to it }
        }.toMap()
        val all = reach.keys
            .map { Holder(AppRef(it, packages.label(it)), originOf(it, inventory)) }
            .sortedBy { it.app.label.lowercase() }
        // Every holder was allowed by someone, whatever its origin, so all of them count.
        val (trusted, counted) = context.splitTrusted(all) { it.app.packageName }

        val evidence = buildList {
            Bridge.entries.forEach { add(appEvidence(it, installed, inventory)) }
            termuxApiEvidence(inventory)?.let { add(it) }
            all.forEach { holder ->
                val label = reach.getValue(holder.app.packageName).joinToString(" and ") { it.label }
                add(holder.evidence(label, granted.source, trusted = holder in trusted))
            }
            if (all.isEmpty()) add(Evidence("Apps that may use them", "none", granted.source))
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(onlyTrusted("may ${phrase(trusted, reach)}", trusted.labels()), evidence)
        }
        if (counted.isEmpty()) {
            return Outcome.pass("No app may run commands in Termux or start Tasker tasks", evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} may ${phrase(counted, reach)}: ${counted.labels().joinNames()}" +
                sideloadedSuffix(counted),
            evidence,
            escalation = sideloadedEscalation(counted),
        )
    }

    /** "run commands in Termux", "start Tasker tasks", or both joined with "or". */
    private fun phrase(holders: List<Holder>, reach: Map<String, List<Bridge>>): String =
        holders.flatMap { reach.getValue(it.app.packageName) }.distinct().sorted().joinToString(" or ") { it.does }

    /** Whether Termux or Tasker is installed, as context: without it no app holds its permission. */
    private fun appEvidence(bridge: Bridge, installed: Reading<List<InstalledApp>>, inventory: Map<String, InstalledApp>?): Evidence {
        if (inventory == null) return installed.toEvidence(bridge.app)
        val pkg = bridge.providers.firstOrNull { it in inventory }
            ?: return Evidence(bridge.app, "not installed", installed.source)
        return Evidence(bridge.app, "${packages.label(pkg)} ($pkg)", installed.source, packageName = pkg)
    }

    /**
     * What Termux:API lets every Termux command do: the sensitive permissions held by any package
     * that shares Termux's uid. Null when Termux isn't installed or nothing sensitive is granted.
     */
    private fun termuxApiEvidence(inventory: Map<String, InstalledApp>?): Evidence? {
        val termux = inventory?.get(TERMUX) ?: return null
        val held = permissions.holders(TERMUX_API_PERMISSIONS.keys) as? Reading.Value ?: return null
        val sameUid = held.value.filterKeys { pkg -> pkg == TERMUX || (termux.uid != null && inventory[pkg]?.uid == termux.uid) }
        val names = TERMUX_API_PERMISSIONS.filterKeys { perm -> sameUid.values.any { perm in it } }.values.distinct()
        if (names.isEmpty()) return null
        return Evidence(
            "What Termux commands can use",
            names.joinToString(),
            held.source,
            note = "permissions of Termux and its add-ons, such as Termux:API",
        )
    }

    companion object {
        const val TERMUX = "com.termux"

        /** Permissions Termux:API asks for that matter most, by what they let a command do. */
        val TERMUX_API_PERMISSIONS = linkedMapOf(
            "android.permission.SEND_SMS" to "send SMS",
            "android.permission.READ_SMS" to "read SMS",
            "android.permission.READ_CALL_LOG" to "read the call log",
            "android.permission.CALL_PHONE" to "make calls",
            "android.permission.READ_CONTACTS" to "read contacts",
            "android.permission.ACCESS_FINE_LOCATION" to "precise location",
            "android.permission.ACCESS_COARSE_LOCATION" to "approximate location",
            "android.permission.CAMERA" to "camera",
            "android.permission.RECORD_AUDIO" to "microphone",
        )
    }
}
