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
import java.util.Locale
import kotlin.time.Duration.Companion.seconds

/**
 * Apps the user installed that show the same name as an app that came with the phone, such as a
 * second "Settings". Malware takes a system app's name so it is left alone in the app list, and
 * Magisk's "Hide the Magisk app" renames the root manager to "Settings" under a random package
 * name. Every other check would report such an app by that borrowed name.
 *
 * Names are compared as shown: case, surrounding space and invisible characters don't count.
 * Letters that only look alike (a Cyrillic "е" in "Sеttings") are not matched.
 */
class SystemNameAppsCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5008",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps using a built-in app's name",
        severity = Severity.NOTICE,
        explanation = "An app you installed that shows the same name as an app that came with the phone is easy " +
            "to mistake for it: a second \"Settings\" or \"Google Play services\" in the app list looks like part " +
            "of the system. Malware uses such names to be left alone, and a root manager hidden with Magisk's " +
            "\"Hide the Magisk app\" is called \"Settings\" unless you chose another name. Replacements you picked " +
            "yourself, such as another calculator or gallery, match too: from an app store they are listed, not " +
            "counted. Droynis names these apps with their package name, since the name alone says nothing.",
        remediation = Remediation(
            text = "Open each app listed (the button next to it opens its App info) and check that you installed " +
                "it yourself under that name. Uninstall the ones you don't recognize. If it is your own hidden " +
                "root manager or a replacement app you chose, trust it here.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        // Loads the label of every system app once: a few seconds on a phone with a few hundred.
        timeout = 30.seconds,
        failsWhen = "an app from outside an app store shows the same name as an app that came with the phone " +
            "(a warning when that app is a core one, such as Settings or Google Play services)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        if (apps !is Reading.Value) {
            return Outcome.unknown("Could not read the installed apps", listOf(apps.toEvidence("Installed apps")))
        }
        val inventory = apps.value.associateBy { it.packageName }
        val (system, user) = apps.value.partition { it.isSystem }
        val inspected = Evidence("User apps inspected", user.size.toString(), apps.source)
        if (user.isEmpty() || system.isEmpty()) return Outcome.pass(NONE, listOf(inspected))

        // An app without a label of its own is shown by its package name, which no other app can have.
        val builtIn = HashMap<String, MutableList<String>>()
        for (app in system) {
            val label = packages.label(app.packageName)
            if (label != app.packageName) builtIn.getOrPut(normalize(label)) { mutableListOf() } += app.packageName
        }
        val found = user.mapNotNull { app ->
            val installedLabel = packages.installedLabel(app.packageName)
            if (installedLabel == app.packageName) return@mapNotNull null
            val twins = builtIn[normalize(installedLabel)] ?: return@mapNotNull null
            Found(Holder(AppRef(app.packageName, packages.label(app.packageName)), originOf(app.packageName, inventory)), twins.sorted())
        }.sortedWith(compareByDescending<Found> { it.core }.thenBy { it.holder.app.label.lowercase(Locale.ROOT) })
        if (found.isEmpty()) return Outcome.pass(NONE, listOf(inspected))

        // An app store reviewed the app under that name, or the OS shipped it: a replacement, not a disguise.
        val (fromStore, outside) = found.partition { it.holder.origin == AppOrigin.STORE || it.holder.origin == AppOrigin.PREINSTALLED }
        val (trusted, counted) = context.splitTrusted(outside) { it.holder.app.packageName }
        val evidence = listOf(inspected) + found.map { item ->
            val twin = item.twins.first()
            val more = if (item.twins.size > 1) " and ${count(item.twins.size - 1, "more app")}" else ""
            item.holder.evidence(LABEL, apps.source, counted = item !in fromStore, trusted = item in trusted)
                .let { it.copy(note = "same name as ${packages.label(twin)} ($twin)$more; ${it.note}") }
        }
        if (counted.isEmpty()) {
            val listed = if (fromStore.isEmpty()) "" else " (${count(fromStore.size, "app")} from an app store listed, not counted)"
            val head = if (trusted.isEmpty()) NONE else onlyTrusted("use a built-in app's name", trusted.map { it.holder.app.label })
            return Outcome.pass(head + listed, evidence)
        }
        // By package name too: the name is the one thing that doesn't tell these apps apart.
        val names = counted.map { "${it.holder.app.label} (${it.holder.app.packageName})" }
        val verb = if (counted.size == 1) "uses" else "use"
        return Outcome.fail(
            "${count(counted.size, "app")} from outside an app store $verb the name of an app that came with the phone: " +
                names.joinNames(),
            evidence,
            escalation = Severity.WARNING.takeIf { counted.any { it.core } },
        )
    }

    /** A user app and the system apps that show the same name. */
    private class Found(val holder: Holder, val twins: List<String>) {
        /** It took the name of an app nobody replaces: a disguise, not a replacement. */
        val core: Boolean get() = twins.any { it in CORE_APPS }
    }

    companion object {
        const val NONE = "No app you installed uses the name of an app that came with the phone"
        private const val LABEL = "Uses a built-in app's name"

        /**
         * System apps a user never installs a replacement for, so an app under their name is posing
         * as one: Settings and its storage, the system itself and its UI, the installers and
         * permission dialogs, Google Play services and the Play Store.
         */
        val CORE_APPS = setOf(
            "android",
            "com.android.settings",
            "com.android.providers.settings",
            "com.android.systemui",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.permissioncontroller",
            "com.google.android.permissioncontroller",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending",
            "com.android.shell",
        )

        /**
         * A name as it reads on screen: without control and format characters (zero-width spaces,
         * direction marks), runs of space folded to one, and case ignored.
         */
        fun normalize(label: String): String {
            val visible = StringBuilder()
            label.codePoints().forEach { codePoint ->
                when (Character.getType(codePoint)) {
                    Character.CONTROL.toInt(), Character.FORMAT.toInt() -> Unit
                    else -> if (Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint)) {
                        visible.append(' ')
                    } else {
                        visible.appendCodePoint(codePoint)
                    }
                }
            }
            return visible.trim().replace(Regex(" +"), " ").lowercase(Locale.ROOT)
        }
    }
}
