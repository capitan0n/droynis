package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import kotlin.time.Duration.Companion.seconds

/**
 * User apps signed with Android's debug key or the public AOSP test keys. App stores never ship
 * either; a release build re-signed with a debug key is usually a repackaged copy.
 */
class TestKeyAppsCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5006",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps signed with a debug or test key",
        severity = Severity.NOTICE,
        explanation = "Every app is signed by its developer. Android's debug key is meant for testing on the " +
            "developer's own phone, and Android's test keys are published with its source code, so anyone can sign " +
            "with them. Apps from an app store never use either. A finished app re-signed with a debug key is " +
            "usually a repackaged copy, modded or with malware added; a debuggable one is often a developer's own build.",
        remediation = Remediation(
            text = "Uninstall apps listed here unless you built them yourself or know where they came from, and " +
                "install them again from the developer or an app store.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 30.seconds,
        failsWhen = "a user app is signed with Android's debug key or a public test key (warning for a test key, " +
            "or a debug key on an app that isn't debuggable)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val evidence = mutableListOf(apps.inspected())
        val found = apps.all.mapNotNull { app -> keyOf(app.footprint.signerSubjects)?.let { app to it } }
        if (found.isEmpty()) return Outcome.pass(NONE, evidence)

        val inventory = packages.byPackage().orEmpty()
        val (trusted, counted) = context.splitTrusted(found) { it.first.packageName }
        fun repackaged(item: Pair<AppSighting, Key>) =
            item.second == Key.TEST || inventory[item.first.packageName]?.isDebuggable == false

        evidence += found.map { item ->
            val (app, key) = item
            val details = key.note + if (key == Key.DEBUG && repackaged(item)) ", on an app that isn't debuggable" else ""
            app.evidence("Signed with", apps.source, details, item in trusted, counted = true, showVisibility = false)
        }
        if (counted.isEmpty()) {
            return Outcome.pass(onlyTrusted("are signed with a debug or test key", trusted.map { it.first.name }), evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} signed with a debug or test key: ${counted.map { it.first }.names()}",
            evidence,
            escalation = Severity.WARNING.takeIf { counted.any(::repackaged) },
        )
    }

    internal enum class Key(val note: String) {
        DEBUG("Android's debug key"),
        TEST("a public Android test key"),
    }

    internal companion object {
        const val NONE = "No app you installed is signed with a debug or test key"

        /** The debug keystore Android's build tools create: `CN=Android Debug, O=Android, C=US`. */
        private val DEBUG = mapOf("CN" to "Android Debug", "O" to "Android", "C" to "US")

        /** The test keys in AOSP's build/target/product/security (testkey, platform, shared, media…). */
        private val TEST = mapOf(
            "CN" to "Android",
            "OU" to "Android",
            "O" to "Android",
            "L" to "Mountain View",
            "ST" to "California",
            "C" to "US",
        )

        /** The kind of well-known key among [subjects], test keys first; null for any other key. */
        fun keyOf(subjects: List<String>): Key? {
            val names = subjects.map(::attributes)
            return when {
                names.any { it == TEST } -> Key.TEST
                names.any { it == DEBUG } -> Key.DEBUG
                else -> null
            }
        }

        /**
         * An RFC 2253 name's attributes by type, e.g. "C=US,O=Android,CN=Android Debug". Attributes
         * printed as OIDs (emailAddress) are dropped, so the AOSP keys' email doesn't matter.
         */
        fun attributes(subject: String): Map<String, String> =
            subject.split(Regex("""(?<!\\),"""))
                .mapNotNull { part ->
                    val type = part.substringBefore('=', "").trim()
                    val value = part.substringAfter('=', "").trim().replace("\\", "")
                    if (type.isEmpty() || type.first().isDigit()) null else type.uppercase() to value
                }
                .toMap()
    }
}
