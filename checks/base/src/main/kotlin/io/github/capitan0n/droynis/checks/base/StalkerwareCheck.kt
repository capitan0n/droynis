package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import kotlin.time.Duration.Companion.seconds

/**
 * User apps whose package name or signing key is on Echap's Stalkerware Indicators list, bundled
 * with the app. An exact match on a fixed list, so it finds known apps only: a new or rebuilt one
 * passes.
 */
class StalkerwareCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
    /** The list to match against; null for the bundled one, loaded on first use. */
    private val indicators: StalkerwareIndicators? = null,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5007",
        category = Category.SUSPICIOUS_APPS,
        title = "Known stalkerware and monitoring apps",
        severity = Severity.WARNING,
        explanation = "Stalkerware is an app someone installs on another person's phone to secretly read their " +
            "messages, follow their location or listen in. It usually hides its icon and poses as a system service. " +
            "Droynis compares every app you installed with Stalkerware Indicators, a public list by Echap of the " +
            "package names and signing keys of known stalkerware, and of monitoring apps that don't hide, such as " +
            "child-monitoring and family-locator apps. The list ships with Droynis and works offline. A new or " +
            "rebuilt stalkerware app won't be on it, so a pass means no known stalkerware, not none at all.",
        remediation = Remediation(
            text = "If you didn't install a listed app yourself, someone with access to your phone may be watching " +
                "you. Removing it can alert them, so if you might be in danger, first talk to a support organization " +
                "for domestic violence or stalking (the Coalition Against Stalkerware lists some at " +
                "stopstalkerware.org). Then remove its device admin access (APPS-4002) if it has any, uninstall it, and " +
                "change your account passwords from another device. Mark a monitoring app you set up on purpose " +
                "as trusted.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 30.seconds,
        failsWhen = "an app you installed has the package name or signing key of an app on Echap's Stalkerware " +
            "Indicators list (critical for stalkerware, warning for a monitoring app that doesn't hide)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val list = indicators ?: StalkerwareIndicators.bundled
        val apps = readSightings(footprints, packages) { return it }
        val evidence = mutableListOf(
            apps.inspected(),
            Evidence("Indicator list", "${count(list.size, "app")}, updated ${list.date}", list.source),
        )
        val found = apps.all.mapNotNull { app -> list.match(app.packageName, app.footprint.signerSha1)?.let { app to it } }
        if (found.isEmpty()) return Outcome.pass(NONE, evidence)

        val (trusted, counted) = context.splitTrusted(found) { it.first.packageName }
        evidence += found.map { item ->
            val (app, match) = item
            app.evidence("Listed app", list.source, match.note, item in trusted, counted = true, showVisibility = false)
        }
        if (counted.isEmpty()) {
            return Outcome.pass(onlyTrusted("are on the list", trusted.map { it.first.name }), evidence)
        }

        val (stalkerware, watchware) = counted.partition { it.second.family.kind == IndicatorKind.STALKERWARE }
        val summary = listOfNotNull(
            stalkerware.takeIf { it.isNotEmpty() }?.let {
                "${count(it.size, "app")} ${if (it.size == 1) "matches" else "match"} known stalkerware: ${it.map { p -> p.first }.names()}"
            },
            watchware.takeIf { it.isNotEmpty() }?.let {
                "${count(it.size, "known monitoring app")}: ${it.map { p -> p.first }.names()}"
            },
        ).joinToString("; ")
        return Outcome.fail(summary, evidence, escalation = Severity.CRITICAL.takeIf { stalkerware.isNotEmpty() })
    }

    internal companion object {
        const val NONE = "No app you installed matches known stalkerware or a known monitoring app"
    }
}

/** How Echap's list classes an app. */
enum class IndicatorKind(val label: String) {
    /** Built to spy on someone and hide from them. */
    STALKERWARE("stalkerware"),

    /** Monitoring that doesn't hide, like child-monitoring and family-locator apps ("watchware"). */
    WATCHWARE("monitoring app"),
}

/** One app on the list, under the name it is best known by. */
data class IndicatorFamily(
    val name: String,
    val kind: IndicatorKind,
    val packages: List<String>,
    /** SHA-1 fingerprints of its signing certificates: upper-case hex, no colons. */
    val certificates: List<String>,
)

/** An installed app found on the list, and what matched. */
data class IndicatorMatch(val family: IndicatorFamily, val byPackage: Boolean, val byCertificate: Boolean) {
    val note: String
        get() {
            val what = when {
                byPackage && byCertificate -> "package name and signing key"
                byCertificate -> "signing key"
                else -> "package name"
            }
            return "${family.name} (${family.kind.label}): same $what"
        }
}

/** The list, indexed by package name and by certificate fingerprint. */
class StalkerwareIndicators(families: List<IndicatorFamily>, val date: String, val source: Source) {
    val size: Int = families.size

    private val byPackage = HashMap<String, IndicatorFamily>()
    private val byCertificate = HashMap<String, IndicatorFamily>()

    init {
        // The first family listing a value keeps it, as the generator does.
        for (family in families) {
            family.packages.forEach { byPackage.putIfAbsent(it, family) }
            family.certificates.forEach { byCertificate.putIfAbsent(it.uppercase(), family) }
        }
    }

    /**
     * The family [packageName] or one of its [certificates] (SHA-1, any case) belongs to; null when
     * neither is listed. A signing key says more than a package name anyone can copy, so when they
     * point to different families the key's family wins.
     */
    fun match(packageName: String, certificates: List<String>): IndicatorMatch? {
        val packageFamily = byPackage[packageName]
        val certificateFamily = certificates.firstNotNullOfOrNull { byCertificate[it.uppercase()] }
        val family = certificateFamily ?: packageFamily ?: return null
        return IndicatorMatch(family, byPackage = packageFamily == family, byCertificate = certificateFamily == family)
    }

    companion object {
        /** The list generated into [StalkerwareIndicatorData], indexed on first use. */
        val bundled: StalkerwareIndicators by lazy {
            StalkerwareIndicators(
                StalkerwareIndicatorData.FAMILIES,
                StalkerwareIndicatorData.DATE,
                Source(
                    "Stalkerware Indicators by Echap (CC BY 4.0), commit ${StalkerwareIndicatorData.COMMIT.take(12)}, " +
                        "bundled",
                ),
            )
        }
    }
}
