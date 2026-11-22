package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.AppOrigin
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.byPackage
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.checks.base.onlyTrusted
import io.github.capitan0n.droynis.checks.base.originOf
import io.github.capitan0n.droynis.checks.base.splitTrusted
import io.github.capitan0n.droynis.checks.base.trustOf
import io.github.capitan0n.droynis.checks.base.withTrustNote
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Reads `/data/misc/sms/premium_sms_policy.xml`, where telephony's `SmsUsageMonitor` keeps each app's
 * Premium SMS access: `<premium-sms-policy>` holding one `<package name="…" sms-policy="N"/>` per app
 * that was ever asked. Android 12 and later may store it as binary XML, which the root command turns
 * back into text with `abx2xml`.
 */
object PremiumSmsPolicies {

    /** `SmsUsageMonitor.PREMIUM_SMS_PERMISSION_ALWAYS_ALLOW`; 1 is Ask, 2 Never allow. */
    const val ALWAYS_ALLOW = 3

    private val PACKAGE = Regex("""<package\b([^>]*)>""")
    private val ATTRIBUTE = Regex("""([\w-]+)\s*=\s*"([^"]*)"""")

    /** Each app's policy by package; null when the file is in a shape Droynis doesn't recognize. */
    fun parse(text: String): Map<String, Int>? {
        if ("<premium-sms-policy" !in text) return null
        val tags = PACKAGE.findAll(text).toList()
        // A tag the pattern can't take apart must never be skipped: it could be the one that allows.
        if (tags.size != Regex("""<package\b""").findAll(text).count()) return null
        return tags.associate { tag ->
            val attributes = ATTRIBUTE.findAll(tag.groupValues[1]).associate { it.groupValues[1] to it.groupValues[2] }
            val name = attributes["name"]?.takeIf { it.isNotBlank() } ?: return null
            val policy = attributes["sms-policy"]?.toIntOrNull() ?: return null
            name to policy
        }
    }
}

class PremiumSmsCheck(
    private val root: RootShellProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4303",
        category = Category.APPS,
        title = "Apps allowed to text premium numbers",
        severity = Severity.WARNING,
        explanation = "Android asks before an app sends an SMS to a premium-rate number, which is charged to " +
            "your phone bill, unless that app's Premium SMS access is set to Always allow. Such an app can sign " +
            "you up to paid services again and again without asking, which is how billing-fraud malware such as " +
            "Joker makes money. Android keeps these answers in a file only root can read.",
        remediation = Remediation(
            text = "Open Settings › Apps › Special app access › Premium SMS access and set every app to Ask or " +
                "Never allow. Uninstall an app you don't remember allowing.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "an app's Premium SMS access is set to Always allow",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val file = root.premiumSmsPolicy()
        if (file !is Reading.Value) {
            return Outcome.unknown("Android's premium SMS settings could not be read", listOf(file.toEvidence("Premium SMS settings")))
        }
        val text = file.value ?: return Outcome.pass(
            "No app has a premium SMS setting: Android asks the first time an app texts a premium number",
            listOf(Evidence("Premium SMS settings", "none", file.source, note = "the file doesn't exist yet")),
        )
        val policies = PremiumSmsPolicies.parse(text) ?: return Outcome.unknown(
            "Android's premium SMS settings are in a format Droynis doesn't recognize",
            listOf(Evidence("Premium SMS settings", null, file.source, note = text.lineSequence().firstOrNull()?.take(80))),
        )
        val inventory = packages.byPackage()
        val always = policies.filterValues { it == PremiumSmsPolicies.ALWAYS_ALLOW }.keys.sorted()
        // An app that is gone can't text: its setting is listed, not counted.
        val (installed, gone) = always.partition { inventory == null || it in inventory }
        val apps = installed.map { it to packages.label(it) }.sortedBy { it.second.lowercase() }
        val (trusted, counted) = context.splitTrusted(apps) { it.first }

        val evidence = buildList {
            add(Evidence("Apps with a premium SMS setting", policies.size.toString(), file.source))
            apps.forEach { (pkg, label) ->
                val isTrusted = trusted.any { it.first == pkg }
                val origin = originOf(pkg, inventory)
                add(
                    Evidence(
                        "Always allowed",
                        "$label ($pkg)",
                        file.source,
                        note = withTrustNote(origin.note.takeIf { origin != AppOrigin.UNKNOWN }, isTrusted),
                        packageName = pkg,
                        trust = trustOf(counted = true, trusted = isTrusted),
                    ),
                )
            }
            gone.forEach { add(Evidence("Always allowed", it, file.source, note = "not installed; not counted")) }
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(onlyTrusted("may text premium numbers without asking", trusted.map { it.second }), evidence)
        }
        if (counted.isEmpty()) {
            return Outcome.pass("No app may text premium numbers without asking", evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} may text premium numbers without asking: ${counted.map { it.second }.joinNames()}",
            evidence,
        )
    }

    companion object {
        /** Where telephony's `SmsUsageMonitor` keeps each app's Premium SMS access. */
        const val POLICY_FILE = "/data/misc/sms/premium_sms_policy.xml"
    }
}
