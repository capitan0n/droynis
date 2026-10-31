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
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.time.LocalDate
import java.time.temporal.ChronoUnit

class WebViewCheck(private val webView: WebViewProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1070",
        category = Category.DEVICE_INTEGRITY,
        title = "WebView updates",
        severity = Severity.WARNING,
        explanation = "Most apps show web pages through the system WebView, a full browser engine that " +
            "receives security fixes every few weeks. Browser engines are a favourite target for exploits, " +
            "so an outdated WebView puts every app that uses it at risk.",
        remediation = Remediation(
            text = "Update Android System WebView, or the browser that provides it (Chrome, Vanadium…), from " +
                "your app store, and install pending system updates.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        failsWhen = "WebView hasn't been updated for more than 60 days, or its Chromium version is older than that",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val provider = webView.provider()
        val evidence = listOf(
            provider.toEvidence("WebView provider") { info ->
                info?.let {
                    val updated = when {
                        it.lastUpdated < PLAUSIBLE_UPDATE -> "no valid update date (reports ${it.lastUpdated})"
                        it.fromSystemImage -> "came with the system image of ${it.lastUpdated}"
                        else -> "updated ${it.lastUpdated}"
                    }
                    "${it.packageName} ${it.versionName}, $updated"
                } ?: "none"
            }.copy(packageName = (provider as? Reading.Value)?.value?.packageName),
        )
        return provider.evaluate("WebView", evidence) { info ->
            if (info == null) return@evaluate Outcome.unsupported("This phone has no WebView", evidence)
            val age = ChronoUnit.DAYS.between(info.lastUpdated, context.startedAt.toLocalDate())
            val updated = if (info.fromSystemImage) "came with a system update" else "was updated"
            // A recent date doesn't prove a recent engine: a ROM can ship an old WebView in a new system image.
            val stale = staleVersion(info, context)
            when {
                info.lastUpdated < PLAUSIBLE_UPDATE -> stale
                    ?.let { Outcome.fail("WebView ${info.versionName} is at least ${it.days} days old, judging by its version", evidence + it.evidence) }
                    ?: Outcome.unknown("WebView reports a placeholder update date (${info.lastUpdated})", evidence)
                age < 0 -> Outcome.unknown("WebView's update date is ahead of the device clock", evidence)
                age <= MAX_AGE_DAYS && stale != null -> Outcome.fail(
                    "WebView ${info.versionName} $updated $age days ago, but its version is at least ${stale.days} days old",
                    evidence + stale.evidence,
                )
                age <= MAX_AGE_DAYS -> Outcome.pass("WebView ${info.versionName} $updated $age days ago", evidence)
                info.fromSystemImage ->
                    Outcome.fail("WebView ${info.versionName} came with a system update $age days ago and was not updated since", evidence)
                else -> Outcome.fail("WebView ${info.versionName} was last updated $age days ago", evidence)
            }
        }
    }

    private class StaleVersion(val days: Long, val evidence: Evidence)

    /**
     * WebView's version tells how old it is at least, whatever its update date says: Chromium
     * versions come out on a fixed schedule. Null when that doesn't make it older than
     * [MAX_AGE_DAYS], or when the version is too new or not numbered like Chromium's.
     */
    private fun staleVersion(info: WebViewInfo, context: ScanContext): StaleVersion? {
        val major = chromiumMajor(info.versionName) ?: return null
        val releasedBy = releasedBy(major) ?: return null
        val days = ChronoUnit.DAYS.between(releasedBy, context.startedAt.toLocalDate())
        if (days <= MAX_AGE_DAYS) return null
        return StaleVersion(days, Evidence("Chromium $major released", "$releasedBy or earlier", Source("Chromium release schedule")))
    }

    companion object {
        /** About two Chromium release cycles. */
        const val MAX_AGE_DAYS = 60L

        /** "145.0.7632.218": Chromium's four-part version; Vanadium adds a fifth part. */
        private val CHROMIUM_VERSION = Regex("""^(\d+)\.\d+\.\d+\.\d+""")

        /** Lower major versions are a vendor's own numbering, not Chromium's. */
        private const val MIN_CHROMIUM = 58

        /**
         * Chromium 152, the last release of the four-week cycle, reached stable on 2026-08-25.
         * From Chromium 94 to 152 a release took four weeks or longer on average (longer holiday gaps
         * offset the odd three-week one), so an older major came out no later than four weeks per
         * version before 152. Majors after 152 come every two weeks, with delays a formula can't
         * foresee, so they are left Unknown.
         */
        private const val ANCHOR_MAJOR = 152
        private val ANCHOR_STABLE = LocalDate.of(2026, 8, 25)
        private const val FOUR_WEEK_CYCLE_SINCE = 94

        /** The Chromium major version of [versionName], or null when it isn't numbered like Chromium. */
        internal fun chromiumMajor(versionName: String): Int? =
            CHROMIUM_VERSION.find(versionName)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it >= MIN_CHROMIUM }

        /** The latest date Chromium [major] can have reached stable, or null when it is too new to tell. */
        internal fun releasedBy(major: Int): LocalDate? {
            if (major > ANCHOR_MAJOR) return null
            // Before Chromium 94 releases came every six weeks, and 93 to 94 only three: bound by 94's date.
            val cycles = ANCHOR_MAJOR - maxOf(major, FOUR_WEEK_CYCLE_SINCE)
            return ANCHOR_STABLE.minusWeeks(4L * cycles)
        }

        /**
         * A date before Android 8 was released is a placeholder (1970 on some phones, 2009 from
         * reproducible builds), not an update: Droynis runs on Android 8 and later.
         */
        private val PLAUSIBLE_UPDATE = LocalDate.of(2017, 1, 1)
    }
}
