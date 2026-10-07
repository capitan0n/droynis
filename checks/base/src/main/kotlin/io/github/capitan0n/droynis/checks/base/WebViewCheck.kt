package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
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
        failsWhen = "WebView hasn't been updated for more than 60 days",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val provider = webView.provider()
        val evidence = listOf(
            provider.toEvidence("WebView provider") { info ->
                info?.let {
                    val updated = if (it.fromSystemImage) "came with the system image of" else "updated"
                    "${it.packageName} ${it.versionName}, $updated ${it.lastUpdated}"
                } ?: "none"
            },
        )
        return provider.evaluate("WebView", evidence) { info ->
            if (info == null) return@evaluate Outcome.unsupported("This phone has no WebView", evidence)
            val age = ChronoUnit.DAYS.between(info.lastUpdated, context.startedAt.toLocalDate())
            val updated = if (info.fromSystemImage) "came with a system update" else "was updated"
            when {
                age < 0 -> Outcome.unknown("WebView's update date is ahead of the device clock", evidence)
                age <= MAX_AGE_DAYS -> Outcome.pass("WebView ${info.versionName} $updated $age days ago", evidence)
                info.fromSystemImage ->
                    Outcome.fail("WebView ${info.versionName} came with a system update $age days ago and was not updated since", evidence)
                else -> Outcome.fail("WebView ${info.versionName} was last updated $age days ago", evidence)
            }
        }
    }

    companion object {
        /** About two Chromium release cycles. */
        const val MAX_AGE_DAYS = 60L
    }
}
