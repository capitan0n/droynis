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
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Reads the autofill service through `AutofillManager.getAutofillServiceComponentName()`, public
 * from Android 9 and answered for any caller (checked against AutofillManagerService in Android 17).
 */
class AutofillServiceCheck(
    private val autofill: AutofillProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4010",
        category = Category.APPS,
        title = "Autofill service",
        severity = Severity.NOTICE,
        explanation = "The autofill service fills in passwords, addresses and card numbers for you, so it " +
            "sees the forms you fill in, in every app. Password managers use it; a malicious one reads " +
            "what you type into login forms. Autofill that came with the phone is part of the system; any " +
            "other one should come from a developer you trust, and one installed from outside an app " +
            "store is a warning.",
        remediation = Remediation(
            text = "Open Settings › Passwords, passkeys & accounts (on older phones Settings › System › " +
                "Languages & input › Autofill service) and pick a password manager you trust, or None.",
            settingsActions = listOf(SettingsActions.ACCOUNTS),
        ),
        minSdk = 28,
        // Two calls that AutofillManager lets wait up to 5 seconds each.
        timeout = 10.seconds,
        failsWhen = "an autofill service from an app you installed is selected " +
            "(a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val state = autofill.state()
        val read = state.toEvidence("Autofill service") { it.component ?: "none" }
        return state.evaluate("The autofill service", listOf(read)) { current ->
            if (!current.allowed) {
                return@evaluate Outcome.pass("A device policy turns autofill off for this user", listOf(read))
            }
            val component = current.component?.trim().takeUnless { it.isNullOrEmpty() }
                ?: return@evaluate Outcome.pass("No autofill service is selected", listOf(read))
            val pkg = component.substringBefore('/')
            val holder = Holder(AppRef(pkg, packages.label(pkg)), originOf(pkg, packages.byPackage()))
            val counted = holder.origin != AppOrigin.PREINSTALLED
            val evidence = listOf(
                Evidence("Autofill service", "${holder.app.label} ($component)", state.source, note = holder.origin.note),
            )
            if (!counted) {
                Outcome.pass("${holder.app.label}, which came with the phone, fills in forms", evidence)
            } else {
                Outcome.fail(
                    "${holder.app.label} fills in forms and passwords in every app" + sideloadedSuffix(listOf(holder)),
                    evidence,
                    escalation = sideloadedEscalation(listOf(holder)),
                )
            }
        }
    }
}
