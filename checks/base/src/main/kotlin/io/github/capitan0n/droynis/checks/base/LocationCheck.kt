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

class LocationCheck(private val radios: RadioProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3008",
        category = Category.NETWORK,
        title = "Location",
        severity = Severity.NOTICE,
        explanation = "With Location on, every app you allowed can see where you are, and the phone's " +
            "location services may keep collecting Wi-Fi and cell data in the background. Turning it off " +
            "when you don't need it is the simplest way to stop being tracked.",
        remediation = Remediation(
            text = "Turn Location off in Quick Settings when you don't need it. Under Settings › Location › " +
                "App location permissions, keep \"Allow all the time\" only for apps that really need it.",
            settingsActions = listOf(SettingsActions.LOCATION),
        ),
        failsWhen = "Location is on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val location = radios.locationEnabled()
        val evidence = listOf(location.toEvidence("Location") { if (it) "on" else "off" })
        return location.evaluate("Location", evidence) { on ->
            if (on) Outcome.fail("Location is on", evidence) else Outcome.pass("Location is off", evidence)
        }
    }
}
