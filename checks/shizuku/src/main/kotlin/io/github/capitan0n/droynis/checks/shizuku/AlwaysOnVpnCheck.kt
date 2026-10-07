package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.NOT_SET
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.SwitchState
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.checks.base.settingEvidence
import io.github.capitan0n.droynis.checks.base.switchState
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class AlwaysOnVpnCheck(
    private val settings: SystemSettings,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3201",
        category = Category.NETWORK,
        title = "Always-on VPN lockdown",
        severity = Severity.NOTICE,
        explanation = "An always-on VPN starts with the phone and stays connected. Only with \"Block " +
            "connections without VPN\" does traffic also stop while the VPN is down or reconnecting; " +
            "without it, apps quietly use the normal network. Apps can't see which app is the always-on " +
            "VPN, but the shell user Shizuku runs as can.",
        remediation = Remediation(
            text = "Open Settings › Network & internet › VPN, tap the gear next to your VPN, and turn on " +
                "both \"Always-on VPN\" and \"Block connections without VPN\".",
            settingsActions = listOf(SettingsActions.VPN),
        ),
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "an always-on VPN lets traffic out while it is down",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val app = settings.secure(ALWAYS_ON_VPN_APP)
        val lockdown = settings.secure(ALWAYS_ON_VPN_LOCKDOWN)
        val evidence = listOf(
            app.toEvidence(ALWAYS_ON_VPN_APP) { pkg -> pkg?.let { "${packages.label(it)} ($it)" } ?: NOT_SET },
            lockdown.settingEvidence(ALWAYS_ON_VPN_LOCKDOWN),
        )
        return app.evaluate("The always-on VPN app", evidence) { pkg ->
            if (pkg.isNullOrBlank()) return@evaluate Outcome.unsupported("No always-on VPN is set", evidence)
            val name = packages.label(pkg.trim())
            lockdown.evaluate("The VPN lockdown switch", evidence) { raw ->
                when (switchState(raw)) {
                    SwitchState.ON -> Outcome.pass("$name is always on and blocks connections without the VPN", evidence)
                    // Android treats an unset switch as off.
                    SwitchState.OFF, SwitchState.UNSET ->
                        Outcome.fail("$name is always on, but traffic bypasses it while the VPN is down", evidence)
                    SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$raw\" for $ALWAYS_ON_VPN_LOCKDOWN", evidence)
                }
            }
        }
    }

    companion object {
        /** `Settings.Secure.ALWAYS_ON_VPN_APP`: hidden, and not readable by apps (Android 17). */
        const val ALWAYS_ON_VPN_APP = "always_on_vpn_app"

        /** `Settings.Secure.ALWAYS_ON_VPN_LOCKDOWN`: hidden, but `@Readable` (Android 17). */
        const val ALWAYS_ON_VPN_LOCKDOWN = "always_on_vpn_lockdown"
    }
}
