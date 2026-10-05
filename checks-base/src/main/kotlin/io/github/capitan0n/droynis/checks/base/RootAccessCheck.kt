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

class RootAccessCheck(
    private val files: FileProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1050",
        category = Category.DEVICE_INTEGRITY,
        title = "Root access",
        severity = Severity.CRITICAL,
        explanation = "Root lets any app you approve read every other app's data, log what you type and " +
            "hide itself from the system. It also switches off much of Android's app sandbox. Root can be " +
            "hidden, so a clean result means no signs were found, not that the phone cannot be rooted.",
        remediation = Remediation(
            text = "If you did not root this phone yourself, back up your data and reinstall the official " +
                "firmware. If you did, remove the root manager when you no longer need it and grant root only " +
                "to apps you trust.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Only looks: never runs su, which would pop up a root prompt.
        val suFiles = files.existing(SU_PATHS)
        val apps = packages.installedApps()
        val found = (suFiles as? Reading.Value)?.value.orEmpty()
        val rootApps = (apps as? Reading.Value)?.value.orEmpty().filter { it.packageName in ROOT_APPS }
        val evidence = buildList {
            add(suFiles.toEvidence("su binaries") { if (it.isEmpty()) "none of ${SU_PATHS.size} known paths" else it.joinToString() })
            if (apps !is Reading.Value) add(apps.toEvidence("Installed apps"))
            rootApps.forEach {
                add(Evidence("Root or hooking app", "${packages.label(it.packageName)} (${it.packageName})", apps.source))
            }
        }
        val signs = found.map { "su at $it" } + rootApps.map { "${packages.label(it.packageName)} installed" }
        return when {
            signs.isNotEmpty() -> Outcome.fail("Signs of root: ${signs.joinNames()}", evidence)
            suFiles is Reading.Value && apps is Reading.Value -> Outcome.pass("No signs of root were found", evidence)
            else -> Outcome.unknown("Not every root indicator could be read", evidence)
        }
    }

    companion object {
        val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/system/bin/failsafe/su",
            "/sbin/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
        )

        /** Root managers and the hooking frameworks that need root. */
        val ROOT_APPS = setOf(
            "com.topjohnwu.magisk", // Magisk
            "io.github.vvb2060.magisk", // Magisk Alpha
            "io.github.huskydg.magisk", // Kitsune Mask
            "me.weishu.kernelsu", // KernelSU
            "com.rifsxd.ksunext", // KernelSU Next
            "me.bmax.apatch", // APatch
            "eu.chainfire.supersu", // SuperSU
            "com.koushikdutta.superuser", // Superuser
            "com.noshufou.android.su", // Superuser (ChainsDD)
            "com.kingroot.kinguser", // KingRoot
            "com.kingo.root", // Kingo Root
            "de.robv.android.xposed.installer", // Xposed
            "org.meowcat.edxposed.manager", // EdXposed
            "org.lsposed.manager", // LSPosed
        )
    }
}
