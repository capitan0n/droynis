package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.BaseProbes
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.checks.root.RootProbes
import io.github.capitan0n.droynis.checks.root.rootChecks
import io.github.capitan0n.droynis.checks.shizuku.ShizukuProbes
import io.github.capitan0n.droynis.checks.shizuku.shizukuChecks
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.adbGrantCommand
import io.github.capitan0n.droynis.report.HardeningIndex
import java.io.File
import java.lang.reflect.Proxy
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/**
 * docs/CHECKS.md is generated from the check specs, so it can't drift from the app. After adding
 * or changing a check, regenerate it with `UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test`.
 */
class CatalogDocTest {

    @Test
    fun `docs CHECKS md matches the check specs`() {
        val file = File(System.getProperty("droynis.checksDoc") ?: "../docs/CHECKS.md")
        val expected = CatalogDoc.render(allSpecs())
        if (System.getenv("UPDATE_CHECKS_DOC") == "1") file.writeText(expected)

        assertTrue(file.exists(), "${file.path} is missing; $HOW_TO_UPDATE")
        assertEquals(expected, file.readText(), "${file.path} is out of date; $HOW_TO_UPDATE")
    }

    @Test
    fun `every check says when it fails`() {
        val missing = allSpecs().filter { it.failsWhen.isBlank() }.map { it.id }
        assertEquals(emptyList(), missing, "set CheckSpec.failsWhen for these checks")
    }

    @Test
    fun `anchors follow GitHub's heading slugs`() {
        assertEquals(
            "apps-4101-background-camera-microphone-and-location-use",
            CatalogDoc.anchor("APPS-4101 Background camera, microphone and location use"),
        )
        assertEquals("netw-3009-wi-fi-and-bluetooth-scanning", CatalogDoc.anchor("NETW-3009 Wi-Fi and Bluetooth scanning"))
    }

    private companion object {
        const val HOW_TO_UPDATE = "run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test"

        /** Every registry, built with probes nothing calls: a spec is a plain value. */
        fun allSpecs(): List<CheckSpec> =
            (
                baseChecks(unused<BaseProbes>()) + adbChecks(unused<AdbProbes>()) +
                    shizukuChecks(unused<ShizukuProbes>()) + rootChecks(unused<RootProbes>())
                ).map { it.spec }

        inline fun <reified T : Any> unused(): T = T::class.java.cast(unusedProbe(T::class.java))

        /** A probe that hands out more such probes and fails on any real call. */
        fun unusedProbe(type: Class<*>): Any = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, _ ->
            if (method.returnType.isInterface) unusedProbe(method.returnType) else error("a check called ${method.name} while being built")
        }
    }
}

/** Renders the check catalog as Markdown: an overview per tier, then every check in full. */
object CatalogDoc {

    private const val APP_ID = "io.github.capitan0n.droynis"

    private val INTRO = mapOf(
        Tier.BASE to "Public Android APIs only. These checks run on every phone, with no setup and no extra permissions.",
        Tier.ADB to "Two read-only permissions, granted once from a computer with adb, unlock checks that public " +
            "Android APIs can't do. Until then these checks show as N/A and don't change the score. The " +
            "Shizuku tier covers them too, without the grants.",
        Tier.SHIZUKU to "[Shizuku](https://github.com/RikkaApps/Shizuku) is an open-source app that gives other apps " +
            "the rights adb has, without a computer once it runs. Through it Droynis starts a small shell that " +
            "runs only a fixed list of read-only commands. It reads what Android hides from apps, such as the " +
            "real USB debugging state on Android 17, and also runs every ADB-tier check.",
        Tier.ROOT to "For phones that are already rooted. Once you turn it on, Droynis asks the root manager " +
            "(Magisk, KernelSU, APatch…) for a root shell at each scan and runs only a fixed list of read-only " +
            "commands. Root also runs every ADB and Shizuku check. Rooting weakens Android's security model, so " +
            "don't root a phone just to audit it; root access (INTG-1050) stays a critical finding.",
    )

    private val ANDROID = mapOf(
        26 to "8.0", 27 to "8.1", 28 to "9", 29 to "10", 30 to "11", 31 to "12", 32 to "12L",
        33 to "13", 34 to "14", 35 to "15", 36 to "16", 37 to "17",
    )

    fun render(specs: List<CheckSpec>): String = buildString {
        val byTier = specs.groupBy { it.requiredTier }
        appendLine("# Droynis checks")
        appendLine()
        appendLine("<!-- Generated from the check definitions by CatalogDocTest. Don't edit by hand: after")
        appendLine("     changing a check, run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test -->")
        appendLine()
        appendLine("Every check Droynis runs, by privilege tier and category: ${specs.size} checks.")
        appendLine()
        val weights = Severity.entries.sortedDescending().joinToString { "${it.name.lowercase()} ${HardeningIndex.weight(it)}" }
        appendLine("A check passes only after reading a passing value; anything it can't establish is Unknown or")
        appendLine("N/A, never Passed.")
        appendLine()
        appendLine("Severity sets a failed check's weight in the score: $weights.")
        appendLine("Any critical failure caps the score at ${HardeningIndex.CRITICAL_CAP}, and muted checks don't count.")
        appendLine()
        appendLine("| Tier | Checks |")
        appendLine("|---|---|")
        for (tier in Tier.entries) {
            val count = byTier[tier]?.size ?: 0
            val name = tierName(tier)
            appendLine(if (count == 0) "| $name | planned |" else "| [$name](#${anchor("$name tier")}) | $count |")
        }

        for (tier in Tier.entries) {
            val inTier = byTier[tier].orEmpty()
            appendLine()
            appendLine("## ${tierName(tier)} tier")
            appendLine()
            appendLine(INTRO.getValue(tier))
            if (tier == Tier.ADB) appendSetup(inTier)
            if (tier == Tier.SHIZUKU && inTier.isNotEmpty()) appendShizukuSetup()
            if (tier == Tier.ROOT && inTier.isNotEmpty()) appendRootSetup()
            if (inTier.isEmpty()) continue

            appendLine()
            appendLine("| ID | Check | Severity | Fails when |")
            appendLine("|---|---|---|---|")
            // Same order as the sections below: by category, then by id.
            for (spec in inTier.sortedWith(compareBy({ it.category.ordinal }, { it.id }))) {
                val since = if (spec.minSdk > CheckSpec.MIN_SDK) " (Android ${android(spec.minSdk)}+)" else ""
                appendLine(
                    "| [${spec.id}](#${anchor(heading(spec))}) | ${spec.title}$since | ${severity(spec.severity)} | " +
                        "${spec.failsWhen} |",
                )
            }
            for (category in Category.entries) {
                val inCategory = inTier.filter { it.category == category }.sortedBy { it.id }
                if (inCategory.isEmpty()) continue
                appendLine()
                appendLine("### ${category.label}")
                for (spec in inCategory) appendCheck(spec)
            }
        }
    }.trimEnd() + "\n"

    /** GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens. */
    fun anchor(heading: String): String = heading.lowercase().replace(Regex("[^a-z0-9 _-]"), "").replace(' ', '-')

    private fun StringBuilder.appendSetup(specs: List<CheckSpec>) {
        val commands = specs.flatMap { it.requires }.filter { it.tier == Tier.ADB }.distinct()
            .mapNotNull { it.adbGrantCommand(APP_ID) }
        if (commands.isEmpty()) return
        appendLine()
        appendLine("Turn on USB debugging, connect the phone to a computer with adb, run:")
        appendLine()
        appendLine("```sh")
        commands.forEach { appendLine(it) }
        appendLine("```")
        appendLine()
        appendLine("Then tap Scan again. The grants stay until `adb shell pm revoke …` or an uninstall.")
    }

    private fun StringBuilder.appendShizukuSetup() {
        appendLine()
        appendLine("1. Install Shizuku and start it: with Wireless debugging on Android 11 and later, or from a")
        appendLine("   computer with adb. Shizuku's own guide shows each step.")
        appendLine("2. In Droynis open ⋮ › Check catalog › Shizuku and tap Allow access.")
        appendLine("3. Tap Scan again. After a reboot, start Shizuku again; to take access back, turn Droynis off in")
        appendLine("   Shizuku's list of authorized apps.")
    }

    private fun StringBuilder.appendRootSetup() {
        appendLine()
        appendLine("1. In Droynis open ⋮ › Check catalog › Root and tap Allow root access.")
        appendLine("2. Allow Droynis when the root manager asks. Droynis scans again by itself.")
        appendLine("3. To stop, tap Turn off in the same tab, and revoke Droynis in the root manager's Superuser list.")
    }

    private fun StringBuilder.appendCheck(spec: CheckSpec) {
        appendLine()
        appendLine("#### ${heading(spec)}")
        appendLine()
        appendLine("${severity(spec.severity)} · Android ${android(spec.minSdk)} and later · fails when ${spec.failsWhen}")
        appendLine()
        appendLine(spec.explanation)
        appendLine()
        appendLine("**What to do:** ${spec.remediation.text}")
    }

    private fun heading(spec: CheckSpec) = "${spec.id} ${spec.title}"

    private fun tierName(tier: Tier) = when (tier) {
        Tier.BASE -> "Base"
        Tier.ADB -> "ADB"
        Tier.SHIZUKU -> "Shizuku"
        Tier.ROOT -> "Root"
    }

    private fun severity(severity: Severity) = severity.name.lowercase().replaceFirstChar { it.uppercase() }

    private fun android(sdk: Int) = ANDROID[sdk] ?: "API $sdk"
}
