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
        val file = File(System.getProperty("droynis.checksDoc") ?: "../../docs/CHECKS.md")
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
    fun `a moved check's old id is retired and its new id exists`() {
        val ids = allSpecs().map { it.id }.toSet()
        for ((old, new) in CheckSpec.RENAMED) {
            assertTrue(old !in ids, "$old was retired and must not be reused")
            assertTrue(new in ids, "$old moved to $new, which no check has")
        }
    }

    @Test
    fun `the adb registry is grouped by category`() {
        val order = adbChecks(unused<AdbProbes>()).map { it.spec.category.ordinal }
        assertEquals(order.sorted(), order)
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

/**
 * Renders the check catalog as Markdown: the tier counts, then one table per category. Each check's
 * full explanation and fix live in the app, so the file stays short enough to skim.
 */
object CatalogDoc {

    private val ANDROID = mapOf(
        26 to "8.0", 27 to "8.1", 28 to "9", 29 to "10", 30 to "11", 31 to "12", 32 to "12L",
        33 to "13", 34 to "14", 35 to "15", 36 to "16", 37 to "17",
    )

    fun render(specs: List<CheckSpec>): String = buildString {
        val byCategory = specs.groupBy { it.category }
        val categories = Category.entries.filter { byCategory[it].orEmpty().isNotEmpty() }
        val weights = Severity.entries.sortedDescending().joinToString { "${it.name.lowercase()} ${HardeningIndex.weight(it)}" }
        appendLine("# Droynis checks")
        appendLine()
        appendLine("<!-- Generated from the check definitions by CatalogDocTest. Don't edit by hand: after")
        appendLine("     changing a check, run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test -->")
        appendLine()
        appendLine("${specs.size} checks. Each one's full explanation and fix are in the app: tap the check.")
        appendLine()
        appendLine("- A check passes only on a value it read; otherwise it is Unknown or N/A, never Passed.")
        appendLine("- A failure weighs by severity ($weights); any critical failure caps the score at ${HardeningIndex.CRITICAL_CAP}.")
        appendLine("- Higher tiers need setup ([README](../README.md#tiers)) and also run every check of the tiers before them.")
        appendLine()
        appendLine("| Category | " + Tier.entries.joinToString(" | ") { tierName(it) } + " | All |")
        appendLine("|---|" + "---|".repeat(Tier.entries.size) + "---|")
        for (category in categories) {
            val inCategory = byCategory.getValue(category)
            appendLine(
                "| [${category.label}](#${anchor(category.label)}) | " +
                    Tier.entries.joinToString(" | ") { tier -> count(inCategory.count { it.requiredTier == tier }) } +
                    " | ${inCategory.size} |",
            )
        }
        appendLine(
            "| **All** | " + Tier.entries.joinToString(" | ") { tier -> count(specs.count { it.requiredTier == tier }) } +
                " | ${specs.size} |",
        )

        for (category in categories) {
            val inCategory = byCategory.getValue(category).sortedWith(compareBy({ it.requiredTier.ordinal }, { it.id }))
            appendLine()
            appendLine("## ${category.label}")
            appendLine()
            appendLine("| ID | Check | Tier | Severity | Fails when |")
            appendLine("|---|---|---|---|---|")
            for (spec in inCategory) {
                val since = if (spec.minSdk > CheckSpec.MIN_SDK) " (Android ${android(spec.minSdk)}+)" else ""
                appendLine(
                    "| ${spec.id} | ${spec.title}$since | ${tierName(spec.requiredTier)} | ${severity(spec.severity)} | " +
                        "${spec.failsWhen} |",
                )
            }
        }
    }.trimEnd() + "\n"

    /** GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens. */
    fun anchor(heading: String): String = heading.lowercase().replace(Regex("[^a-z0-9 _-]"), "").replace(' ', '-')

    private fun count(n: Int) = if (n == 0) "–" else "$n"

    private fun tierName(tier: Tier) = when (tier) {
        Tier.BASE -> "Base"
        Tier.ADB -> "ADB"
        Tier.SHIZUKU -> "Shizuku"
        Tier.ROOT -> "Root"
    }

    private fun severity(severity: Severity) = severity.name.lowercase().replaceFirstChar { it.uppercase() }

    private fun android(sdk: Int) = ANDROID[sdk] ?: "API $sdk"
}
