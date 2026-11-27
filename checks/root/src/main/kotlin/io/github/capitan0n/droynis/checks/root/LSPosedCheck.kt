package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

class LSPosedCheck(private val root: RootShellProbe, private val packages: PackageInventory) : Check {
    override val spec = CheckSpec(
        id = "APPS-4304",
        category = Category.APPS,
        title = "LSPosed modules and their scope",
        severity = Severity.INFO,
        explanation = "LSPosed lets a module change how selected apps or the Android framework behave. " +
            "This lists the saved selections for this profile. The LSPosed policy test checks one rule the framework needs. " +
            "Android's SELinux enforcement has its own check.",
        remediation = Remediation("Open LSPosed › Modules, select a module and review its selected apps. " +
            "If the LSPosed policy test fails, check the activation message on LSPosed's Overview screen."),
        requires = setOf(Grant.ROOT),
        timeout = 25.seconds,
        failsWhen = "LSPosed's policy test denies the required rule (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val read = root.lsposed()
        return read.evaluate("LSPosed", if (read is Reading.Value) emptyList() else listOf(read.toEvidence("LSPosed"))) { raw ->
            val lines = raw.trimEnd('\n', '\r').lines()
            val policy = lines.first().removePrefix("policy=")
            if (policy !in setOf("allowed", "denied", "unknown", "disabled") || lines.first() != "policy=$policy" || lines.last() != "end") {
                return@evaluate Outcome.unknown("Could not read the LSPosed configuration")
            }
            val evidence = mutableListOf(Evidence("LSPosed policy test", when (policy) {
                "allowed" -> "required rule allowed"
                "denied" -> "required rule denied"
                "disabled" -> "skipped (framework configured as disabled)"
                else -> null
            }, read.source, note = "LSPosed checks whether dex2oat may execute its binary without a domain transition"))
            val rows = lines.drop(1).dropLast(1)
            val modules = linkedMapOf<String, MutableList<String>>()
            val complete = rows != listOf("inventory=unknown")
            if (complete) {
                for (row in rows) {
                    val fields = row.split('\t')
                    if (fields.size != 3 || fields[0] != "module" || !PACKAGE.matches(fields[1]) ||
                        (fields[2].isNotEmpty() && !PACKAGE.matches(fields[2]))) {
                        return@evaluate Outcome.unknown("Unexpected LSPosed scope data", evidence)
                    }
                    val targets = modules.getOrPut(fields[1]) { mutableListOf() }
                    if (fields[2].isNotEmpty()) targets += fields[2]
                }
                modules.forEach { (pkg, targets) ->
                    val scope = targets.map {
                        if (it == "system") "System Framework ($it)"
                        else appName(it)
                    }
                    evidence += Evidence("Enabled module", appName(pkg), read.source,
                        note = if (scope.isEmpty()) "no targets selected for this profile" else "Selected: ${scope.joinToString()}",
                        packageName = pkg)
                }
            } else {
                evidence += Evidence("Enabled modules", null, read.source, note = "scope database unreadable or unsupported")
            }
            val summary = if (complete) "${count(modules.size, "enabled LSPosed module")} in this configuration"
                else "Could not read the LSPosed module list"
            when {
                policy == "denied" -> Outcome.fail("$summary. LSPosed's policy test failed", evidence)
                !complete || policy == "unknown" -> Outcome.unknown("$summary. " +
                    if (policy == "unknown") "LSPosed's policy test was unavailable" else "See policy details", evidence)
                else -> Outcome.pass(summary, evidence)
            }
        }
    }

    private fun appName(pkg: String): String = packages.label(pkg).let { if (it == pkg) pkg else "$it ($pkg)" }

    companion object {
        val PACKAGE = Regex("""[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*""")
    }
}
