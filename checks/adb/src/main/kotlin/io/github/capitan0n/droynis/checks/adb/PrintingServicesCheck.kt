package io.github.capitan0n.droynis.checks.adb

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
import io.github.capitan0n.droynis.core.Trust
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

class PrintingServicesCheck(private val dumpsys: Dumpsys, private val packages: PackageInventory) : Check {
    override val spec = CheckSpec(
        id = "APPS-4110",
        category = Category.APPS,
        title = "Printing services",
        severity = Severity.INFO,
        explanation = "An enabled printing service can discover printers and handle documents you send " +
            "to it. This inventory shows installed plugins and their switches in this profile.",
        remediation = Remediation("Open Printing in Settings to turn off plugins you no longer use.",
            settingsActions = listOf("android.settings.ACTION_PRINT_SETTINGS")),
        minSdk = 28,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "never (inventory of installed printing services and their switches)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val user = context.appUid?.div(100_000) ?: return Outcome.unknown("Could not identify the scanned profile")
        val dump = dumpsys.dump("print")
        return dump.evaluate("Printing services", if (dump is Reading.Value) emptyList() else listOf(dump.toEvidence("Print manager"))) {
            val services = PrintServicesDump.parse(it, user)
                ?: return@evaluate Outcome.unknown("No complete print service inventory for this profile",
                    listOf(Evidence("Print manager", null, dump.source, note = "missing or unrecognized profile data")))
            val evidence = services.toSortedMap().map { (component, enabled) ->
                val pkg = component.substringBefore('/')
                Evidence(packages.label(pkg), component, dump.source, note = if (enabled) "enabled" else "disabled",
                    packageName = pkg, trust = Trust.NOT_COUNTED)
            }
            Outcome.pass("${count(services.size, "printing service")} installed, ${services.values.count { enabled -> enabled }} enabled", evidence)
        }
    }
}

/** AOSP DualDumpOutputStream uses name={...} for one record and name=[{...}, {...}] for several.
 * Follow direct children only: printer names, print jobs and records for other profiles are private.
 */
internal object PrintServicesDump {
    private val identifier = Regex("""[A-Za-z_][A-Za-z0-9_.$]*""")

    private class Block(val lines: List<String>, val indent: String) {
        fun fields(key: String) = lines.filter { it.startsWith(indent + key + "=") }

        fun records(key: String): List<Block>? {
            val headers = fields(key)
            if (headers.isEmpty()) return emptyList()
            val header = headers.singleOrNull() ?: return null
            val start = lines.indexOf(header)
            val tail = lines.subList(start + 1, lines.size)
            val end = tail.indexOfFirst { it.isNotBlank() && !it.startsWith(indent + " ") }
            if (end < 0) return null
            val body = tail.subList(0, end)
            val inner = body.firstOrNull()?.takeWhile { it == ' ' } ?: return null
            if (header == indent + key + "={" && tail[end] == indent + "}") return listOf(Block(body, inner))
            if (header != indent + key + "=[" || tail[end] != indent + "]") return null
            val result = mutableListOf<Block>()
            var i = 0
            while (i < body.size) {
                if (body[i++] != inner + "{") return null
                val from = i
                while (i < body.size && body[i].startsWith(inner + " ")) i++
                if (i == from || i == body.size || body[i++] != inner + "}") return null
                result += Block(body.subList(from, i - 1), body[from].takeWhile { it == ' ' })
            }
            return result
        }

        fun field(key: String): String? = fields(key).singleOrNull()?.substringAfter('=')
        fun component(): String? {
            val pkg = field("package_name")?.takeIf(identifier::matches) ?: return null
            val cls = field("class_name")?.takeIf(identifier::matches) ?: return null
            return "$pkg/$cls"
        }
    }

    fun parse(text: String, user: Int): Map<String, Boolean>? {
        val lines = dumpLines(text).filter { it.isNotBlank() }
        if (lines.size < 5 || lines[0] != "PRINT MANAGER STATE (dumpsys print)" ||
            lines[1] != "{" || lines.last() != "}") return null
        val root = Block(lines.subList(2, lines.lastIndex), lines[2].takeWhile { it == ' ' })
        val profile = root.records("user_states")?.singleOrNull { it.field("user_id") == user.toString() } ?: return null
        // AOSP always emits the spooler section after installed/disabled services.
        if (profile.fields("print_spooler_state").singleOrNull()?.endsWith("={") != true) return null
        val installed = profile.records("installed_services")?.map {
            it.records("component_name")?.singleOrNull()?.component() ?: return null
        } ?: return null
        val disabled = profile.records("disabled_services")?.map { it.component() ?: return null }?.toSet() ?: return null
        if (installed.size != installed.distinct().size) return null
        return installed.associateWith { it !in disabled }
    }
}
