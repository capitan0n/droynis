package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/** A Magisk, KernelSU or APatch module from `/data/adb/modules`. */
data class RootModule(
    /** The module's directory name, which is its id. */
    val id: String,
    val name: String,
    val version: String?,
    val author: String?,
    /** False when the user disabled it; it then does nothing after the next reboot. */
    val enabled: Boolean,
    /** Marked for removal at the next reboot. */
    val removing: Boolean,
)

/**
 * Reads the module listing the platform's fixed script prints: for each directory in
 * `/data/adb/modules`, a `@@module <id>` line, `@@disabled` and `@@remove` when those marker files
 * exist, then the module's `module.prop` (`key=value` lines).
 */
object RootModules {

    const val MODULE = "@@module "
    const val DISABLED = "@@disabled"
    const val REMOVE = "@@remove"

    sealed interface Result {
        data class Parsed(val modules: List<RootModule>) : Result

        data class Failed(val reason: String) : Result
    }

    private class Builder(val id: String) {
        var disabled = false
        var removing = false
        val props = mutableMapOf<String, String>()

        fun build() = RootModule(
            id = id,
            name = props["name"]?.takeIf { it.isNotBlank() } ?: id,
            version = props["version"]?.takeIf { it.isNotBlank() },
            author = props["author"]?.takeIf { it.isNotBlank() },
            enabled = !disabled,
            removing = removing,
        )
    }

    fun parse(text: String): Result {
        val modules = mutableListOf<Builder>()
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            if (line.startsWith(MODULE.trim())) {
                val id = line.removePrefix(MODULE.trim()).trim()
                if (id.isEmpty()) return Result.Failed("a module without a name")
                modules += Builder(id)
                continue
            }
            // Anything before the first module header means the listing is not ours.
            val current = modules.lastOrNull() ?: return Result.Failed("output before the first module")
            when {
                line == DISABLED -> current.disabled = true
                line == REMOVE -> current.removing = true
                line.startsWith("#") -> Unit
                '=' in line -> current.props.putIfAbsent(line.substringBefore('=').trim(), line.substringAfter('=').trim())
            }
        }
        return Result.Parsed(modules.map { it.build() })
    }
}

class RootModulesCheck(private val root: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1301",
        category = Category.DEVICE_INTEGRITY,
        title = "Root modules",
        severity = Severity.INFO,
        explanation = "Magisk, KernelSU and APatch modules change the system at every boot, with full " +
            "root rights and before any app or security setting can stop them. Each one is code you " +
            "trust completely. This check lists them for your review and doesn't count in the score.",
        remediation = Remediation(
            text = "Open your root manager's Modules screen and remove modules you no longer use or " +
                "don't fully trust. Install modules only from their authors' own pages.",
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "an enabled root module is installed (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val listing = root.modules()
        val text = when (listing) {
            is Reading.Value -> listing.value
            is Reading.Unsupported -> return Outcome.unsupported(
                "Root modules are not available here (${listing.reason})",
                listOf(listing.toEvidence("Modules")),
            )
            is Reading.Unavailable -> return Outcome.unknown(
                "The module list could not be read (${listing.reason})",
                listOf(listing.toEvidence("Modules")),
            )
        }
        val modules = when (val parsed = RootModules.parse(text)) {
            is RootModules.Result.Failed -> return Outcome.unknown(
                "The module list is in a format Droynis doesn't recognize (${parsed.reason})",
                listOf(Evidence("Modules", null, listing.source, note = parsed.reason)),
            )
            is RootModules.Result.Parsed -> parsed.modules
        }
        val evidence = listOf(Evidence("Modules installed", modules.size.toString(), listing.source)) +
            modules.map { module ->
                Evidence(
                    "Module",
                    listOfNotNull(module.name, module.version).joinToString(" ") + " (${module.id})",
                    listing.source,
                    note = listOfNotNull(
                        module.author?.let { "by $it" },
                        "disabled".takeIf { !module.enabled },
                        "removed at the next reboot".takeIf { module.removing },
                    ).joinToString(", ").ifEmpty { null },
                )
            }
        val active = modules.filter { it.enabled }
        if (active.isEmpty()) {
            val summary = if (modules.isEmpty()) "No root modules are installed" else "Every root module is disabled"
            return Outcome.pass(summary, evidence)
        }
        return Outcome.fail("${count(active.size, "root module")} active: ${active.map { it.name }.joinNames()}", evidence)
    }
}
