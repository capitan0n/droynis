package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.PackageInventory
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

/**
 * Reads Quick Share's (formerly Nearby Share) visibility from Google Play services' private
 * SharedPreferences files, `shared_prefs/nearbysharing*.xml` of `com.google.android.gms`. The root
 * command prints each file after a [FILE] line. Play services is closed source and its keys and
 * numbers are not documented, so the parser takes only what holds across every version known:
 *
 * - The setting is an `<int>` or `<string>` entry whose name says "visibility", except the ones that
 *   hold a fallback, an expiry, a time or an earlier value ([COMPANION]). Entries that disagree, or
 *   any such entry in a shape the parser doesn't recognize, make the result unknown.
 * - As a number, 4 is Everyone: `DEVICE_VISIBILITY_EVERYONE` in Google's own Quick Share code
 *   (github.com/google/nearby, `sharing/proto/enums.proto`). 1, 2 and 3 are never Everyone, though
 *   they name different modes in different versions: Hidden, Your devices and All contacts there;
 *   All contacts, Some contacts and Hidden in 2020's Play services. Other numbers are unknown.
 * - As text, the enum's name, with or without its `DEVICE_VISIBILITY_` prefix.
 *
 * Only the parsed setting is kept. The files also hold the device's name and account data, which
 * never leave this parser.
 */
object QuickSharePrefs {

    /** Starts each file in the root command's output, followed by the file's name. */
    const val FILE = "@@file "

    enum class Visibility(val label: String, val everyone: Boolean) {
        EVERYONE("Everyone", true),
        CONTACTS("Contacts", false),
        SOME_CONTACTS("Some contacts", false),
        YOUR_DEVICES("Your devices", false),
        NO_ONE("No one", false),

        /** A number that is never Everyone, but names a different mode in each Play services version. */
        NOT_EVERYONE("not Everyone", false),
    }

    /** One visibility entry: its file and key, the stored value, and what it means; null when unknown. */
    data class Setting(val file: String, val key: String, val stored: String, val visibility: Visibility?)

    data class PrefsFile(
        val name: String,
        /** Every key in the file, for a report when no setting is found. */
        val keys: List<String>,
        val settings: List<Setting>,
        /** Keys next to the setting: its fallback, expiry or earlier value. */
        val companions: List<String>,
    )

    sealed interface Result {
        data class Parsed(val files: List<PrefsFile>) : Result

        data class Failed(val reason: String) : Result
    }

    /** Name parts that mark a key as holding something other than the setting in force. */
    val COMPANION = listOf("fallback", "expir", "time", "millis", "seconds", "last", "previous", "default", "initial", "original")

    private val NAME = Regex("""[A-Za-z0-9_.:@+-]{1,200}\.xml""")
    private val NAMED = Regex("""<(\w+)\s+name="([^"]*)"""")
    private val ANY_NAMED = Regex("""<\w+\b[^<>]*\bname\s*=""")
    private val INT = Regex("""<int\s+name="([^"]*)"\s+value="(-?\d{1,10})"\s*/>""")
    private val STRING = Regex("""<string\s+name="([^"]*)">([^<]*)</string>""")
    private val EMPTY_MAP = Regex("""<map\s*/>""")

    fun parse(output: String): Result {
        val chunks = mutableListOf<Pair<String, StringBuilder>>()
        for (line in output.lineSequence()) {
            when {
                line.startsWith(FILE) -> chunks += line.removePrefix(FILE) to StringBuilder()
                chunks.isEmpty() -> if (line.isNotBlank()) return Result.Failed("text before the first file")
                else -> chunks.last().second.appendLine(line)
            }
        }
        val names = chunks.map { it.first }
        if (names.size != names.toSet().size) return Result.Failed("a file appears twice")
        return Result.Parsed(chunks.map { (name, text) -> file(name, text.toString().trim()) ?: return Result.Failed("$name is in an unknown shape") })
    }

    private fun file(name: String, text: String): PrefsFile? {
        if (!NAME.matches(name)) return null
        // A whole file only: a cut one may have lost the entry that matters.
        val empty = EMPTY_MAP.containsMatchIn(text)
        if (!empty && (!text.contains("<map>") || !text.endsWith("</map>"))) return null
        if (empty && NAMED.containsMatchIn(text)) return null

        val named = NAMED.findAll(text).map { it.groupValues[1] to it.groupValues[2] }.toList()
        // Every entry, whatever the order of its attributes, or one could go unseen.
        if (ANY_NAMED.findAll(text).count() != named.size) return null
        val keys = named.map { it.second }
        if (keys.size != keys.toSet().size) return null
        val ints = INT.findAll(text).associate { it.groupValues[1] to it.groupValues[2] }
        val strings = STRING.findAll(text).associate { it.groupValues[1] to it.groupValues[2] }

        val settings = mutableListOf<Setting>()
        val companions = mutableListOf<String>()
        for ((type, key) in named) {
            val lower = key.lowercase()
            if ("visibility" !in lower) continue
            if (COMPANION.any { it in lower }) {
                companions += key
                continue
            }
            settings += when (type) {
                // An entry the patterns can't take apart must never be skipped: it may be the one in force.
                "int" -> (ints[key] ?: return null).let { Setting(name, key, it, number(it)) }
                "string" -> (strings[key] ?: return null).let { Setting(name, key, it, text(it)) }
                else -> continue
            }
        }
        return PrefsFile(name, keys, settings, companions)
    }

    private fun number(value: String): Visibility? = when (value.toIntOrNull()) {
        4 -> Visibility.EVERYONE
        1, 2, 3 -> Visibility.NOT_EVERYONE
        else -> null
    }

    private fun text(value: String): Visibility? {
        val name = value.trim().uppercase().removePrefix("DEVICE_VISIBILITY_").removePrefix("VISIBILITY_")
        return when (name) {
            "EVERYONE" -> Visibility.EVERYONE
            "ALL_CONTACTS", "CONTACTS" -> Visibility.CONTACTS
            "SELECTED_CONTACTS", "SOME_CONTACTS" -> Visibility.SOME_CONTACTS
            "SELF_SHARE", "YOUR_DEVICES" -> Visibility.YOUR_DEVICES
            "HIDDEN", "NO_ONE" -> Visibility.NO_ONE
            else -> if (name.all { it.isDigit() } && name.isNotEmpty()) number(name) else null
        }
    }
}

/**
 * Quick Share's device visibility (formerly Nearby Share). Google's Quick Share lives in Play services,
 * which keeps the setting in its private files, so only root can read it ([QuickSharePrefs]). Samsung's
 * Quick Share app keeps its own setting, which Droynis can't read: with it installed, only a Google
 * setting of Everyone is a result.
 */
class QuickShareCheck(
    private val root: RootShellProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3302",
        category = Category.NETWORK,
        title = "Quick Share visibility",
        severity = Severity.NOTICE,
        explanation = "Quick Share (formerly Nearby Share) set to Everyone shows this phone's name to every " +
            "phone and computer in Bluetooth and Wi-Fi range and lets them offer it files. Each transfer still " +
            "asks first, but flaws such as SafeBreach's QuickShell (2024) got files through without asking, " +
            "so Everyone is safest only for the few minutes you receive from someone new.",
        remediation = Remediation(
            text = "Open Quick Share's settings: Settings › Connected devices › Connection preferences › Quick " +
                "Share, or Settings › Google › All services › Quick Share; on Samsung, Settings › Connected " +
                "devices › Quick Share. Set Device visibility (Who can share with you) to Contacts or Your " +
                "devices, and pick Everyone for 10 minutes only when you need it.",
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "Quick Share (Nearby Share) is visible to everyone nearby",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val installed = packages.installedApps()
        val apps = (installed as? Reading.Value)?.value?.associateBy { it.packageName }
        val google = apps == null || apps[GMS]?.isEnabled == true
        val samsung = apps?.get(SAMSUNG)?.takeIf { it.isEnabled }
        val samsungEvidence = listOfNotNull(
            samsung?.let {
                Evidence(
                    "Samsung Quick Share",
                    "installed",
                    installed.source,
                    note = "keeps its own visibility setting, which Droynis can't read",
                    packageName = SAMSUNG,
                )
            },
        )
        if (!google && samsung == null) {
            val off = apps?.get(GMS) != null
            return Outcome.unsupported(
                if (off) "Google Play services is turned off and Samsung's Quick Share isn't installed" else "No Quick Share app is installed",
                listOf(Evidence("Google Play services", if (off) "turned off" else "not installed", installed.source)),
            )
        }
        if (!google) {
            return Outcome.unknown("Samsung's Quick Share keeps its visibility where Droynis can't read it", samsungEvidence)
        }

        val read = root.quickShareSettings()
        if (read !is Reading.Value) {
            return Outcome.unknown("Quick Share's settings could not be read", listOf(read.toEvidence("Quick Share settings")) + samsungEvidence)
        }
        val output = read.value ?: return Outcome.unknown(
            "Google Play services keeps no settings for this user",
            listOf(Evidence("Play services settings folder", null, read.source, note = "it doesn't exist")) + samsungEvidence,
        )
        val files = when (val result = QuickSharePrefs.parse(output)) {
            is QuickSharePrefs.Result.Failed -> return Outcome.unknown(
                "Quick Share's settings are in a format Droynis doesn't recognize",
                listOf(Evidence("Quick Share settings", null, read.source, note = result.reason)) + samsungEvidence,
            )
            is QuickSharePrefs.Result.Parsed -> result.files
        }
        if (files.isEmpty()) {
            return Outcome.unknown(
                "Quick Share has no settings file: open its settings once, then scan again",
                listOf(Evidence("Quick Share settings files", "none", read.source)) + samsungEvidence,
            )
        }

        val settings = files.flatMap { it.settings }
        val where = Evidence(
            "Read from",
            files.joinToString { it.name },
            read.source,
            // File and key names may carry an account.
            note = settings.joinToString { it.key }.ifEmpty { "keys: " + files.flatMap { it.keys }.take(MAX_KEYS).joinToString() },
            personal = true,
        )
        if (settings.isEmpty()) {
            return Outcome.unknown("Quick Share's visibility isn't where Droynis looks for it", listOf(where) + samsungEvidence)
        }
        val evidence = settings.map { setting ->
            Evidence("Device visibility", setting.visibility?.label, read.source, note = "stored as ${setting.stored}")
        } + where + samsungEvidence
        if (settings.any { it.visibility == null }) {
            return Outcome.unknown("Quick Share's visibility is stored as a value Droynis doesn't know", evidence)
        }
        val everyone = settings.map { it.visibility!!.everyone }.toSet()
        if (everyone.size > 1) {
            return Outcome.unknown("Quick Share's settings disagree about its visibility", evidence)
        }
        if (everyone.single()) {
            val timed = files.any { file -> file.companions.any { "expir" in it.lowercase() } }
            return Outcome.fail(
                "Quick Share is visible to everyone nearby",
                if (timed) evidence + Evidence("Everyone", "may be temporary", read.source, note = "the 10-minute mode switches back by itself") else evidence,
            )
        }
        if (samsung != null) {
            return Outcome.unknown(
                "Google's Quick Share isn't visible to everyone, but Samsung's keeps its own setting, which Droynis can't read",
                evidence,
            )
        }
        if (apps == null) {
            return Outcome.unknown(
                "Google's Quick Share isn't visible to everyone, but Droynis couldn't check for Samsung's",
                evidence + installed.toEvidence("Installed apps") { "${it.size}" },
            )
        }
        return Outcome.pass(summary(settings.mapNotNull { it.visibility }.toSet()), evidence)
    }

    private fun summary(modes: Set<QuickSharePrefs.Visibility>): String = when (modes.singleOrNull()) {
        QuickSharePrefs.Visibility.CONTACTS -> "Quick Share is visible to your contacts only"
        QuickSharePrefs.Visibility.SOME_CONTACTS -> "Quick Share is visible to some of your contacts only"
        QuickSharePrefs.Visibility.YOUR_DEVICES -> "Quick Share is visible to your own devices only"
        QuickSharePrefs.Visibility.NO_ONE -> "Quick Share is hidden from everyone"
        else -> "Quick Share isn't visible to everyone nearby"
    }

    companion object {
        /** Google Play services, which holds Google's Quick Share. */
        const val GMS = "com.google.android.gms"

        /** Samsung's Quick Share app. */
        const val SAMSUNG = "com.samsung.android.app.sharelive"

        private const val MAX_KEYS = 40
    }
}
