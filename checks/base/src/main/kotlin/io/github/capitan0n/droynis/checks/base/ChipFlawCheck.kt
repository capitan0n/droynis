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
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence

/**
 * Whether the phone's chip is on a bundled list of published boot ROM flaws ([ChipFlawData]). The
 * chip comes from the public `Build` fields and a few system properties; a phone that names no chip
 * is UNKNOWN, and one that names only a platform several chips share is UNKNOWN too.
 */
class ChipFlawCheck(
    private val build: BuildInfo,
    private val properties: SystemProperties,
    private val keyguard: Keyguard,
    /** The list to match against; null for the bundled one. */
    private val flaws: ChipFlaws? = null,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1013",
        category = Category.DEVICE_INTEGRITY,
        title = "Chip with an unfixable boot flaw",
        severity = Severity.NOTICE,
        explanation = "The boot ROM is the first code a chip runs, burned into it at the factory, so no update " +
            "can change it. Researchers have published flaws in the boot ROMs of some chips that let someone with " +
            "the phone in hand, a USB cable and for some flaws lab equipment, run their own code before Android " +
            "starts, past verified boot and the secure area that guards your keys. Each attack restarts the phone, " +
            "so your data stays locked behind the screen lock, which they can then try to guess, possibly without " +
            "Android's limit on wrong tries. Droynis compares the chip Android reports with a list of published " +
            "flaws that ships with the app; a pass means the chip isn't on that list.",
        remediation = Remediation(
            text = "No update can fix the chip. Because these attacks end in guessing your screen lock, use a long " +
                "password of letters and numbers instead of a PIN or pattern (Settings › Security › Screen lock), " +
                "then mute this check: only replacing the phone removes the flaw.",
            settingsActions = listOf(SettingsActions.SET_NEW_PASSWORD, SettingsActions.SECURITY),
        ),
        failsWhen = "the chip has a published boot ROM flaw no update can fix, such as Qualcomm's CVE-2026-25262 " +
            "or MediaTek's kamakiri (a warning when the screen lock isn't a strong PIN or password)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val list = flaws ?: ChipFlaws.bundled
        val chip = build.chip()
        val device = build.device()
        val props = properties.all()
        val propValues = (props as? Reading.Value)?.value.orEmpty()

        val names = buildList {
            chip.socModel?.let {
                val maker = chip.socManufacturer?.takeIf { m -> m.isNotBlank() }?.let { m -> "$m " }.orEmpty()
                add(ChipName("Chip model", maker + it, ChipNameKind.MODEL, Source("Build.SOC_MODEL")))
            }
            propValues[BOARD_PLATFORM]?.takeIf { it.isNotBlank() }?.let {
                add(ChipName("Platform", it, ChipNameKind.PLATFORM, props.source, BOARD_PLATFORM))
            }
            for (key in VENDOR_CHIP_PROPERTIES) {
                propValues[key]?.takeIf { it.isNotBlank() }?.let { add(ChipName("Chip name", it, ChipNameKind.MODEL, props.source, key)) }
            }
            chip.hardware?.let { add(ChipName("Hardware", it, ChipNameKind.OTHER, Source("Build.HARDWARE"))) }
            chip.board?.let { add(ChipName("Board", it, ChipNameKind.OTHER, Source("Build.BOARD"))) }
        }

        val evidence = mutableListOf<Evidence>()
        if (chip.socModel == null) {
            evidence += Evidence("Chip model", null, Source("Build.SOC_MODEL"), note = "not reported (Android 12+ only)")
        }
        names.forEach { evidence += Evidence(it.label, it.value, it.source, note = it.note) }
        if (props !is Reading.Value) evidence += props.toEvidence("System properties") { "" }
        evidence += Evidence(
            "Flaw list",
            "${count(list.flaws.size, "flaw")} in ${list.size} chips and devices, checked ${list.date}",
            LIST_SOURCE,
        )

        val matches = list.match(names, device.manufacturer, device.model)
        val (ambiguous, definite) = matches.partition { it.ambiguous }
        if (definite.isNotEmpty()) {
            if (definite.any { it.name == null }) {
                evidence += Evidence("Device", "${device.manufacturer} ${device.model}".trim(), Source("Build.MANUFACTURER, Build.MODEL"))
            }
            evidence += definite.groupBy { it.flaw }.map { (flaw, found) ->
                Evidence(
                    flaw.id,
                    "${flaw.title}: ${found.map { it.chip }.distinct().joinToString()}",
                    Source(flaw.source),
                    note = listOfNotNull("needs ${flaw.needs}", flaw.note).joinToString("; "),
                )
            }
            return fail(definite, evidence)
        }
        if (ambiguous.isNotEmpty()) {
            val platform = ambiguous.first().name?.value.orEmpty()
            val shared = ChipFlaws.chipTokens(platform, ChipNameKind.PLATFORM).firstNotNullOfOrNull { list.sharedPlatforms[it] }
            return Outcome.unknown(
                "Android names only the platform $platform, shared by ${shared ?: "several chips"}; " +
                    "the ${ambiguous.map { it.chip }.distinct().joinNames()} has a boot ROM flaw, the others aren't listed",
                evidence,
            )
        }
        if (!list.identifies(names)) {
            return Outcome.unknown("Android doesn't say which chip this phone has", evidence)
        }
        val shown = names.firstOrNull { it.kind != ChipNameKind.OTHER }?.value
            ?: names.firstNotNullOf { ChipFlaws.chipTokens(it.value, it.kind).firstOrNull() }
        return Outcome.pass("The chip ($shown) isn't on the list of chips with a published boot ROM flaw", evidence)
    }

    private fun fail(found: List<ChipMatch>, evidence: MutableList<Evidence>): Outcome {
        val secure = keyguard.isDeviceSecure()
        val complexity = keyguard.passwordComplexity()
        evidence += secure.toEvidence("Screen lock set")
        evidence += complexity.toEvidence("Screen lock strength") { it.name }
        // Android rates a lock only low, medium or high; high is a PIN of 8+ digits or a password of 6+ characters.
        val weakLock = (secure is Reading.Value && !secure.value) ||
            (complexity is Reading.Value && complexity.value in WEAK_LOCKS)

        val chips = found.map { it.chip }.distinct().joinNames()
        val flaws = found.map { it.flaw }.distinct().size
        val summary = buildString {
            append("The chip, $chips, has ")
            append(if (flaws == 1) "a published boot ROM flaw" else "$flaws published boot ROM flaws")
            append(" no update can fix")
            if (weakLock) append(", and the screen lock isn't a strong PIN or password")
        }
        return Outcome.fail(summary, evidence, escalation = Severity.WARNING.takeIf { weakLock })
    }

    companion object {
        const val BOARD_PLATFORM = "ro.board.platform"

        /** Properties some vendors set to the chip's own name: Samsung's, and MediaTek's older and newer ones. */
        val VENDOR_CHIP_PROPERTIES = listOf("ro.chipname", "ro.mediatek.platform", "ro.vendor.mediatek.platform")

        private val WEAK_LOCKS = setOf(PasswordComplexity.LOW, PasswordComplexity.MEDIUM)

        private val LIST_SOURCE = Source("Droynis' list of published boot ROM flaws (ChipFlawData)")
    }
}
