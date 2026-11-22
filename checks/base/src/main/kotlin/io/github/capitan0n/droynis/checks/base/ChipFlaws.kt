package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Source

/** A chip as people know it, with the names Android may give it: lowercase letters and digits. */
data class Chip(val label: String, val ids: Set<String>) {
    constructor(label: String, vararg ids: String) : this(label, ids.toSet())
}

/** A device listed by its model, for chips Android doesn't name on it and that went into other devices too. */
data class ListedDevice(val label: String, val manufacturer: String, val model: String)

/**
 * A published flaw in a chip's boot ROM, the code burned into the chip that starts it: no update can
 * change it. Every chip and device listed is named by the vendor or by the researchers.
 */
data class ChipFlaw(
    /** The CVEs, or the name the researchers gave it when it has none. */
    val id: String,
    val title: String,
    /** What an attacker needs, read after "needs". */
    val needs: String,
    val chips: List<Chip>,
    val devices: List<ListedDevice> = emptyList(),
    /** Where the chips and devices listed come from. */
    val source: String,
    /** A limit of the listing, shown with a match. */
    val note: String? = null,
)

/** How much a name says about the chip. */
enum class ChipNameKind {
    /** Names the chip itself: `Build.SOC_MODEL`, a vendor's chip property. Every word counts. */
    MODEL,

    /** `ro.board.platform`: the chip, or a platform several chips share ([ChipFlaws.sharedPlatforms]). */
    PLATFORM,

    /** `Build.HARDWARE`, `Build.BOARD`: often a codename; only chip-shaped words count. */
    OTHER,
}

/** One name Android gives the chip, and where it came from. */
data class ChipName(val label: String, val value: String, val kind: ChipNameKind, val source: Source, val note: String? = null)

/**
 * A listed chip or device found on this phone, and the name that matched; null for a device matched by
 * its model.
 *
 * @property ambiguous matched only through a platform name that chips without a listed flaw share.
 */
data class ChipMatch(val flaw: ChipFlaw, val chip: String, val name: ChipName?, val ambiguous: Boolean = false)

/** The flaws to match against, and when they were last checked against their sources. */
class ChipFlaws(
    val flaws: List<ChipFlaw>,
    val date: String,
    /** Platform names shared by chips with and without a listed flaw, with the chips that share them. */
    val sharedPlatforms: Map<String, String> = emptyMap(),
) {
    /** Distinct chips and devices listed. */
    val size: Int get() = flaws.flatMap { f -> f.chips.map { it.label } + f.devices.map { it.label } }.toSet().size

    /** Every listed chip and device found in [names] or as [manufacturer] and [model]. */
    fun match(names: List<ChipName>, manufacturer: String, model: String): List<ChipMatch> {
        val tokens = names.map { it to chipTokens(it.value, it.kind) }
        val hasModel = names.any { it.kind == ChipNameKind.MODEL }
        return flaws.flatMap { flaw ->
            val byChip = flaw.chips.mapNotNull { chip ->
                val hits = tokens.filter { (_, words) -> words.any { it in chip.ids } }.map { it.first }
                val definite = hits.filterNot { isShared(it, chip) }
                when {
                    hits.isEmpty() -> null
                    definite.isNotEmpty() -> ChipMatch(flaw, chip.label, definite.first())
                    // The chip model Android reports would have matched; a shared platform says no more.
                    hasModel -> null
                    else -> ChipMatch(flaw, chip.label, hits.first(), ambiguous = true)
                }
            }
            val byDevice = flaw.devices.filter {
                it.manufacturer.equals(manufacturer.trim(), ignoreCase = true) && it.model.equals(model.trim(), ignoreCase = true)
            }.map { ChipMatch(flaw, it.label, null) }
            byChip + byDevice
        }
    }

    /** At least one name says which chip this is. */
    fun identifies(names: List<ChipName>): Boolean =
        names.any { it.kind != ChipNameKind.OTHER || chipTokens(it.value, it.kind).isNotEmpty() }

    // Qualcomm phones often put the platform name in Build.BOARD too: only a chip model is never shared.
    private fun isShared(name: ChipName, chip: Chip): Boolean =
        name.kind != ChipNameKind.MODEL && chipTokens(name.value, name.kind).any { it in sharedPlatforms && it in chip.ids }

    companion object {
        val bundled: ChipFlaws by lazy {
            ChipFlaws(ChipFlawData.FLAWS, ChipFlawData.DATE, ChipFlawData.SHARED_PLATFORMS)
        }

        /**
         * How chip names begin: MediaTek "mt6765", Qualcomm "msm8916", Samsung "exynos8890",
         * "samsungexynos8890" and "universal8890", Unisoc "ums9230", "sp9863a" and "sc9863a".
         */
        private val CHIP_PREFIX = Regex("^(mt\\d{4}|msm\\d{4}|exynos\\d{4}|samsungexynos\\d{4}|universal\\d{4}|ums\\d{3,4}|sp\\d{4}[a-z]?|sc\\d{4}[a-z]?)")

        /**
         * The words of [raw], lowercase, plus the chip name each begins with ("MT6765V/CB" gives "mt6765").
         * For [ChipNameKind.OTHER] only those chip names: a board codename such as "t310" is no chip.
         */
        fun chipTokens(raw: String, kind: ChipNameKind): Set<String> = buildSet {
            for (word in raw.lowercase().split(Regex("[^a-z0-9]+"))) {
                if (word.isEmpty()) continue
                CHIP_PREFIX.find(word)?.let { add(it.value) }
                if (kind != ChipNameKind.OTHER) add(word)
            }
        }
    }
}
