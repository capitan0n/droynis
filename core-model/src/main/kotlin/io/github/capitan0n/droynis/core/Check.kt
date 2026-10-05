package io.github.capitan0n.droynis.core

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * One independent, read-only audit check.
 *
 * Checks never touch Android APIs directly: they receive probe interfaces through their
 * constructor, so every check is plain Kotlin and unit-testable with fakes. A check must only
 * return PASS after positively observing a passing value; anything it could not establish is
 * UNKNOWN or UNSUPPORTED.
 */
interface Check {
    val spec: CheckSpec

    /**
     * Called by [Scanner] only when the device meets [CheckSpec.minSdk] and holds every grant in
     * [CheckSpec.requires]. May throw or hang; the scanner turns that into UNKNOWN.
     */
    suspend fun run(context: ScanContext): Outcome
}

/** Static description of a check; also what reports and diffs key on. */
data class CheckSpec(
    /** Stable identifier `AREA-NNNN`. Never reused for a different check. */
    val id: String,
    val category: Category,
    val title: String,
    /** Severity of a FAIL. An [Outcome] may escalate it for one result, never lower it. */
    val severity: Severity,
    /** Why it matters, in 2–3 sentences. */
    val explanation: String,
    val remediation: Remediation,
    val minSdk: Int = MIN_SDK,
    /** Privileges beyond public APIs. Empty for base-tier checks. */
    val requires: Set<Grant> = emptySet(),
    val timeout: Duration = 5.seconds,
    /** When the check fails, in one short phrase with its thresholds, for the catalog and docs. */
    val failsWhen: String = "",
) {
    init {
        require(ID_PATTERN.matches(id)) { "Check id '$id' must look like ACCS-2001" }
        require(minSdk >= MIN_SDK) { "Check $id: minSdk $minSdk is below the app's minSdk $MIN_SDK" }
        require(timeout.isPositive()) { "Check $id: timeout must be positive" }
    }

    val requiredTier: Tier get() = requires.maxOfOrNull { it.tier } ?: Tier.BASE

    companion object {
        const val MIN_SDK = 26
        private val ID_PATTERN = Regex("[A-Z]{4}-\\d{4}")
    }
}

enum class Category(val label: String) {
    DEVICE_INTEGRITY("Device integrity"),
    ACCESS_CONTROL("Access control"),
    APPS("Apps and permissions"),
    NETWORK("Network and radios"),
}

/** Ordered from least to most severe, so `maxOf` picks the worst. */
enum class Severity { INFO, NOTICE, WARNING, CRITICAL }

/**
 * What the user can do about a FAIL. Droynis never applies a fix itself.
 *
 * @property settingsActions intent actions to try in order; the UI opens the first one the device
 *   can handle and falls back to the main Settings screen.
 * @property command an optional copy-paste command (for example adb), explained by [text].
 */
data class Remediation(
    val text: String,
    val settingsActions: List<String> = emptyList(),
    val command: String? = null,
)
