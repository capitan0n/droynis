package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence

/** A sign that an installed app keeps itself out of sight on purpose. */
enum class HidingSign(val note: String) {
    /** Its app drawer entries were turned off while it ran: the classic adware move after the first start. */
    ICON_TURNED_OFF("turned its app drawer icon off after it was installed"),

    /** It declares app drawer entries, but its manifest keeps all of them off. */
    ICON_DISABLED("declares an app drawer icon but keeps it off"),

    /** Its own label, or an app drawer entry's, is empty or made only of invisible characters. */
    BLANK_NAME("has a blank name"),

    /** An app drawer entry's icon is (nearly) fully transparent. */
    INVISIBLE_ICON("has a transparent icon"),
}

/** One installed app as the suspicious-app checks see it: how it shows itself and where it came from. */
data class AppSighting(
    val footprint: AppFootprint,
    val origin: AppOrigin,
    val signs: List<HidingSign>,
) {
    val packageName: String get() = footprint.packageName

    /** At least one enabled app drawer entry, whether or not it can be seen. */
    val hasLauncherEntry: Boolean get() = footprint.launcherEntries.any { it.enabled }

    /** Shows at least one sign of hiding on purpose. */
    val hiding: Boolean get() = signs.isNotEmpty()

    /** Can't be found in the app drawer: it hides, or it never had an icon, like most add-ons and plugins. */
    val outOfSight: Boolean get() = hiding || !hasLauncherEntry

    /**
     * How much it should worry you when it is out of sight and runs or shows screens on its own.
     * Hiding on purpose and coming from outside an app store each raise it one step, so an add-on
     * without an icon from an app store stays a notice.
     */
    val concern: Severity get() = when {
        hiding && origin == AppOrigin.SIDELOADED -> Severity.CRITICAL
        hiding || origin == AppOrigin.SIDELOADED -> Severity.WARNING
        else -> Severity.NOTICE
    }

    /** Counted in a check's result; a notice is only listed, since add-ons without an icon are common. */
    val counted: Boolean get() = concern > Severity.NOTICE

    /** A name to look for in Settings: its own label, else a visible app drawer label, else the package name. */
    val name: String
        get() = (listOf(footprint.appLabel) + footprint.launcherEntries.filter { it.enabled }.map { it.label })
            .firstOrNull { !isInvisibleText(it) }
            ?.trim()
            ?: packageName

    /**
     * [trusted]: the user trusts this app, so it is listed but not counted. [counted] defaults to
     * this app's concern; checks about something else than hiding pass their own, and leave out the
     * visibility note unless the app hides ([showVisibility]).
     */
    fun evidence(
        label: String,
        source: Source,
        details: String? = null,
        trusted: Boolean = false,
        counted: Boolean = this.counted,
        showVisibility: Boolean = true,
    ): Evidence {
        val visibility = when {
            hiding -> signs.joinToString("; ") { it.note }
            showVisibility -> "no app drawer icon"
            else -> null
        }
        val counting = when {
            trusted -> TRUSTED_NOTE
            counted -> null
            else -> "not counted"
        }
        val note = listOfNotNull(details, visibility, origin.note, counting)
        val value = if (name == packageName) packageName else "$name ($packageName)"
        return Evidence(
            label,
            value,
            source,
            note = note.joinToString("; "),
            packageName = packageName,
            trust = trustOf(counted, trusted),
        )
    }
}

object AppPresence {
    /**
     * An icon whose visible pixels cover less than this share of its square can't be seen. Normal
     * icons cover far more: a round adaptive icon about 80%, a thin glyph on transparency over 10%.
     */
    const val MIN_ICON_COVERAGE = 0.02

    fun signs(footprint: AppFootprint): List<HidingSign> = buildList {
        val entries = footprint.launcherEntries
        val enabled = entries.filter { it.enabled }
        if (entries.isNotEmpty() && enabled.isEmpty()) {
            add(if (entries.any { it.turnedOff }) HidingSign.ICON_TURNED_OFF else HidingSign.ICON_DISABLED)
        }
        if (isInvisibleText(footprint.appLabel) || enabled.any { isInvisibleText(it.label) }) add(HidingSign.BLANK_NAME)
        if (enabled.any { (it.iconCoverage ?: 1.0) < MIN_ICON_COVERAGE }) add(HidingSign.INVISIBLE_ICON)
    }

    /**
     * Joins each footprint with the app list for its origin. System and disabled apps are left out
     * even if the footprint probe let one through; an app missing from the list (installed during the
     * scan) stays, with an unknown origin.
     */
    fun sightings(footprints: List<AppFootprint>, inventory: Map<String, InstalledApp>): List<AppSighting> =
        footprints
            .filter { footprint -> inventory[footprint.packageName]?.let { !it.isSystem && it.isEnabled } ?: true }
            .map { AppSighting(it, originOf(it.packageName, inventory), signs(it)) }
}

/**
 * True when [text] shows nothing: it is empty, or every character is a space, a control or format
 * character (zero-width space and joiners, word joiner, BOM, soft hyphen…), a combining mark with
 * nothing to combine with, or one of the blank letters below. Unassigned characters don't count:
 * the JDK's Unicode tables can be older than the phone's fonts.
 */
fun isInvisibleText(text: String): Boolean = text.codePoints().allMatch(::isInvisibleCodePoint)

private fun isInvisibleCodePoint(codePoint: Int): Boolean =
    Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint) || codePoint in BLANK_LETTERS ||
        when (Character.getType(codePoint)) {
            Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.NON_SPACING_MARK.toInt() -> true
            else -> false
        }

/**
 * Letters and symbols that draw nothing: Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and the
 * blank Braille pattern (U+2800), long used for "invisible" names.
 */
private val BLANK_LETTERS = setOf(0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800)

/** The user apps as sightings, and the source they were read from. */
class Sightings(val all: List<AppSighting>, val source: Source) {
    fun inspected() = Evidence("User apps inspected", all.size.toString(), source)

    val outOfSight: List<AppSighting> get() = all.filter { it.outOfSight }
}

/**
 * Reads the user apps and the app list they are judged against. When either can't be read, calls
 * [onFailure] with the outcome to give instead: UNKNOWN or UNSUPPORTED, never a pass.
 */
inline fun readSightings(
    footprints: AppFootprintProbe,
    packages: PackageInventory,
    onFailure: (Outcome) -> Nothing,
): Sightings {
    val read = footprints.userApps()
    val apps = when (read) {
        is Reading.Value -> read.value
        is Reading.Unsupported -> onFailure(
            Outcome.unsupported("The app list is not available on this device (${read.reason})", listOf(read.toEvidence("User apps"))),
        )
        is Reading.Unavailable -> onFailure(
            Outcome.unknown("The app list could not be read (${read.reason})", listOf(read.toEvidence("User apps"))),
        )
    }
    val installed = packages.installedApps()
    val inventory = (installed as? Reading.Value)?.value?.associateBy { it.packageName }
        ?: onFailure(
            Outcome.unknown(
                "The installed apps could not be read, so where each app came from is unknown",
                listOf(installed.toEvidence("Installed apps") { "${it.size} apps" }),
            ),
        )
    return Sightings(AppPresence.sightings(apps, inventory), read.source)
}

/**
 * What a check found, with the user's trust applied: [counted] apps go into the result; [trusted]
 * ones and add-ons from an app store ([listedOnly]) are only listed. [all] keeps the order found.
 */
class Judged(val all: List<AppSighting>, val counted: List<AppSighting>, val trusted: List<AppSighting>, val listedOnly: List<AppSighting>) {
    fun isTrusted(app: AppSighting): Boolean = app in trusted

    /**
     * The pass summary when nothing counts: [none], or "Only hidden apps you trust [trustedPhrase]: Foo"
     * when trusted apps are all that is left; either way with the add-ons listed.
     */
    fun passSummary(none: String, trustedPhrase: String, subject: String = "hidden apps"): String {
        val head = if (trusted.isEmpty()) none else onlyTrusted(trustedPhrase, trusted.map { it.name }, subject)
        return head + listedSuffix(listedOnly.size)
    }
}

/** Splits [found] into the apps the check counts, those the user trusts, and add-ons it only lists. */
fun ScanContext.judge(found: List<AppSighting>): Judged {
    val (trusted, rest) = splitTrusted(found) { it.packageName }
    return Judged(found, rest.filter { it.counted }, trusted, rest.filterNot { it.counted })
}

/** For a pass that still lists apps: " (2 add-ons without an icon of their own listed, not counted)". */
fun listedSuffix(listed: Int): String =
    if (listed == 0) "" else " (${count(listed, "add-on")} without an icon of ${if (listed == 1) "its" else "their"} own listed, not counted)"

/** "Foo, Bar and 2 more". */
fun List<AppSighting>.names(): String = map { it.name }.joinNames()

/** CRITICAL when any counted app hides and came from outside an app store; the spec's WARNING otherwise. */
fun List<AppSighting>.escalation(): Severity? =
    Severity.CRITICAL.takeIf { any { it.counted && it.concern == Severity.CRITICAL } }
