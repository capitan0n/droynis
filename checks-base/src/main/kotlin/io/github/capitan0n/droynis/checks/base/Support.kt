package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.toEvidence

internal const val NOT_SET = "(not set)"

/** State of a 0/1 Settings switch. */
internal enum class SwitchState { ON, OFF, UNSET, UNEXPECTED }

internal fun switchState(raw: String?, on: Set<String> = setOf("1"), off: Set<String> = setOf("0")): SwitchState =
    when (val value = raw?.trim()) {
        null -> SwitchState.UNSET
        in on -> SwitchState.ON
        in off -> SwitchState.OFF
        else -> SwitchState.UNEXPECTED
    }

internal fun Reading<String?>.settingEvidence(label: String): Evidence = toEvidence(label) { it ?: NOT_SET }

/**
 * From Android 17 (API 37) the platform may answer an ordinary app's read of `adb_enabled` or
 * `development_settings_enabled` with the placeholder "0" instead of the real value
 * (`@Settings.Readable(redactedValue = "0")`, behind a platform flag). Android 16 has no such
 * redaction. A "0" read there proves nothing, so it must never become a PASS.
 */
internal const val SETTINGS_REDACTION_SDK = 37

internal fun mayBeRedacted(context: ScanContext, raw: String?): Boolean =
    context.sdkInt >= SETTINGS_REDACTION_SDK && raw?.trim() == "0"

internal const val REDACTED_SUMMARY = "Can't be verified: Android 17 and later report this as off to every app"

internal fun Evidence.redacted(): Evidence =
    copy(note = "Android 17+ may show apps \"0\" here whatever the real state")

internal fun count(n: Int, singular: String, plural: String = "${singular}s"): String =
    if (n == 1) "1 $singular" else "$n $plural"

/** "Signal", "Signal and Tasker" or "Signal, Tasker and 3 more". */
internal fun List<String>.joinNames(limit: Int = 2): String = when {
    size <= limit -> if (size <= 1) joinToString() else dropLast(1).joinToString() + " and " + last()
    else -> take(limit).joinToString() + " and ${size - limit} more"
}
