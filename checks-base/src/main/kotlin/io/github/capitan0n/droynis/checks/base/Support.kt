package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.toEvidence

const val NOT_SET = "(not set)"

/** State of a 0/1 Settings switch. */
enum class SwitchState { ON, OFF, UNSET, UNEXPECTED }

fun switchState(raw: String?, on: Set<String> = setOf("1"), off: Set<String> = setOf("0")): SwitchState =
    when (val value = raw?.trim()) {
        null -> SwitchState.UNSET
        in on -> SwitchState.ON
        in off -> SwitchState.OFF
        else -> SwitchState.UNEXPECTED
    }

fun Reading<String?>.settingEvidence(label: String): Evidence = toEvidence(label) { it ?: NOT_SET }

/**
 * From Android 17 (API 37) the platform may answer an ordinary app's read of these keys with the
 * placeholder "0" instead of the real value (`@Settings.Readable(redactedValue = "0")`, behind a
 * platform flag). Android 16 has no such redaction.
 */
val REDACTED_SETTINGS: Set<String> = setOf(UsbDebuggingCheck.ADB_ENABLED, DeveloperOptionsCheck.DEVELOPMENT_SETTINGS_ENABLED)

const val SETTINGS_REDACTION_SDK = 37

/**
 * A "0" an app read from a [REDACTED_SETTINGS] key on Android 17+ proves nothing, so it must never
 * become a PASS. A read through a privileged shell (Shizuku) is not an app's read and is never
 * redacted, so its "0" is real.
 */
internal fun Reading<String?>.mayBeRedacted(context: ScanContext): Boolean =
    this is Reading.Value && source.grant == null &&
        context.sdkInt >= SETTINGS_REDACTION_SDK && value?.trim() == "0"

internal const val REDACTED_SUMMARY =
    "Can't be verified: Android 17 and later report this as off to apps. The Shizuku tier reads the real state"

internal fun Evidence.redacted(): Evidence =
    copy(note = "Android 17+ may show apps \"0\" here whatever the real state")

/** "1 app" or "3 apps". */
fun count(n: Int, singular: String, plural: String = "${singular}s"): String =
    if (n == 1) "1 $singular" else "$n $plural"

/** "Signal", "Signal and Tasker" or "Signal, Tasker and 3 more". */
fun List<String>.joinNames(limit: Int = 2): String = when {
    size <= limit -> if (size <= 1) joinToString() else dropLast(1).joinToString() + " and " + last()
    else -> take(limit).joinToString() + " and ${size - limit} more"
}
