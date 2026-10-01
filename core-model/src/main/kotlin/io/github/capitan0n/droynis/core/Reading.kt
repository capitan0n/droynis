package io.github.capitan0n.droynis.core

/**
 * Result of one probe call. Probes never throw: every failure is a value, so a check cannot
 * mistake "could not read" for "disabled".
 */
sealed interface Reading<out T> {
    val source: Source

    data class Value<out T>(val value: T, override val source: Source) : Reading<T>

    /** The API, setting or hardware does not exist here (old SDK, removed by the OEM). */
    data class Unsupported(val reason: String, override val source: Source) : Reading<Nothing>

    /** Should exist but could not be read: setting missing, access denied, unexpected error. */
    data class Unavailable(val reason: String, override val source: Source) : Reading<Nothing>
}

fun <T> Reading<T>.toEvidence(label: String, render: (T) -> String = { it.toString() }): Evidence =
    when (this) {
        is Reading.Value -> Evidence(label, render(value), source)
        is Reading.Unsupported -> Evidence(label, null, source, note = "not supported: $reason")
        is Reading.Unavailable -> Evidence(label, null, source, note = "not readable: $reason")
    }

/**
 * Evaluates the value with [onValue]; a reading without a value becomes UNSUPPORTED or UNKNOWN,
 * never PASS. [subject] names what was being read, for the summary line.
 */
inline fun <T> Reading<T>.evaluate(
    subject: String,
    evidence: List<Evidence>,
    onValue: (T) -> Outcome,
): Outcome = when (this) {
    is Reading.Value -> onValue(value)
    is Reading.Unsupported -> Outcome.unsupported("$subject is not available on this device ($reason)", evidence)
    is Reading.Unavailable -> Outcome.unknown("$subject could not be read ($reason)", evidence)
}
