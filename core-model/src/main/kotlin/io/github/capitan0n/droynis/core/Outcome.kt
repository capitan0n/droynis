package io.github.capitan0n.droynis.core

enum class Status { PASS, FAIL, UNKNOWN, UNSUPPORTED }

/**
 * How a value was obtained.
 *
 * @property method the exact API, setting or command, e.g. `Settings.Global "adb_enabled"`.
 * @property grant the privilege used, or null for a public API that needs none.
 */
data class Source(val method: String, val grant: Grant? = null) {
    val tier: Tier get() = grant?.tier ?: Tier.BASE

    override fun toString(): String = if (grant == null) method else "$method (via $grant)"
}

/**
 * One observed value. [value] is null when nothing could be read, and [note] says why.
 *
 * @property personal the value identifies the user, their network or their computers (a DNS server,
 *   a proxy, a computer's name): reports leave it out unless the user asks for personal details.
 */
data class Evidence(
    val label: String,
    val value: String?,
    val source: Source,
    val note: String? = null,
    val personal: Boolean = false,
)

/** What a check concluded. Build with the factory functions. */
data class Outcome(
    val status: Status,
    /** One line describing what was observed, e.g. "USB debugging is enabled". */
    val summary: String,
    val evidence: List<Evidence> = emptyList(),
    /** FAIL only: raise this result above [CheckSpec.severity], e.g. a patch over a year old. */
    val escalation: Severity? = null,
) {
    init {
        require(escalation == null || status == Status.FAIL) { "Only a FAIL can escalate severity" }
    }

    companion object {
        fun pass(summary: String, evidence: List<Evidence> = emptyList()) =
            Outcome(Status.PASS, summary, evidence)

        fun fail(summary: String, evidence: List<Evidence> = emptyList(), escalation: Severity? = null) =
            Outcome(Status.FAIL, summary, evidence, escalation)

        fun unknown(summary: String, evidence: List<Evidence> = emptyList()) =
            Outcome(Status.UNKNOWN, summary, evidence)

        fun unsupported(summary: String, evidence: List<Evidence> = emptyList()) =
            Outcome(Status.UNSUPPORTED, summary, evidence)
    }
}

/** A check's result as stored in a report. */
data class Finding(
    val spec: CheckSpec,
    val status: Status,
    /** The spec's severity, or the FAIL's escalation when that is higher. */
    val severity: Severity,
    val summary: String,
    val evidence: List<Evidence>,
    val elapsedMillis: Long,
)
