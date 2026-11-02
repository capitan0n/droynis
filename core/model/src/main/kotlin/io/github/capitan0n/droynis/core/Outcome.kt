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
 * @property packageName the installed app this evidence is about, if any: the UI offers a button that
 *   opens that app's own Settings screen ([Remediation.appSettingsActions], then App info).
 * @property trust for evidence that names an app in a check that lists apps: whether the check
 *   counts it, the user trusts it ([ScanContext.trustedApps]), or the check never counts it. The UI
 *   offers Trust or Stop trusting for the first two and says "Not counted" for the third. Null for
 *   evidence where trust means nothing, such as the WebView provider.
 */
data class Evidence(
    val label: String,
    val value: String?,
    val source: Source,
    val note: String? = null,
    val personal: Boolean = false,
    val packageName: String? = null,
    val trust: Trust? = null,
) {
    init {
        require(trust == null || packageName != null) { "Only evidence that names an app can be trusted" }
    }
}

/** Whether an app named in evidence counts against the check, the user trusts it, or neither applies. */
enum class Trust {
    /** Counted against the check; the user may trust it. */
    COUNTED,

    /** The user trusts this app: listed, but not counted. */
    TRUSTED,

    /**
     * Listed, but this check never counts it: it came with the phone, it is an app store, your
     * default SMS or phone app using its role, or Droynis itself. Nothing to trust.
     */
    NOT_COUNTED,
}

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
