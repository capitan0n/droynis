package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Trust

/** Note on the evidence of an app the user trusts. */
const val TRUSTED_NOTE = "trusted by you, not counted"

/** Splits [items] into the ones whose app the user trusts and the rest, in that order. */
fun <T> ScanContext.splitTrusted(items: List<T>, packageOf: (T) -> String?): Pair<List<T>, List<T>> =
    items.partition { trusts(packageOf(it)) }

/** TRUSTED when the user trusts the app, COUNTED when it counts against the check, else NOT_COUNTED. */
fun trustOf(counted: Boolean, trusted: Boolean): Trust = when {
    trusted -> Trust.TRUSTED
    counted -> Trust.COUNTED
    else -> Trust.NOT_COUNTED
}

/** [note] with [TRUSTED_NOTE] added when [trusted]. */
fun withTrustNote(note: String?, trusted: Boolean): String? = when {
    !trusted -> note
    note.isNullOrBlank() -> TRUSTED_NOTE
    else -> "$note; $TRUSTED_NOTE"
}

/**
 * PASS summary for when the only apps left are ones the user trusts: "Only apps you trust can read
 * your notifications: Gadgetbridge". [others] names apps the check never counts, such as "apps that
 * came with the phone".
 */
fun onlyTrusted(phrase: String, trusted: List<String>, subject: String = "apps", others: String? = null): String {
    val who = listOfNotNull(others, "$subject you trust").joinToString(" and ")
    return "Only $who $phrase: ${trusted.distinct().joinNames()}"
}
