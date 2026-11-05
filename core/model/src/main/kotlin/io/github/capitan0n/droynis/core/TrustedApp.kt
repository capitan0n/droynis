package io.github.capitan0n.droynis.core

/**
 * An app the user trusts for one check, such as a watch app that needs notification access. The
 * check still lists it, but no longer counts it against its result. Trust is per check: the same
 * app gaining another access is still reported.
 */
data class TrustedApp(val checkId: String, val packageName: String) {

    /** "APPS-4005:org.example.watch", for storage. */
    val key: String get() = "$checkId$SEPARATOR$packageName"

    companion object {
        private const val SEPARATOR = ':'

        /** Parses [key]; null for anything [key] can't have produced. */
        fun parse(key: String): TrustedApp? {
            val checkId = key.substringBefore(SEPARATOR, "")
            val packageName = key.substringAfter(SEPARATOR, "")
            if (checkId.isEmpty() || packageName.isEmpty() || SEPARATOR in packageName) return null
            return TrustedApp(checkId, packageName)
        }
    }
}
