package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding

/**
 * Leaves out of a report what identifies the user, their network or their computers, so it can be
 * shared: evidence the check marked [Evidence.personal] (DNS servers, proxies, the Private DNS host,
 * computers trusted for USB debugging), those values wherever a summary repeats them, and every IP
 * or MAC address in the text. App names, the device model and Android version stay: findings are
 * about them, and they don't identify one phone.
 */
object PersonalDetails {

    const val HIDDEN = "[hidden]"

    /** What [hide] leaves out, in the words reports use. */
    const val DESCRIPTION = "IP addresses, DNS and proxy servers, the Private DNS host and computers trusted for USB debugging"

    fun hide(findings: List<Finding>): List<Finding> = findings.map { it.hidden() }

    private fun Finding.hidden(): Finding {
        // Longest first, so a value that contains another is replaced whole.
        val secrets = evidence.filter { it.personal }
            .flatMap { listOfNotNull(it.value, it.note) }
            .filter { it.isNotBlank() }
            .distinct()
            .sortedByDescending { it.length }
        fun clean(text: String) = mask(secrets.fold(text) { acc, secret -> acc.withoutSecret(secret) })
        return copy(
            summary = clean(summary),
            evidence = evidence.map { item ->
                if (item.personal) {
                    item.copy(value = item.value?.let { HIDDEN }, note = item.note?.let { HIDDEN })
                } else {
                    item.copy(value = item.value?.let(::clean), note = item.note?.let(::clean))
                }
            },
        )
    }

    /**
     * Replaces [secret] with [HIDDEN]. A short one (a computer called "pc") only where it stands
     * alone, so it doesn't cut words apart; it is still never left in the text.
     */
    private fun String.withoutSecret(secret: String): String =
        if (secret.length >= MIN_SECRET) {
            replace(secret, HIDDEN)
        } else {
            Regex("(?<![\\p{L}\\p{N}])${Regex.escape(secret)}(?![\\p{L}\\p{N}])").replace(this, HIDDEN)
        }

    /** Replaces IPv4, IPv6 and MAC addresses; "any address" and loopback say nothing about anyone. */
    fun mask(text: String): String {
        val v4 = IPV4.replace(text) { if (it.value == "0.0.0.0" || it.value.startsWith("127.")) it.value else HIDDEN }
        return COLON_HEX.replace(v4) { match ->
            val token = match.value
            val address = token.contains("::") || token.count { it == ':' } >= MIN_COLONS
            if (!address || token == "::" || token == "::1") token else HIDDEN
        }.replace(HIDDEN + HIDDEN, HIDDEN)
    }

    private const val MIN_SECRET = 4
    private const val MIN_COLONS = 3
    private const val OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"

    /** Four octets, not part of a longer dotted number such as an app version. */
    private val IPV4 = Regex("(?<!\\d)(?<!\\d\\.)(?:$OCTET\\.){3}$OCTET(?!\\d|\\.\\d)")

    /** Hex groups joined by colons: IPv6 and MAC addresses, but also times, sorted out by [mask]. */
    private val COLON_HEX = Regex("(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
}
