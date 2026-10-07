package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.security.MessageDigest
import java.util.Base64
import kotlin.time.Duration.Companion.seconds

/** A computer allowed to use adb without asking: one line of `adb_keys`. */
data class TrustedKey(
    /** The comment adb adds, usually `user@host`; null when there is none. */
    val name: String?,
    /** MD5 of the key, as the "Allow USB debugging?" dialog shows it; null if the key isn't valid base64. */
    val fingerprint: String?,
)

class TrustedComputersCheck(private val root: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2301",
        category = Category.ACCESS_CONTROL,
        title = "Computers trusted for USB debugging",
        severity = Severity.NOTICE,
        explanation = "Every computer you once allowed for USB debugging keeps its key on the phone, and " +
            "gets adb again without asking whenever debugging is on, even after you turn it off and " +
            "back on. Android 11 and later forget a computer after 7 days without a connection, unless " +
            "that timeout is turned off. Only root can read the list.",
        remediation = Remediation(
            text = "In Developer options tap \"Revoke USB debugging authorizations\". Your own computer " +
                "asks again the next time you connect it.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "a computer is trusted for USB debugging",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val file = root.adbKeys()
        return file.evaluate("The list of trusted computers", listOf(file.toEvidence(ADB_KEYS) { if (it == null) "no file" else "read" })) { text ->
            val keys = text?.let(::parse).orEmpty()
            val evidence = listOf(Evidence(ADB_KEYS, count(keys.size, "key"), file.source)) + keys.map { key ->
                // A key's name is usually user@host of the computer: personal, like its fingerprint.
                Evidence(
                    "Trusted computer",
                    key.name ?: "(no name)",
                    file.source,
                    note = key.fingerprint?.let { "fingerprint $it" },
                    personal = true,
                )
            }
            if (keys.isEmpty()) {
                Outcome.pass("No computer is trusted for USB debugging", evidence)
            } else {
                val names = keys.map { it.name ?: "a computer without a name" }
                Outcome.fail("${count(keys.size, "computer is", "computers are")} trusted for USB debugging: ${names.joinNames()}", evidence)
            }
        }
    }

    companion object {
        const val ADB_KEYS = "/data/misc/adb/adb_keys"

        /** One key per line: base64 of the public key, then an optional comment. */
        fun parse(text: String): List<TrustedKey> = text.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { line ->
                val key = line.substringBefore(' ')
                val name = line.substringAfter(' ', "").trim().ifEmpty { null }
                TrustedKey(name, fingerprint(key))
            }

        private fun fingerprint(base64: String): String? {
            val bytes = try {
                Base64.getDecoder().decode(base64)
            } catch (e: IllegalArgumentException) {
                return null
            }
            return MessageDigest.getInstance("MD5").digest(bytes).joinToString(":") { "%02X".format(it) }
        }
    }
}
