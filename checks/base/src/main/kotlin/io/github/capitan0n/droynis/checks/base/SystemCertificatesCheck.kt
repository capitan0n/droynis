package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import java.time.Instant
import java.time.ZoneOffset
import kotlin.time.Duration.Companion.seconds

/**
 * CA certificates added to Android's system store, which every app trusts. Only root or a modified
 * system image can add one, so three signs are read, none of them needing privileges:
 *
 * - a certificate named after a traffic interception tool;
 * - before Android 14, where the store changes only with the system image, a certificate made
 *   after that image was built (`Build.TIME`);
 * - something mounted over a store directory in Droynis' own mount namespace, as root modules do
 *   (apps inherit zygote's mounts). From Android 14 the store lives in the Conscrypt module, whose
 *   versioned mount still shows the original, so the files the mount added can be named.
 */
class SystemCertificatesCheck(
    private val certificates: CertificateStore,
    private val build: BuildInfo,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3012",
        category = Category.NETWORK,
        title = "Added system CA certificates",
        severity = Severity.WARNING,
        explanation = "Android comes with about 150 trusted certificate authorities (CAs). Every app trusts that " +
            "system list, while most apps ignore CAs you install yourself. Root modules and app-testing tools " +
            "(Burp Suite, mitmproxy, HTTP Toolkit) can add a CA to the system list, and then whoever holds its key " +
            "can read and change the encrypted traffic of every app. A clean result means no sign of an added CA " +
            "was found: one written into a modified system image with an old date can't be told apart.",
        remediation = Remediation(
            text = "If you added it to inspect app traffic, remove the root module or tool once you're done. If you " +
                "didn't, turn the certificate off under Settings › Security › Encryption & credentials › Trusted " +
                "credentials › System, uninstall root modules you don't recognize, or reinstall the official firmware.",
            settingsActions = listOf(SettingsActions.TRUSTED_CREDENTIALS, SettingsActions.SECURITY),
        ),
        timeout = 15.seconds,
        failsWhen = "a CA certificate was added to the system store, which every app trusts (by a root module or a modified system)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val read = certificates.systemCertificates()
        if (read !is Reading.Value) {
            return Outcome.unknown("The system CA store could not be read", listOf(read.toEvidence(STORE)))
        }
        val store = read.value
        val evidence = mutableListOf(Evidence(STORE, store.size.toString(), read.source))
        val reasons = linkedMapOf<SystemCertificate, MutableList<String>>()
        fun flag(found: List<SystemCertificate>, why: String) = found.forEach { reasons.getOrPut(it) { mutableListOf() } += why }

        flag(store.filter { cert -> INTERCEPTION_TOOLS.any { cert.subject.contains(it, ignoreCase = true) } }, "named after a traffic interception tool")

        if (context.sdkInt < UPDATABLE_STORE_SDK) {
            val built = build.builtAt()
            evidence += built.toEvidence("System image built") { it.atOffset(ZoneOffset.UTC).toLocalDate().toString() }
            val time = (built as? Reading.Value)?.value?.takeIf { it > PLAUSIBLE_BUILD }
            if (time != null) flag(store.filter { it.notBefore?.isAfter(time) == true }, "made after the system image was built")
        }

        val info = certificates.mountInfo()
        val mounts = (info as? Reading.Value)?.value?.let(MountInfo::parse)
        if (info !is Reading.Value || mounts == null) {
            val note = if (info is Reading.Value) Evidence(MOUNTS, null, info.source, note = "in a format Droynis doesn't recognize") else info.toEvidence(MOUNTS)
            return Outcome.unknown("The mounts over the system CA store could not be read", evidence + note)
        }
        val over = mounts.filter { mount -> STORE_DIRECTORIES.any { mount.mountPoint == it || mount.mountPoint.startsWith("$it/") } }
        // Nothing mounted over the store: it is the one in the system image or module, as built.
        var compared = over.isEmpty()
        if (over.isNotEmpty()) {
            evidence += Evidence(
                "Mounted over the store",
                over.map { it.mountPoint }.distinct().joinNames(limit = 3),
                info.source,
                note = over.map { it.fsType }.distinct().joinToString(prefix = "filesystem "),
            )
            if (context.sdkInt >= UPDATABLE_STORE_SDK) {
                val original = originalStore(mounts)
                val names = original?.let { certificates.fileNames(it) }
                if (names is Reading.Value) {
                    compared = true
                    evidence += Evidence("Original store", "${names.value.size} certificates in $original", names.source)
                    flag(store.filter { it.file !in names.value }, "not in the Conscrypt module's own copy of the store")
                } else {
                    evidence += names?.toEvidence("Original store")
                        ?: Evidence("Original store", null, info.source, note = "the Conscrypt module's own mount was not found")
                }
            }
        }

        val added = reasons.entries.sortedBy { nameOf(it.key).lowercase() }
        added.forEach { (cert, why) ->
            val made = cert.notBefore?.atOffset(ZoneOffset.UTC)?.toLocalDate()?.let { ", valid from $it" }.orEmpty()
            evidence += Evidence("Added CA certificate", "${nameOf(cert)} (${cert.file}$made)", read.source, note = why.joinToString("; "))
        }
        return when {
            added.isNotEmpty() -> Outcome.fail(
                "${count(added.size, "CA certificate")} added to the system store, trusted by every app: " +
                    added.map { nameOf(it.key) }.joinNames(),
                evidence,
            )
            !compared -> Outcome.unknown(
                "Something is mounted over the system CA store, and Droynis can't compare it with the original",
                evidence,
            )
            else -> Outcome.pass("No sign of a CA certificate added to the system store", evidence)
        }
    }

    private fun nameOf(cert: SystemCertificate): String = COMMON_NAME.find(cert.subject)?.groupValues?.get(1) ?: cert.subject

    /**
     * The Conscrypt module's own store: its versioned mount (`/apex/com.android.conscrypt@<version>`),
     * the same filesystem as the active one, where a mount over the active store's directory doesn't reach.
     */
    private fun originalStore(mounts: List<Mount>): String? {
        val active = mounts.lastOrNull { it.mountPoint == CONSCRYPT } ?: return null
        val versioned = mounts.firstOrNull { VERSIONED.matches(it.mountPoint) && it.device == active.device } ?: return null
        return "${versioned.mountPoint}/cacerts"
    }

    companion object {
        /** From Android 14 the store lives in the Conscrypt module, which Google Play system updates may change. */
        const val UPDATABLE_STORE_SDK = 34

        const val CONSCRYPT = "/apex/com.android.conscrypt"

        /** Where Android reads system CAs: the Conscrypt module from Android 14, the system image before. */
        val STORE_DIRECTORIES = listOf("$CONSCRYPT/cacerts", "/system/etc/security/cacerts")

        /** Words in the subject of the CAs that traffic interception tools generate. */
        val INTERCEPTION_TOOLS = listOf(
            "mitmproxy", // mitmproxy, and PCAPdroid's decryption add-on
            "PortSwigger", // Burp Suite
            "Charles Proxy",
            "HTTP Toolkit",
            "DO_NOT_TRUST", // Fiddler Classic
            "Fiddler",
            "Proxyman",
        )

        private const val STORE = "System CA certificates"
        private const val MOUNTS = "Mounts"
        private val VERSIONED = Regex("""/apex/com\.android\.conscrypt@\d+""")
        private val COMMON_NAME = Regex("CN=([^,]+)")

        /** A `Build.TIME` before Android 8 was released is a placeholder, not a build date. */
        private val PLAUSIBLE_BUILD = Instant.parse("2017-01-01T00:00:00Z")
    }
}
