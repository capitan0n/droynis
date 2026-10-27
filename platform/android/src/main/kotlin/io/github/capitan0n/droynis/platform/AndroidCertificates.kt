package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.base.CertificateStore
import io.github.capitan0n.droynis.checks.base.SystemCertificate
import io.github.capitan0n.droynis.checks.base.UserCertificate
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.ZoneId

/** "AndroidCAStore" lists system CAs as "system:…" and user-installed ones as "user:…". */
internal object AndroidCertificates : CertificateStore {

    private val COMMON_NAME = Regex("CN=([^,]+)")

    override fun userCertificates(): Reading<List<UserCertificate>> {
        val source = Source("KeyStore \"AndroidCAStore\", user: entries")
        return probe(source) {
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val certificates = store.aliases().toList()
                .filter { it.startsWith("user:") }
                .mapNotNull { store.getCertificate(it) as? X509Certificate }
                .map { cert ->
                    val subject = cert.subjectX500Principal.name
                    UserCertificate(
                        subject = COMMON_NAME.find(subject)?.groupValues?.get(1) ?: subject,
                        expires = cert.notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDate(),
                    )
                }
            Reading.Value(certificates, source)
        }
    }

    override fun systemCertificates(): Reading<List<SystemCertificate>> {
        val source = Source("KeyStore \"AndroidCAStore\", system: entries")
        return probe(source) {
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val certificates = store.aliases().toList()
                .filter { it.startsWith(SYSTEM) }
                .mapNotNull { alias ->
                    val cert = store.getCertificate(alias) as? X509Certificate ?: return@mapNotNull null
                    SystemCertificate(alias.removePrefix(SYSTEM), cert.subjectX500Principal.name, cert.notBefore.toInstant())
                }
            Reading.Value(certificates, source)
        }
    }

    // A process may read its own mount table; apps share zygote's mounts, root modules' included.
    override fun mountInfo(): Reading<String> {
        val source = Source("/proc/self/mountinfo")
        return probe(source) { Reading.Value(File("/proc/self/mountinfo").readText(), source) }
    }

    override fun fileNames(directory: String): Reading<Set<String>> {
        val source = Source("File.list(\"$directory\")")
        return probe(source) {
            val names = File(directory).list() ?: return@probe Reading.Unavailable("the directory can't be listed", source)
            Reading.Value(names.toSet(), source)
        }
    }

    private const val SYSTEM = "system:"
}
