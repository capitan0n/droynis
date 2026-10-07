package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.base.CertificateStore
import io.github.capitan0n.droynis.checks.base.UserCertificate
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
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
}
