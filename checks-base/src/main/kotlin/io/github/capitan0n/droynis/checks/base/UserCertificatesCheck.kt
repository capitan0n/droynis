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
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class UserCertificatesCheck(private val certificates: CertificateStore) : Check {

    override val spec = CheckSpec(
        id = "NETW-3003",
        category = Category.NETWORK,
        title = "User CA certificates",
        severity = Severity.WARNING,
        explanation = "An installed certificate authority can be used to decrypt the TLS traffic of apps " +
            "that trust user certificates, for example on a school or company network that inspects " +
            "traffic. One you did not knowingly install is a red flag.",
        remediation = Remediation(
            text = "Under Settings › Security › Encryption & credentials › Trusted credentials › User, " +
                "remove certificates you do not need (the location varies by vendor).",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val certs = certificates.userCertificates()
        val evidence = when (certs) {
            is Reading.Value ->
                if (certs.value.isEmpty()) {
                    listOf(Evidence("User certificates", "none", certs.source))
                } else {
                    certs.value.map { Evidence("Certificate", "${it.subject} (expires ${it.expires ?: "?"})", certs.source) }
                }
            else -> listOf(certs.toEvidence("User certificates"))
        }
        return certs.evaluate("Certificate store", evidence) { list ->
            if (list.isEmpty()) {
                Outcome.pass("No user-installed CA certificates", evidence)
            } else {
                Outcome.fail(
                    "${count(list.size, "user CA certificate")} installed: ${list.map { it.subject }.joinNames()}",
                    evidence,
                )
            }
        }
    }
}
