package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Whether the phone has StrongBox, a separate security chip for keys. It passes only when a key made
 * in StrongBox comes back with a certificate that says StrongBox; the declared feature alone isn't
 * enough. Like the other attestation checks, the certificate is checked by the OS being judged.
 */
class StrongBoxCheck(private val strongBox: StrongBoxProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1021",
        category = Category.DEVICE_INTEGRITY,
        title = "StrongBox security chip",
        severity = Severity.NOTICE,
        explanation = "StrongBox is a separate security chip, such as the Titan M in Pixels, with its own " +
            "processor, memory and storage, that keeps encryption keys away from the main processor. Without " +
            "it, keys live in the TEE, a walled-off part of the main processor, which a flaw in that processor " +
            "(INTG-1013) can open. Phones that also use the chip to limit screen lock guesses, as Pixels do, keep " +
            "that limit even when the main processor is broken. Droynis asks Android whether the phone has " +
            "StrongBox, then makes a throwaway key in it and reads the certificate the chip signs.",
        remediation = Remediation(
            text = "A security chip can't be added to a phone. If you keep this one, a long screen lock password " +
                "matters more, and you can mute this check. When you choose your next phone, pick one with " +
                "StrongBox, such as a Google Pixel 3 or later.",
        ),
        // StrongBox and FEATURE_STRONGBOX_KEYSTORE exist from Android 9.
        minSdk = 28,
        // A security chip is slower than the TEE: making an attested key in it can take several seconds.
        timeout = 30.seconds,
        failsWhen = "the phone has no StrongBox security chip for keys",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val feature = strongBox.feature()
        val featureEvidence = feature.toEvidence("StrongBox feature") { version ->
            when (version) {
                null -> "not declared"
                0 -> "declared"
                else -> "declared (version $version)"
            }
        }
        return feature.evaluate("Whether the phone has StrongBox", listOf(featureEvidence)) { version ->
            if (version == null) {
                Outcome.fail("This phone has no StrongBox: its keys live in the main processor's TEE", listOf(featureEvidence))
            } else {
                attestedOutcome(featureEvidence)
            }
        }
    }

    private fun attestedOutcome(featureEvidence: Evidence): Outcome {
        val attested = strongBox.attest()
        val evidence = listOf(
            featureEvidence,
            attested.toEvidence("Key made in StrongBox") { "attested at ${level(it.securityLevel)}" },
        )
        return when (attested) {
            is Reading.Value -> if (attested.value.securityLevel == SecurityLevel.STRONG_BOX) {
                Outcome.pass("Keys can be kept in StrongBox, a separate security chip", evidence)
            } else {
                Outcome.unknown(
                    "The phone declares StrongBox, but the key made there was attested at ${level(attested.value.securityLevel)}",
                    evidence,
                )
            }
            is Reading.Unsupported ->
                Outcome.unknown("The phone declares StrongBox, but Android refused to make a key in it", evidence)
            is Reading.Unavailable ->
                Outcome.unknown("A key couldn't be made in StrongBox (${attested.reason})", evidence)
        }
    }

    private fun level(level: SecurityLevel): String = when (level) {
        SecurityLevel.SOFTWARE -> "software level"
        SecurityLevel.TRUSTED_ENVIRONMENT -> "TEE level"
        SecurityLevel.STRONG_BOX -> "StrongBox level"
    }
}
