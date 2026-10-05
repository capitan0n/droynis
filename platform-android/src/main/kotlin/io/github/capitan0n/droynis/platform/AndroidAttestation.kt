package io.github.capitan0n.droynis.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.capitan0n.droynis.checks.base.AttestationProbe
import io.github.capitan0n.droynis.checks.base.KeyAttestation
import io.github.capitan0n.droynis.checks.base.KeyDescription
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Key attestation: the secure hardware signs a certificate stating the bootloader lock and
 * verified boot state, as the bootloader reported them. Public API, no permission, offline.
 */
internal object AndroidAttestation : AttestationProbe {

    private const val KEYSTORE = "AndroidKeyStore"

    override fun attest(): Reading<KeyAttestation> {
        val source = Source("Android Keystore key attestation (extension ${KeyDescription.OID})")
        return probe(source) {
            val alias = "droynis-attestation-${UUID.randomUUID()}"
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            try {
                val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                    initialize(spec)
                    generateKeyPair()
                }
                val leaf = keyStore.getCertificateChain(alias)?.firstOrNull() as? X509Certificate
                    ?: return@probe Reading.Unsupported("the keystore returned no certificate chain", source)
                val extension = leaf.getExtensionValue(KeyDescription.OID)
                    ?: return@probe Reading.Unsupported("the certificate has no attestation extension", source)
                val description = KeyDescription.fromExtensionValue(extension)
                if (!description.challenge.contentEquals(challenge)) {
                    return@probe Reading.Unavailable("the certificate answers a different challenge", source)
                }
                Reading.Value(description.toAttestation(), source)
            } finally {
                try {
                    keyStore.deleteEntry(alias)
                } catch (e: Exception) {
                    // The throwaway key may not exist if generation failed.
                }
            }
        }
    }
}
