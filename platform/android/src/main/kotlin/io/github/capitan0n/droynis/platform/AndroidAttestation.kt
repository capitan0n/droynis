package io.github.capitan0n.droynis.platform

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.capitan0n.droynis.checks.base.AttestationProbe
import io.github.capitan0n.droynis.checks.base.KeyAttestation
import io.github.capitan0n.droynis.checks.base.KeyDescription
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
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

    /**
     * Generating an attested key takes up to a few seconds in secure hardware. What it attests (the
     * bootloader lock, verified boot, the patch levels) changes only with a reboot, which also ends
     * this process: one successful attestation serves every scan of this app run.
     */
    private val lock = Any()
    private var cached: Reading.Value<KeyAttestation>? = null
    private var cachedStrongBox: Reading<KeyAttestation>? = null

    override fun attest(): Reading<KeyAttestation> = synchronized(lock) {
        cached ?: generate(strongBox = false).also { if (it is Reading.Value) cached = it }
    }

    /**
     * The same, with the key made in StrongBox. A phone without StrongBox answers Unsupported, which
     * is kept too: whether the chip exists doesn't change while the app runs.
     */
    fun attestStrongBox(): Reading<KeyAttestation> = synchronized(lock) {
        cachedStrongBox ?: generate(strongBox = true).also { if (it !is Reading.Unavailable) cachedStrongBox = it }
    }

    private fun generate(strongBox: Boolean): Reading<KeyAttestation> {
        val source = if (strongBox) {
            Source("Android Keystore key attestation in StrongBox (extension ${KeyDescription.OID})")
        } else {
            Source("Android Keystore key attestation (extension ${KeyDescription.OID})")
        }
        if (strongBox && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return Reading.Unsupported("needs Android 9", source)
        }
        return probe(source) {
            val alias = "droynis-attestation-${UUID.randomUUID()}"
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            try {
                val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
                try {
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                        initialize(builder.build())
                        generateKeyPair()
                    }
                } catch (e: ProviderException) {
                    // Android 9-11 throw it directly, keystore2 may wrap it.
                    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        generateSequence<Throwable>(e) { it.cause }.any { it is StrongBoxUnavailableException }
                    ) {
                        return@probe Reading.Unsupported("this phone has no StrongBox", source)
                    }
                    throw e
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
