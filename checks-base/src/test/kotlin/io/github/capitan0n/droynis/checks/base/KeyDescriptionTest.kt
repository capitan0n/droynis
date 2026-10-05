package io.github.capitan0n.droynis.checks.base

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** Builds attestation extensions with a tiny DER encoder and parses them back. */
class KeyDescriptionTest {

    private fun tlv(tag: ByteArray, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        when {
            content.size < 0x80 -> out.write(content.size)
            content.size < 0x100 -> { out.write(0x81); out.write(content.size) }
            else -> { out.write(0x82); out.write(content.size shr 8); out.write(content.size and 0xFF) }
        }
        out.write(content)
        return out.toByteArray()
    }

    private fun seq(vararg parts: ByteArray) = tlv(byteArrayOf(0x30), parts.fold(ByteArray(0)) { a, b -> a + b })
    private fun set(vararg parts: ByteArray) = tlv(byteArrayOf(0x31), parts.fold(ByteArray(0)) { a, b -> a + b })
    private fun int(v: Long) = tlv(byteArrayOf(0x02), BigInteger.valueOf(v).toByteArray())
    private fun enumerated(v: Long) = tlv(byteArrayOf(0x0A), BigInteger.valueOf(v).toByteArray())
    private fun bool(v: Boolean) = tlv(byteArrayOf(0x01), byteArrayOf(if (v) 0xFF.toByte() else 0))
    private fun octets(bytes: ByteArray) = tlv(byteArrayOf(0x04), bytes)

    /** EXPLICIT context-specific tag, using the high-tag-number form above 30 (e.g. [704] = BF 85 40). */
    private fun explicit(tag: Int, inner: ByteArray): ByteArray {
        val id = if (tag < 31) {
            byteArrayOf((0xA0 or tag).toByte())
        } else {
            val groups = generateSequence(tag) { it ushr 7 }.takeWhile { it > 0 }.map { it and 0x7F }.toList().reversed()
            byteArrayOf(0xBF.toByte()) + groups.mapIndexed { i, g -> (if (i < groups.lastIndex) g or 0x80 else g).toByte() }
        }
        return tlv(id, inner)
    }

    private val challenge = "droynis-challenge".toByteArray()

    private fun keyDescription(
        level: Long = 1,
        rootOfTrust: ByteArray? = seq(octets(ByteArray(32) { 7 }), bool(true), enumerated(0), octets(ByteArray(32))),
        rootInSoftwareList: Boolean = false,
        patchLevel: Long? = 202609,
        bootKeyBytes: Int = 32,
    ): ByteArray {
        val hardware = buildList {
            add(explicit(1, set(int(2)))) // purpose: sign
            add(explicit(2, int(3))) // algorithm: EC
            if (rootOfTrust != null && !rootInSoftwareList) {
                add(explicit(704, if (bootKeyBytes == 32) rootOfTrust else seq(octets(ByteArray(bootKeyBytes)), bool(true), enumerated(0))))
            }
            if (patchLevel != null) add(explicit(706, int(patchLevel)))
        }
        val software = buildList {
            add(explicit(701, int(1_790_000_000_000))) // creationDateTime
            if (rootOfTrust != null && rootInSoftwareList) add(explicit(704, rootOfTrust))
        }
        return seq(
            int(300), // attestationVersion (KeyMint 3)
            enumerated(level),
            int(300),
            enumerated(level),
            octets(challenge),
            octets(ByteArray(0)), // uniqueId
            seq(*software.toTypedArray()),
            seq(*hardware.toTypedArray()),
        )
    }

    @Test
    fun `parses a TEE attestation with root of trust and patch level`() {
        val parsed = KeyDescription.fromExtensionValue(octets(keyDescription()))

        assertEquals(300, parsed.attestationVersion)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, parsed.securityLevel)
        assertContentEquals(challenge, parsed.challenge)
        assertEquals(RootOfTrust(deviceLocked = true, VerifiedBootState.VERIFIED), parsed.rootOfTrust)
        assertEquals(202609, parsed.osPatchLevel)
    }

    @Test
    fun `reads the unlocked flag and boot state`() {
        val unlocked = seq(octets(ByteArray(32)), bool(false), enumerated(2), octets(ByteArray(32)))

        val parsed = KeyDescription.parse(keyDescription(rootOfTrust = unlocked))

        assertEquals(RootOfTrust(deviceLocked = false, VerifiedBootState.UNVERIFIED), parsed.rootOfTrust)
    }

    @Test
    fun `finds the root of trust in the software list and handles long lengths`() {
        val software = KeyDescription.parse(keyDescription(level = 0, rootInSoftwareList = true))
        assertEquals(SecurityLevel.SOFTWARE, software.securityLevel)
        assertEquals(true, software.rootOfTrust?.deviceLocked)

        // A 300-byte boot key forces a two-byte length; v1/v2 roots of trust have no boot hash.
        val longKey = KeyDescription.parse(keyDescription(bootKeyBytes = 300))
        assertEquals(VerifiedBootState.VERIFIED, longKey.rootOfTrust?.verifiedBootState)
    }

    @Test
    fun `missing optional fields are null`() {
        val parsed = KeyDescription.parse(keyDescription(rootOfTrust = null, patchLevel = null))

        assertNull(parsed.rootOfTrust)
        assertNull(parsed.osPatchLevel)
    }

    @Test
    fun `malformed input is rejected, never guessed`() {
        val valid = keyDescription()
        assertFailsWith<DerException> { KeyDescription.parse(valid.copyOf(valid.size - 5)) }
        assertFailsWith<DerException> { KeyDescription.parse(valid + byteArrayOf(0)) }
        assertFailsWith<DerException> { KeyDescription.parse(seq(int(1), int(2))) }
        assertFailsWith<DerException> { KeyDescription.parse(keyDescription(level = 7)) }
        assertFailsWith<DerException> { KeyDescription.fromExtensionValue(keyDescription()) } // not wrapped
    }
}
