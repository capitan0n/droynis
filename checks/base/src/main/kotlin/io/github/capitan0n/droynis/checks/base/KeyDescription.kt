package io.github.capitan0n.droynis.checks.base

import java.math.BigInteger

class DerException(message: String) : Exception(message)

/** One DER element: its tag and where its content lies in [bytes]. */
class DerElement internal constructor(
    private val bytes: ByteArray,
    val tagClass: Int,
    val constructed: Boolean,
    val tag: Int,
    private val start: Int,
    private val end: Int,
) {
    val content: ByteArray get() = bytes.copyOfRange(start, end)

    fun children(): List<DerElement> {
        if (!constructed) throw DerException("element [$tagClass/$tag] is not constructed")
        return Der.readAll(bytes, start, end)
    }

    fun integer(): Long {
        if (tagClass != Der.UNIVERSAL || (tag != Der.INTEGER && tag != Der.ENUMERATED)) throw unexpected("an integer")
        if (end == start) throw DerException("empty integer")
        val value = BigInteger(content)
        if (value.bitLength() > 63) throw DerException("integer too large")
        return value.toLong()
    }

    fun boolean(): Boolean {
        if (tagClass != Der.UNIVERSAL || tag != Der.BOOLEAN || end - start != 1) throw unexpected("a boolean")
        return bytes[start] != 0.toByte()
    }

    fun octetString(): ByteArray {
        if (tagClass != Der.UNIVERSAL || tag != Der.OCTET_STRING) throw unexpected("an octet string")
        return content
    }

    private fun unexpected(what: String) = DerException("expected $what, found tag [$tagClass/$tag]")
}

/** A small, strict DER reader: definite lengths only, which is all X.509 extensions use. */
object Der {
    const val UNIVERSAL = 0
    const val CONTEXT = 2
    const val BOOLEAN = 1
    const val INTEGER = 2
    const val OCTET_STRING = 4
    const val ENUMERATED = 10
    const val SEQUENCE = 16

    /** Parses exactly one element spanning all of [bytes]. */
    fun parse(bytes: ByteArray): DerElement {
        val (element, next) = read(bytes, 0, bytes.size)
        if (next != bytes.size) throw DerException("${bytes.size - next} trailing bytes")
        return element
    }

    fun readAll(bytes: ByteArray, start: Int, end: Int): List<DerElement> {
        val elements = mutableListOf<DerElement>()
        var pos = start
        while (pos < end) {
            val (element, next) = read(bytes, pos, end)
            elements += element
            pos = next
        }
        return elements
    }

    private fun read(bytes: ByteArray, start: Int, end: Int): Pair<DerElement, Int> {
        var pos = start
        fun next(): Int {
            if (pos >= end) throw DerException("truncated at byte $pos")
            return bytes[pos++].toInt() and 0xFF
        }

        val first = next()
        var tag = first and 0x1F
        if (tag == 0x1F) { // high tag number form, e.g. [704]
            tag = 0
            do {
                val b = next()
                tag = (tag shl 7) or (b and 0x7F)
                if (tag > MAX_TAG) throw DerException("tag number too large")
            } while (b and 0x80 != 0)
        }
        var length = next()
        if (length and 0x80 != 0) {
            val count = length and 0x7F
            if (count == 0 || count > 4) throw DerException("unsupported length encoding")
            length = 0
            repeat(count) { length = (length shl 8) or next() }
            if (length < 0) throw DerException("length too large")
        }
        if (length > end - pos) throw DerException("element of $length bytes overruns its parent")
        val element = DerElement(bytes, first ushr 6, first and 0x20 != 0, tag, pos, pos + length)
        return element to pos + length
    }

    private const val MAX_TAG = 0xFFFFFF
}

/**
 * The Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17), as defined for
 * Keymaster and KeyMint: only the fields Droynis uses.
 */
data class KeyDescription(
    val attestationVersion: Int,
    val securityLevel: SecurityLevel,
    val challenge: ByteArray,
    val rootOfTrust: RootOfTrust?,
    val osPatchLevel: Int?,
    val vendorPatchLevel: Int? = null,
    val bootPatchLevel: Int? = null,
) {
    fun toAttestation() =
        KeyAttestation(attestationVersion, securityLevel, rootOfTrust, osPatchLevel, vendorPatchLevel, bootPatchLevel)

    override fun equals(other: Any?): Boolean =
        other is KeyDescription && attestationVersion == other.attestationVersion &&
            securityLevel == other.securityLevel && challenge.contentEquals(other.challenge) &&
            rootOfTrust == other.rootOfTrust && osPatchLevel == other.osPatchLevel &&
            vendorPatchLevel == other.vendorPatchLevel && bootPatchLevel == other.bootPatchLevel

    override fun hashCode(): Int = challenge.contentHashCode() * 31 + attestationVersion

    companion object {
        const val OID = "1.3.6.1.4.1.11129.2.1.17"
        private const val TAG_ROOT_OF_TRUST = 704
        private const val TAG_OS_PATCH_LEVEL = 706
        private const val TAG_VENDOR_PATCH_LEVEL = 718
        private const val TAG_BOOT_PATCH_LEVEL = 719

        /** Parses the value of `X509Certificate.getExtensionValue(OID)`: an OCTET STRING around the description. */
        fun fromExtensionValue(extension: ByteArray): KeyDescription = parse(Der.parse(extension).octetString())

        fun parse(der: ByteArray): KeyDescription {
            val top = Der.parse(der)
            if (top.tag != Der.SEQUENCE || !top.constructed) throw DerException("KeyDescription is not a SEQUENCE")
            val fields = top.children()
            if (fields.size < 8) throw DerException("KeyDescription has ${fields.size} fields, expected 8")
            val softwareEnforced = fields[6].children()
            val hardwareEnforced = fields[7].children()
            fun find(tag: Int) = (hardwareEnforced + softwareEnforced)
                .firstOrNull { it.tagClass == Der.CONTEXT && it.tag == tag }
                ?.children()?.singleOrNull()
            return KeyDescription(
                attestationVersion = fields[0].integer().toInt(),
                securityLevel = enumAt(SecurityLevel.entries, fields[1].integer(), "security level"),
                challenge = fields[4].octetString(),
                rootOfTrust = find(TAG_ROOT_OF_TRUST)?.let(::rootOfTrust),
                osPatchLevel = find(TAG_OS_PATCH_LEVEL)?.integer()?.toInt(),
                vendorPatchLevel = find(TAG_VENDOR_PATCH_LEVEL)?.integer()?.toInt(),
                bootPatchLevel = find(TAG_BOOT_PATCH_LEVEL)?.integer()?.toInt(),
            )
        }

        private fun rootOfTrust(element: DerElement): RootOfTrust {
            val fields = element.children()
            if (fields.size < 3) throw DerException("RootOfTrust has ${fields.size} fields, expected 3 or more")
            return RootOfTrust(
                deviceLocked = fields[1].boolean(),
                verifiedBootState = enumAt(VerifiedBootState.entries, fields[2].integer(), "verified boot state"),
            )
        }

        private fun <T> enumAt(values: List<T>, index: Long, what: String): T =
            values.getOrNull(index.coerceIn(-1L, values.size.toLong()).toInt())
                ?: throw DerException("unknown $what $index")
    }
}
