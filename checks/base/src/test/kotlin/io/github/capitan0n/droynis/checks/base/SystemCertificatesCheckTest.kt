package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Status
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Added system CA certificates (NETW-3012) and the mountinfo parser it reads with. */
class SystemCertificatesCheckTest {

    private fun cert(file: String, subject: String, made: String = "2015-06-04") =
        SystemCertificate(file, subject, Instant.parse("${made}T00:00:00Z"))

    private val isrg = cert("6187b673.0", "CN=ISRG Root X1,O=Internet Security Research Group,C=US")
    private val globalSign = cert("b0e59380.0", "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R6", made = "2014-12-10")
    private val toolkit = cert("9a5ba575.0", "CN=HTTP Toolkit CA,O=HTTP Toolkit CA,C=XX", made = "2026-03-02")
    private val custom = cert("c0ffee00.0", "CN=Corp Inspection Root,O=Example Corp", made = "2026-02-01")

    private val stock = """
        1 0 253:5 / / ro,relatime shared:1 - ext4 /dev/block/dm-5 ro,seclabel
        50 30 7:40 / /apex/com.android.conscrypt@350090000 ro,nodev,noatime shared:20 - ext4 /dev/block/loop5 ro,dirsync,seclabel
        51 30 7:40 / /apex/com.android.conscrypt ro,nodev,noatime shared:21 - ext4 /dev/block/loop5 ro,dirsync,seclabel
    """.trimIndent()

    /** What a root module leaves: a tmpfs copy of the store mounted over Android 14+'s directory. */
    private val injected = stock + "\n900 51 0:120 / /apex/com.android.conscrypt/cacerts rw,relatime - tmpfs tmpfs rw,seclabel"

    /** Magisk's magic mount before Android 14: the system directory replaced, each file bound back. */
    private val magicMount = stock + """

        700 1 0:99 / /system/etc/security/cacerts rw,relatime - tmpfs magisk rw,seclabel
        701 700 253:5 /system/etc/security/cacerts/6187b673.0 /system/etc/security/cacerts/6187b673.0 ro - ext4 /dev/block/dm-5 ro
    """.trimIndent()

    private val original = "/apex/com.android.conscrypt@350090000/cacerts"

    private suspend fun scan(
        store: List<SystemCertificate>,
        mounts: Reading<String> = value(stock),
        originalFiles: Reading<Set<String>>? = null,
        sdk: Int = 37,
        built: Reading<Instant> = value(Instant.parse("2026-01-05T00:00:00Z")),
    ): Outcome {
        val directories = originalFiles?.let { mapOf(original to it) }.orEmpty()
        val check = SystemCertificatesCheck(
            FakeCertificates(system = value(store), mounts = mounts, directories = directories),
            FakeBuildInfo(value("2026-01-05"), built = built),
        )
        return check.run(scanContext(sdk = sdk))
    }

    @Test
    fun `a stock store with nothing mounted over it passes`() = runTest {
        val outcome = scan(listOf(isrg, globalSign))

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No sign of a CA certificate added to the system store", outcome.summary)
        assertEquals("2", outcome.evidence.first().value)
    }

    @Test
    fun `from Android 14 a CA a mount added is named by comparing with the module's own copy`() = runTest {
        val outcome = scan(listOf(isrg, globalSign, custom), mounts = value(injected), originalFiles = value(setOf(isrg.file, globalSign.file)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 CA certificate added to the system store, trusted by every app: Corp Inspection Root", outcome.summary)
        val added = outcome.evidence.single { it.label == "Added CA certificate" }
        assertEquals("Corp Inspection Root (c0ffee00.0, valid from 2026-02-01)", added.value)
        assertEquals("not in the Conscrypt module's own copy of the store", added.note)
        assertEquals("/apex/com.android.conscrypt/cacerts", outcome.evidence.single { it.label == "Mounted over the store" }.value)
    }

    @Test
    fun `an interception tool's CA fails on any Android, with every reason listed`() = runTest {
        val outcome = scan(listOf(isrg, toolkit), mounts = value(injected), originalFiles = value(setOf(isrg.file)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "named after a traffic interception tool; not in the Conscrypt module's own copy of the store",
            outcome.evidence.single { it.label == "Added CA certificate" }.note,
        )
        // Named after a tool is enough, even with nothing mounted.
        assertEquals(Status.FAIL, scan(listOf(isrg, toolkit), sdk = 30).status)
    }

    @Test
    fun `a mount over the store that adds nothing passes, one Droynis can't compare is unknown`() = runTest {
        // A module that only takes CAs away leaves nothing the original lacks.
        assertEquals(Status.PASS, scan(listOf(isrg), mounts = value(injected), originalFiles = value(setOf(isrg.file, globalSign.file))).status)

        val unreadable = scan(listOf(isrg, custom), mounts = value(injected), originalFiles = unavailable("permission denied"))
        assertEquals(Status.UNKNOWN, unreadable.status)
        assertEquals("Something is mounted over the system CA store, and Droynis can't compare it with the original", unreadable.summary)
        // Without the module's versioned mount there is no original to compare with.
        assertEquals(Status.UNKNOWN, scan(listOf(isrg), mounts = value(injected.lines().filterNot { "@" in it }.joinToString("\n"))).status)
    }

    @Test
    fun `before Android 14 a CA made after the system image was built fails`() = runTest {
        val outcome = scan(listOf(isrg, custom), sdk = 33, built = value(Instant.parse("2025-11-01T00:00:00Z")))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("made after the system image was built", outcome.evidence.single { it.label == "Added CA certificate" }.note)
        assertEquals("2025-11-01", outcome.evidence.single { it.label == "System image built" }.value)
    }

    @Test
    fun `the build date proves nothing from Android 14, or when it is a placeholder`() = runTest {
        // Google Play system updates may add CAs to Android 14's store after the system image was built.
        assertEquals(Status.PASS, scan(listOf(isrg, custom), sdk = 34, built = value(Instant.parse("2025-11-01T00:00:00Z"))).status)
        assertEquals(Status.PASS, scan(listOf(isrg, custom), sdk = 33, built = value(Instant.parse("2009-01-01T00:00:00Z"))).status)
    }

    @Test
    fun `before Android 14 a store replaced by a mount is unknown unless a CA gives itself away`() = runTest {
        assertEquals(Status.UNKNOWN, scan(listOf(isrg), mounts = value(magicMount), sdk = 33).status)
        assertEquals(Status.FAIL, scan(listOf(isrg, toolkit), mounts = value(magicMount), sdk = 33).status)
    }

    @Test
    fun `an unreadable store or mount table is unknown, never a pass`() = runTest {
        val noStore = SystemCertificatesCheck(FakeCertificates(system = unavailable("KeyStoreException")), FakeBuildInfo(value("x")))
        assertEquals(Status.UNKNOWN, noStore.run(scanContext()).status)
        assertEquals(Status.UNKNOWN, scan(listOf(isrg), mounts = unavailable("EACCES")).status)
        assertEquals(Status.UNKNOWN, scan(listOf(isrg), mounts = value("not a mount table")).status)
    }

    @Test
    fun `mountinfo is parsed with optional fields and escaped paths`() {
        val mounts = MountInfo.parse(
            """
            36 35 98:0 /mnt1 /mnt\0402 rw,noatime master:1 shared:7 - ext3 /dev/root rw,errors=continue
            37 35 0:5 / /proc rw - proc proc rw
            """.trimIndent(),
        )
        assertEquals(
            listOf(Mount("98:0", "/mnt1", "/mnt 2", "ext3"), Mount("0:5", "/", "/proc", "proc")),
            mounts,
        )
        assertNull(MountInfo.parse("36 35 98:0 /mnt1 /mnt2 rw ext3 /dev/root rw"))
        assertTrue(MountInfo.parse("")!!.isEmpty())
    }
}
