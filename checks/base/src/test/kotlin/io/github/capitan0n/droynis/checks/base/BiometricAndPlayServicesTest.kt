package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.BiometricAvailability.ENROLLED
import io.github.capitan0n.droynis.checks.base.BiometricAvailability.NONE_ENROLLED
import io.github.capitan0n.droynis.checks.base.BiometricAvailability.NO_HARDWARE
import io.github.capitan0n.droynis.checks.base.BiometricAvailability.OTHER
import io.github.capitan0n.droynis.checks.base.BiometricModality.FACE
import io.github.capitan0n.droynis.checks.base.BiometricModality.FINGERPRINT
import io.github.capitan0n.droynis.checks.base.BiometricModality.IRIS
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Biometric unlock strength (ACCS-2009) and Google Play services (APPS-4014). */
class BiometricAndPlayServicesTest {

    private suspend fun biometric(state: Reading<BiometricState>, secure: Reading<Boolean> = value(true)) =
        BiometricUnlockCheck(FakeKeyguard(secure), FakeBiometrics(state)).run(scanContext(sdk = 36))

    @Test
    fun `a weak biometric with no strong one fails`() = runTest {
        val faceOnly = biometric(biometrics(ENROLLED, NONE_ENROLLED, FINGERPRINT, FACE))

        assertEquals(Status.FAIL, faceOnly.status)
        assertEquals("Only a weak (Class 2) biometric is set up to unlock the phone", faceOnly.summary)
        assertEquals(Status.FAIL, biometric(biometrics(ENROLLED, NO_HARDWARE, FACE)).status)
    }

    @Test
    fun `a strong biometric passes only where it is the only kind of sensor`() = runTest {
        val fingerprintOnly = biometric(biometrics(ENROLLED, ENROLLED, FINGERPRINT))
        assertEquals(Status.PASS, fingerprintOnly.status)
        assertEquals("The fingerprint unlock set up is strong (Class 3)", fingerprintOnly.summary)

        // A strong fingerprint says nothing about a weak face unlock next to it.
        val both = biometric(biometrics(ENROLLED, ENROLLED, FINGERPRINT, FACE))
        assertEquals(Status.UNKNOWN, both.status)
        assertEquals(Status.UNKNOWN, biometric(biometrics(ENROLLED, ENROLLED)).status)
    }

    @Test
    fun `nothing enrolled passes only without face or iris hardware, which may be Class 1`() = runTest {
        assertEquals(Status.PASS, biometric(biometrics(NONE_ENROLLED, NONE_ENROLLED, FINGERPRINT)).status)

        val withFace = biometric(biometrics(NONE_ENROLLED, NONE_ENROLLED, FINGERPRINT, FACE))
        assertEquals(Status.UNKNOWN, withFace.status)
        assertTrue("convenience (Class 1)" in withFace.summary)
        assertEquals(Status.UNKNOWN, biometric(biometrics(NONE_ENROLLED, NO_HARDWARE, IRIS)).status)
    }

    @Test
    fun `no rated sensor is N-A, but face hardware without one is a hidden Class 1 face unlock`() = runTest {
        assertEquals(Status.UNSUPPORTED, biometric(biometrics(NO_HARDWARE, NO_HARDWARE)).status)

        val classOneFace = biometric(biometrics(NO_HARDWARE, NO_HARDWARE, FACE))
        assertEquals(Status.UNKNOWN, classOneFace.status)
        assertEquals(
            "The face unlock is convenience (Class 1), weaker than Class 2, and Android doesn't tell apps whether it is set up",
            classOneFace.summary,
        )
        assertEquals(Status.UNKNOWN, biometric(biometrics(NO_HARDWARE, NO_HARDWARE, FINGERPRINT)).status)
    }

    @Test
    fun `unclear answers, no screen lock and unreadable state never pass`() = runTest {
        assertEquals(Status.UNKNOWN, biometric(biometrics(OTHER, OTHER, FINGERPRINT)).status)
        assertEquals(Status.UNKNOWN, biometric(biometrics(ENROLLED, OTHER, FINGERPRINT)).status)
        assertEquals(Status.UNKNOWN, biometric(unavailable("access denied")).status)
        assertEquals(Status.UNSUPPORTED, biometric(unsupported("needs Android 11")).status)
        assertEquals(
            Status.UNSUPPORTED,
            biometric(biometrics(ENROLLED, NONE_ENROLLED, FACE), secure = value(false)).status,
        )
        // An unreadable lock state doesn't stop the check.
        assertEquals(Status.FAIL, biometric(biometrics(ENROLLED, NONE_ENROLLED, FACE), secure = unavailable()).status)
    }

    @Test
    fun `biometric evidence names both answers and the sensors`() = runTest {
        val evidence = biometric(biometrics(ENROLLED, NONE_ENROLLED, FACE, FINGERPRINT)).evidence.associateBy { it.label }

        assertEquals("enrolled", evidence.getValue("Class 2 or 3 biometric").value)
        assertEquals("sensor present, nothing enrolled", evidence.getValue("Class 3 biometric").value)
        assertEquals("fingerprint, face", evidence.getValue("Biometric sensors").value)
    }

    private fun gms(
        enabled: Boolean = true,
        system: Boolean = true,
        signers: Set<String> = setOf(GOOGLE),
        activities: List<String>? = listOf("com.google.android.gms.app.settings.GoogleSettingsActivity"),
    ) = PackageDetails(enabled, system, signers, activities)

    private suspend fun playServices(details: Reading<PackageDetails?>) =
        PlayServicesCheck(FakePackageDetails(mapOf(PlayServicesCheck.GMS to details))).run(scanContext())

    @Test
    fun `Google Play services in the system image fails as information only`() = runTest {
        val outcome = playServices(value(gms()))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("Google Play services is built into the system, with privileged access", outcome.summary)
        assertEquals(Severity.INFO, PlayServicesCheck(FakePackageDetails()).spec.severity)
        val evidence = outcome.evidence.associateBy { it.label }
        assertEquals("Google's key", evidence.getValue("Signing certificate (SHA-1)").note)
        assertEquals(PlayServicesCheck.GMS, evidence.getValue("Package").packageName)
        assertEquals(Status.FAIL, playServices(value(gms(signers = setOf(GOOGLE_SECONDARY)))).status)
    }

    @Test
    fun `absent, turned off, sandboxed or microG passes`() = runTest {
        assertEquals("Google Play services isn't installed", PlayServicesCheck(FakePackageDetails()).run(scanContext()).summary)
        assertEquals(Status.PASS, playServices(value(null)).status)
        assertEquals(Status.PASS, playServices(value(gms(enabled = false))).status)

        val sandboxed = playServices(value(gms(system = false)))
        assertEquals(Status.PASS, sandboxed.status)
        assertEquals("Google Play services runs as an ordinary app, without system privileges", sandboxed.summary)

        // microG in the system image, even when it spoofs Google's signature.
        val microg = gms(activities = listOf("org.microg.gms.ui.SettingsActivity", "org.microg.gms.ui.AboutFragment"))
        val spoofed = playServices(value(microg))
        assertEquals(Status.PASS, spoofed.status)
        assertEquals("microG, an open-source replacement, stands in for Google Play services", spoofed.summary)
        assertEquals(
            "2 activities, e.g. org.microg.gms.ui.SettingsActivity",
            spoofed.evidence.single { it.label == "microG activities" }.value,
        )
        assertEquals(Status.PASS, playServices(value(gms(signers = setOf(PlayServicesCheck.MICROG_SIGNER), activities = null))).status)
    }

    @Test
    fun `Play services it can't attribute to Google or microG is UNKNOWN`() = runTest {
        assertEquals(Status.UNKNOWN, playServices(value(gms(signers = setOf("00".repeat(20))))).status)
        assertEquals(Status.UNKNOWN, playServices(value(gms(signers = emptySet()))).status)
        // Google's key, but microG's spoofing can't be ruled out without its activities.
        assertEquals(Status.UNKNOWN, playServices(value(gms(activities = null))).status)
        assertEquals(Status.UNKNOWN, playServices(unavailable("binder transaction too large")).status)
        assertEquals(Status.UNSUPPORTED, playServices(unsupported("no package manager")).status)
    }

    private companion object {
        const val GOOGLE = "38918a453d07199354f8b19af05ec6562ced5788"
        const val GOOGLE_SECONDARY = "bd32424203e0fb25f36b57e5aa356f9bdd1da998"
    }
}
