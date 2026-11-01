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

/**
 * Android rates each biometric sensor Class 3 (strong), Class 2 (weak) or Class 1 (convenience).
 * Apps may only ask whether some biometric of at least a class is enrolled, never which one, and
 * never see Class 1. So:
 * - a weak biometric enrolled with no strong one is a FAIL;
 * - a strong one is a PASS only on a phone with one kind of sensor, where it is the only one;
 * - nothing enrolled is a PASS only without face or iris hardware, which could be Class 1.
 *
 * Face unlock some makers build outside Android's biometric framework is invisible to every app,
 * and the explanation says so.
 */
class BiometricUnlockCheck(private val keyguard: Keyguard, private val biometrics: BiometricProbe) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2009",
        category = Category.ACCESS_CONTROL,
        title = "Biometric unlock strength",
        severity = Severity.NOTICE,
        explanation = "Android rates fingerprint and face unlock by how hard they are to fool. A weak " +
            "(Class 2) one, typically face unlock that uses only the front camera, can be fooled more " +
            "easily, by a photo or a look-alike, yet it still unlocks the phone. Strong (Class 3) " +
            "sensors are much harder to fool. Some phones also have a convenience (Class 1) face unlock, " +
            "weaker still, which Android hides from apps, as it does face unlock some makers build on their own.",
        remediation = Remediation(
            text = "In Settings › Security (Device unlock or Biometrics on some phones), remove the weak " +
                "face unlock or turn off its use for unlocking the phone, and keep a fingerprint or your PIN " +
                "or password instead. If the phone has a face unlock Droynis can't see, check it there too.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        // canAuthenticate(int), which asks about one class, exists from Android 11.
        minSdk = 30,
        failsWhen = "the only biometric unlock set up is weak (Class 2), such as most camera-only face unlock",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val secure = keyguard.isDeviceSecure()
        val state = biometrics.state()
        val evidence = listOf(secure.toEvidence("Device secure")) + state.evidence()
        if (secure is Reading.Value && !secure.value) {
            return Outcome.unsupported(
                "No screen lock is set, which biometric unlock needs; Secure lock screen (ACCS-2001) covers that",
                evidence,
            )
        }
        return state.evaluate("Biometric enrollment", evidence) { judge(it, evidence) }
    }

    private fun judge(state: BiometricState, evidence: List<Evidence>): Outcome {
        val faceOrIris = state.hardware - BiometricModality.FINGERPRINT
        val faceOrIrisLabel = faceOrIris.joinToString(" or ") { it.label }
        return when (state.weak) {
            BiometricAvailability.ENROLLED -> when (state.strong) {
                BiometricAvailability.NONE_ENROLLED, BiometricAvailability.NO_HARDWARE ->
                    Outcome.fail("Only a weak (Class 2) biometric is set up to unlock the phone", evidence)
                BiometricAvailability.ENROLLED ->
                    if (state.hardware.size == 1) {
                        Outcome.pass("The ${state.hardware.single().label} unlock set up is strong (Class 3)", evidence)
                    } else {
                        Outcome.unknown(
                            "A strong (Class 3) biometric is set up; Android doesn't tell apps whether a weaker " +
                                "one is set up too",
                            evidence,
                        )
                    }
                BiometricAvailability.OTHER -> unclear(state.strongCode, evidence)
            }
            BiometricAvailability.NONE_ENROLLED ->
                if (faceOrIris.isEmpty()) {
                    Outcome.pass("No fingerprint unlock is set up, and the phone reports no face or iris sensor", evidence)
                } else {
                    Outcome.unknown(
                        "No Class 2 or 3 biometric is set up, but the $faceOrIrisLabel unlock may be convenience " +
                            "(Class 1), which Android hides from apps",
                        evidence,
                    )
                }
            BiometricAvailability.NO_HARDWARE -> when {
                state.hardware.isEmpty() ->
                    Outcome.unsupported("This phone reports no fingerprint, face or iris sensor", evidence)
                faceOrIris.isNotEmpty() ->
                    Outcome.unknown(
                        "The $faceOrIrisLabel unlock is convenience (Class 1), weaker than Class 2, and Android " +
                            "doesn't tell apps whether it is set up",
                        evidence,
                    )
                else -> Outcome.unknown("The fingerprint sensor isn't rated Class 2 or 3", evidence)
            }
            BiometricAvailability.OTHER -> unclear(state.weakCode, evidence)
        }
    }

    private fun unclear(code: Int, evidence: List<Evidence>) =
        Outcome.unknown("Android didn't say which biometrics are set up (answer $code)", evidence)

    private fun Reading<BiometricState>.evidence(): List<Evidence> = when (this) {
        is Reading.Value -> listOf(
            Evidence("Class 2 or 3 biometric", describe(value.weak, value.weakCode), source, note = "canAuthenticate(BIOMETRIC_WEAK)"),
            Evidence("Class 3 biometric", describe(value.strong, value.strongCode), source, note = "canAuthenticate(BIOMETRIC_STRONG)"),
            Evidence(
                "Biometric sensors",
                value.hardware.sorted().joinToString { it.label }.ifEmpty { "none reported" },
                source,
                note = "system features",
            ),
        )
        else -> listOf(toEvidence("Biometric enrollment"))
    }

    private fun describe(availability: BiometricAvailability, code: Int) = when (availability) {
        BiometricAvailability.ENROLLED -> "enrolled"
        BiometricAvailability.NONE_ENROLLED -> "sensor present, nothing enrolled"
        BiometricAvailability.NO_HARDWARE -> "no such sensor"
        BiometricAvailability.OTHER -> "unclear (answer $code)"
    }
}
