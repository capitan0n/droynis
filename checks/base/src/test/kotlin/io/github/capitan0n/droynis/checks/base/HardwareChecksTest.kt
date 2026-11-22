package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class ChipFlawCheckTest {

    private val strongLock = FakeKeyguard(value(true), value(PasswordComplexity.HIGH))

    private fun check(
        chip: ChipInfo = ChipInfo(null, null, null, null),
        props: Map<String, String> = emptyMap(),
        keyguard: Keyguard = strongLock,
        manufacturer: String = "Fairphone",
        model: String = "FP6",
    ) = ChipFlawCheck(
        FakeBuildInfo(unavailable(), chip = chip, manufacturer = manufacturer, model = model),
        FakeProperties(value(props)),
        keyguard,
    )

    private fun platform(name: String) = mapOf(ChipFlawCheck.BOARD_PLATFORM to name)

    @Test
    fun `a MediaTek chip named by Build HARDWARE fails at notice with a strong lock`() = runTest {
        val outcome = check(ChipInfo(null, null, "mt6765", "k65v1_64_bsp")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertTrue("Helio P35/G35 (MT6765)" in outcome.summary, outcome.summary)
        assertTrue(outcome.evidence.any { it.label == "kamakiri" })
    }

    @Test
    fun `a weak screen lock escalates to a warning`() = runTest {
        val pin = FakeKeyguard(value(true), value(PasswordComplexity.MEDIUM))
        val outcome = check(ChipInfo("Mediatek", "MT6878", "mt6878", "mt6878"), keyguard = pin).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertTrue(outcome.evidence.any { it.label == "MT6878 EMFI" })
        assertTrue("screen lock" in outcome.summary)
    }

    @Test
    fun `no screen lock escalates, an unreadable strength doesn't`() = runTest {
        val none = FakeKeyguard(value(false), value(PasswordComplexity.NONE))
        assertEquals(Severity.WARNING, check(ChipInfo(null, null, "mt6762", null), keyguard = none).outcome().escalation)

        val unread = FakeKeyguard(value(true), unsupported("needs Android 10"))
        assertNull(check(ChipInfo(null, null, "mt6762", null), keyguard = unread).outcome().escalation)
    }

    @Test
    fun `a chip model with a package suffix still matches`() = runTest {
        val outcome = check(ChipInfo("Mediatek", "MT6765V/CB", "mt6765", null)).outcome()

        assertEquals(Status.FAIL, outcome.status)
    }

    @Test
    fun `a chip on two lists counts both flaws`() = runTest {
        val outcome = check(ChipInfo(null, null, "mt8163", null)).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertTrue("2 published boot ROM flaws" in outcome.summary, outcome.summary)
    }

    @Test
    fun `a listed Qualcomm platform fails, a shared one is unknown`() = runTest {
        assertEquals(Status.FAIL, check(ChipInfo(null, null, "qcom", "msm8909"), platform("msm8909")).status())

        val shared = check(ChipInfo(null, null, "qcom", "MSM8916"), platform("msm8916")).outcome()
        assertEquals(Status.UNKNOWN, shared.status)
        assertTrue("MSM8939" in shared.summary, shared.summary)
    }

    @Test
    fun `a chip model outranks a shared platform`() = runTest {
        val sd615 = check(ChipInfo("QTI", "MSM8939", "qcom", null), platform("msm8916")).outcome()
        assertEquals(Status.PASS, sd615.status)

        val sd410 = check(ChipInfo(null, null, "qcom", null), platform("msm8916") + ("ro.chipname" to "MSM8916")).outcome()
        assertEquals(Status.FAIL, sd410.status)
    }

    @Test
    fun `Exynos 8890 is found by Samsung's board name`() = runTest {
        val outcome = check(ChipInfo(null, null, "samsungexynos8890", "universal8890"), platform("exynos5")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertTrue(outcome.evidence.any { it.label == "exynos-usbdl" })
    }

    @Test
    fun `the Pixel C is found by its model`() = runTest {
        val outcome = check(ChipInfo(null, null, "dragon", "dragon"), manufacturer = "Google", model = "Pixel C").outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertTrue(outcome.evidence.any { it.label == "CVE-2018-6242" })
        assertTrue(outcome.evidence.any { it.label == "Device" && it.value == "Google Pixel C" })
    }

    @Test
    fun `Unisoc chips match by model and by platform`() = runTest {
        val t606 = check(ChipInfo("Unisoc", "T606", "ums9230_1h10", null)).outcome()
        assertEquals(Status.FAIL, t606.status)
        assertTrue("2 published boot ROM flaws" in t606.summary, t606.summary)

        assertEquals(Status.FAIL, check(ChipInfo(null, null, "s9863a1h10", null), platform("sp9863a")).status())
        assertEquals(Status.FAIL, check(ChipInfo(null, null, "ums512_1h10", null)).status())
    }

    @Test
    fun `an unlisted chip passes`() = runTest {
        val sm8450 = check(ChipInfo("QTI", "SM8450", "qcom", "taro"), platform("taro")).outcome()
        assertEquals(Status.PASS, sm8450.status)
        assertTrue("SM8450" in sm8450.summary, sm8450.summary)

        assertEquals(Status.PASS, check(ChipInfo(null, null, "mt6877", null)).status())
        assertEquals(Status.PASS, check(ChipInfo(null, null, "qcom", "sdm660"), platform("sdm660")).status())
    }

    @Test
    fun `a phone that names no chip is unknown, not passed`() = runTest {
        assertEquals(Status.UNKNOWN, check(ChipInfo(null, null, "qcom", "lynx")).status())

        val noProps = ChipFlawCheck(
            FakeBuildInfo(unavailable(), chip = ChipInfo(null, null, "qcom", "t310")),
            FakeProperties(unavailable("getprop printed nothing")),
            strongLock,
        )
        // A board codename that looks like a Unisoc chip isn't taken for one.
        assertEquals(Status.UNKNOWN, noProps.status())
    }

    @Test
    fun `chip tokens keep chip names, and only those for codenames`() {
        assertEquals(setOf("mt6765v", "cb", "mt6765"), ChipFlaws.chipTokens("MT6765V/CB", ChipNameKind.MODEL))
        assertEquals(setOf("ums9230"), ChipFlaws.chipTokens("ums9230_1h10", ChipNameKind.OTHER))
        assertEquals(emptySet(), ChipFlaws.chipTokens("t310", ChipNameKind.OTHER))
        assertEquals(setOf("samsungexynos8890"), ChipFlaws.chipTokens("samsungexynos8890", ChipNameKind.OTHER))
    }

    @Test
    fun `the bundled list is well formed`() {
        val list = ChipFlaws.bundled
        val idShape = Regex("[a-z0-9]+")
        assertEquals(8, list.flaws.size)
        assertEquals(list.flaws.size, list.flaws.map { it.id }.toSet().size)
        for (flaw in list.flaws) {
            assertTrue(flaw.source.startsWith("https://"), flaw.id)
            assertTrue(flaw.chips.isNotEmpty() || flaw.devices.isNotEmpty(), flaw.id)
            for (chip in flaw.chips) {
                assertTrue(chip.ids.isNotEmpty(), chip.label)
                assertTrue(chip.ids.all { idShape.matches(it) }, chip.label)
            }
            // One name belongs to one chip within a flaw.
            val ids = flaw.chips.flatMap { it.ids }
            assertEquals(ids.size, ids.toSet().size, flaw.id)
        }
        val allIds = list.flaws.flatMap { f -> f.chips.flatMap { it.ids } }.toSet()
        assertTrue(allIds.containsAll(list.sharedPlatforms.keys))
    }
}

class StrongBoxCheckTest {

    private fun attestedAt(level: SecurityLevel) = value(KeyAttestation(300, level, null, osPatchLevel = 202609))

    @Test
    fun `no StrongBox fails without making a key`() = runTest {
        val probe = FakeStrongBox(feature = value(null))
        val outcome = StrongBoxCheck(probe).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(0, probe.attested)
    }

    @Test
    fun `a key attested in StrongBox passes`() = runTest {
        val outcome = StrongBoxCheck(FakeStrongBox(value(300), attestedAt(SecurityLevel.STRONG_BOX))).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("declared (version 300)", outcome.evidence.first().value)
    }

    @Test
    fun `a declared StrongBox that doesn't deliver is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, StrongBoxCheck(FakeStrongBox(value(0), attestedAt(SecurityLevel.TRUSTED_ENVIRONMENT))).status())
        assertEquals(Status.UNKNOWN, StrongBoxCheck(FakeStrongBox(value(0), unsupported("this phone has no StrongBox"))).status())
        assertEquals(Status.UNKNOWN, StrongBoxCheck(FakeStrongBox(value(0), unavailable("timed out"))).status())
    }

    @Test
    fun `an unreadable feature is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, StrongBoxCheck(FakeStrongBox(unavailable("package manager died"))).status())
        assertEquals(Status.UNSUPPORTED, StrongBoxCheck(FakeStrongBox(unsupported("needs Android 9"))).status())
    }
}
