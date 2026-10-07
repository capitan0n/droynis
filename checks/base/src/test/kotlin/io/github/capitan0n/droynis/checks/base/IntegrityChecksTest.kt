package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class IntegrityChecksTest {

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(
        "ACTIVE_PER_USER, PASS",
        "ACTIVE, PASS",
        "ACTIVE_DEFAULT_KEY, FAIL",
        "ACTIVATING, UNKNOWN",
        "INACTIVE, FAIL",
        "UNSUPPORTED, FAIL",
    )
    fun `storage encryption`(encryption: EncryptionStatus, status: Status) = runTest {
        assertEquals(status, StorageEncryptionCheck(FakePolicy(encryption = value(encryption))).status())
    }

    @Test
    fun `missing encryption is critical`() = runTest {
        assertEquals(Severity.CRITICAL, StorageEncryptionCheck(FakePolicy()).spec.severity)
        assertEquals(Status.UNKNOWN, StorageEncryptionCheck(FakePolicy(encryption = unavailable())).status())
    }

    @Test
    fun `advanced protection`() = runTest {
        assertEquals(Status.PASS, AdvancedProtectionCheck(FakePolicy(advancedProtection = value(true))).status())
        assertEquals(Status.FAIL, AdvancedProtectionCheck(FakePolicy(advancedProtection = value(false))).status())
        assertEquals(
            Status.UNSUPPORTED,
            AdvancedProtectionCheck(FakePolicy(advancedProtection = unsupported("needs API 36"))).status(),
        )
        assertEquals(36, AdvancedProtectionCheck(FakePolicy()).spec.minSdk)
        assertEquals(Severity.INFO, AdvancedProtectionCheck(FakePolicy()).spec.severity)
    }
}
