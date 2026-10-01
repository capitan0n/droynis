package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import java.time.ZoneOffset
import java.time.ZonedDateTime

private val FAKE = Source("fake")

fun <T> value(value: T): Reading<T> = Reading.Value(value, FAKE)

fun unavailable(reason: String = "not set"): Reading<Nothing> = Reading.Unavailable(reason, FAKE)

fun unsupported(reason: String = "needs API 29"): Reading<Nothing> = Reading.Unsupported(reason, FAKE)

fun scanContext(year: Int = 2026, month: Int = 10, day: Int = 1) = ScanContext(
    startedAt = ZonedDateTime.of(year, month, day, 12, 0, 0, 0, ZoneOffset.UTC),
    sdkInt = 37,
)

class FakeSettings(private val global: Map<String, Reading<String>> = emptyMap()) : SystemSettings {
    override fun global(key: String): Reading<String> = global[key] ?: unavailable()
}

class FakeKeyguard(
    private val secure: Reading<Boolean>,
    private val complexity: Reading<PasswordComplexity> = unsupported(),
) : Keyguard {
    override fun isDeviceSecure() = secure
    override fun passwordComplexity() = complexity
}

class FakeBuildInfo(private val patch: Reading<String>) : BuildInfo {
    override fun securityPatch() = patch
}

class FakeProbes(
    override val settings: SystemSettings = FakeSettings(),
    override val keyguard: Keyguard = FakeKeyguard(unavailable()),
    override val build: BuildInfo = FakeBuildInfo(unavailable()),
) : BaseProbes
