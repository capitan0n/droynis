package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading

/** Read-only access to the Settings provider. */
interface SystemSettings {
    /** Raw value of a `Settings.Global` key; Unavailable when the key is unset or not readable. */
    fun global(key: String): Reading<String>
}

interface Keyguard {
    /** `KeyguardManager.isDeviceSecure()`: a PIN, pattern or password is set (SIM PIN excluded). */
    fun isDeviceSecure(): Reading<Boolean>

    /** Coarse strength bucket of the screen lock (API 29+); never the credential itself. */
    fun passwordComplexity(): Reading<PasswordComplexity>
}

/** Mirrors `DevicePolicyManager.PASSWORD_COMPLEXITY_*`. */
enum class PasswordComplexity { NONE, LOW, MEDIUM, HIGH }

interface BuildInfo {
    /** `Build.VERSION.SECURITY_PATCH` as reported by the OS, e.g. "2026-09-05". */
    fun securityPatch(): Reading<String>
}

/** Everything the base-tier checks read. Implemented by :platform-android. */
interface BaseProbes {
    val settings: SystemSettings
    val keyguard: Keyguard
    val build: BuildInfo
}
