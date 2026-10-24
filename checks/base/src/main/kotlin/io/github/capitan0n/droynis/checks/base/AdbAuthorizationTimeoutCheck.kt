package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

class AdbAuthorizationTimeoutCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2013",
        category = Category.ACCESS_CONTROL,
        title = "USB debugging authorization timeout",
        severity = Severity.NOTICE,
        explanation = "A computer you allowed for USB or wireless debugging gets full adb access whenever " +
            "debugging is on: it can install apps and read app data. Since Android 11 the phone forgets a " +
            "computer that hasn't connected for 7 days. The developer option \"Disable adb authorization " +
            "timeout\" stops that, so every computer you ever allowed stays trusted for good.",
        remediation = Remediation(
            text = "Open Settings › System › Developer options and turn off \"Disable adb authorization " +
                "timeout\". \"Revoke USB debugging authorizations\" on the same screen forgets every " +
                "computer at once.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
        // The timeout and its setting arrived in Android 11.
        minSdk = 30,
        failsWhen = "computers allowed for USB debugging keep their access for more than 7 days " +
            "without connecting, or for good",
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Hidden, but @Readable and not redacted (checked in Android 12L, 16 and 17); Android 11 has no
        // such restriction.
        val setting = settings.global(ADB_ALLOWED_CONNECTION_TIME)
        val evidence = listOf(
            setting.toEvidence(ADB_ALLOWED_CONNECTION_TIME) { raw ->
                raw?.let { "$it ms" } ?: "$NOT_SET (Android's default: 7 days)"
            },
        )
        return setting.evaluate("The adb authorization timeout", evidence) { raw ->
            // The adb key store reads an unset key as the 7-day default (AdbDebuggingManager in Android 16,
            // AdbKeyStore in 17).
            if (raw == null) {
                return@evaluate Outcome.pass(
                    "A computer that hasn't connected for 7 days loses its debugging access (Android's default)",
                    evidence,
                )
            }
            val millis = raw.trim().toLongOrNull()
            when {
                millis == null || millis < 0 -> Outcome.unknown("Unexpected value \"$raw\" for $ADB_ALLOWED_CONNECTION_TIME", evidence)
                // 0 means keys never expire: the "Disable adb authorization timeout" switch.
                millis == 0L -> Outcome.fail("Computers allowed for USB debugging keep their access for good", evidence)
                millis.milliseconds > DEFAULT -> Outcome.fail(
                    "Computers allowed for USB debugging keep their access for ${roughly(millis.milliseconds)} without connecting",
                    evidence,
                )
                else -> Outcome.pass(
                    "A computer that hasn't connected for ${roughly(millis.milliseconds)} loses its debugging access",
                    evidence,
                )
            }
        }
    }

    companion object {
        /** `Settings.Global.ADB_ALLOWED_CONNECTION_TIME`: hidden, in milliseconds; 0 means never. */
        const val ADB_ALLOWED_CONNECTION_TIME = "adb_allowed_connection_time"

        /** `Settings.Global.DEFAULT_ADB_ALLOWED_CONNECTION_TIME`, also what Developer options writes back. */
        val DEFAULT: Duration = 7.days
    }
}
