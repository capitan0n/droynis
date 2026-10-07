package io.github.capitan0n.droynis.checks.adb

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import org.junit.jupiter.api.Test

class AppOpsDumpTest {

    @Test
    fun `reads accesses with their package, op, app state and age`() {
        val result = assertIs<AppOpsDump.Result.Parsed>(AppOpsDump.parse(SAMPLE))

        assertEquals(3, result.packages)
        assertEquals(
            listOf(
                OpAccess("android", "WAKE_LOCK", "pers", 1.seconds + 2.milliseconds),
                OpAccess("org.example.maps", "FINE_LOCATION", "top", 2.hours + 3.minutes + 4.seconds + 5.milliseconds),
                OpAccess("org.example.maps", "FINE_LOCATION", "bg", 1.days + 4.seconds),
                OpAccess("org.example.recorder", "RECORD_AUDIO", "cch", 12.milliseconds),
            ),
            result.accesses,
        )
    }

    @Test
    fun `an access line in an unknown shape fails the whole parse`() {
        val changed = SAMPLE.replace("Access: [bg-s] 2026", "Access: bg 2026")

        assertIs<AppOpsDump.Result.Failed>(AppOpsDump.parse(changed))
    }

    @Test
    fun `output without per-app data or without any access fails`() {
        assertIs<AppOpsDump.Result.Failed>(AppOpsDump.parse(""))
        assertIs<AppOpsDump.Result.Failed>(AppOpsDump.parse("Permission Denial: can't dump appops"))
        assertIs<AppOpsDump.Result.Failed>(
            AppOpsDump.parse("AppOps Uid Op State\n  Uid u0a1:\n    Package org.example:\n      CAMERA (allow):\n"),
        )
    }

    @Test
    fun `an access outside any package or op is not silently dropped`() {
        val orphan = "AppOps Uid Op State\n  Uid u0a1:\n" +
            "          Access: [bg-s] 2026-10-05 12:00:00.000 (-1s0ms)\n" +
            "    Package org.example:\n      CAMERA (allow):\n" +
            "          Access: [top-s] 2026-10-05 12:00:00.000 (-1s0ms)\n"

        assertIs<AppOpsDump.Result.Failed>(AppOpsDump.parse(orphan))
    }

    @Test
    fun `durations follow android TimeUtils`() {
        assertEquals(Duration.ZERO, AppOpsDump.parseDuration("0"))
        assertEquals(-(12.milliseconds), AppOpsDump.parseDuration("-12ms"))
        assertEquals(-(5.seconds), AppOpsDump.parseDuration("-5s0ms"))
        assertEquals(-(2.minutes + 1.milliseconds), AppOpsDump.parseDuration("-2m0s1ms"))
        assertEquals(-(1.days + 5.seconds), AppOpsDump.parseDuration("-1d0h0m5s0ms"))
        assertEquals(3.hours, AppOpsDump.parseDuration("+3h0m0s0ms"))
        assertNull(AppOpsDump.parseDuration("5 minutes ago"))
        assertNull(AppOpsDump.parseDuration("-5m"))
    }

    companion object {
        /** Shaped like Android 17 output: restrictions first, then the per-app part. */
        val SAMPLE = """
            Current AppOps Service state:
              Settings:
                top_state_settle_time=+5s0ms
            AppOps Restrictions
              User restrictions for token android.os.Binder@1a2b3c:
                Restricted ops: [CAMERA]

            AppOps Uid Op State
              Uid 1000:
                state=pers
                capability=LCMNU
                Package android:
                  WAKE_LOCK (allow):
                    null=[
                      Access: [pers-s] 2026-10-05 11:59:59.000 (-1s2ms)
                    ]
              Uid u0a120:
                state=cch
                  CAMERA: mode=ignore
                Package org.example.maps:
                  COARSE_LOCATION (allow / switch FINE_LOCATION=allow):
                    null=[
                    ]
                  FINE_LOCATION (allow):
                    null=[
                      Access: [top-s] 2026-10-05 09:56:55.995 (-2h3m4s5ms) duration=+1m0s0ms
                      Access: [bg-s] 2026-10-04 11:59:56.000 (-1d0h0m4s0ms)
                      Reject: [cch-s]2026-10-01 10:00:00.000 (-4d2h0m0s0ms)
                    ]
              Uid u0a121:
                state=cch
                Package org.example.recorder:
                  RECORD_AUDIO (allow):
                    rec=[
                      Access: [cch-s] 2026-10-05 11:59:59.988 (-12ms) proxy[uid=1000, pkg=android, attributionTag=null]
                      Running start at: +5s0ms
                    ]

        """.trimIndent()
    }
}
