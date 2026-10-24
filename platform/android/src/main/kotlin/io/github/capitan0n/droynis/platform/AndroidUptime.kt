package io.github.capitan0n.droynis.platform

import android.os.SystemClock
import io.github.capitan0n.droynis.checks.base.UptimeProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** The clock since boot, deep sleep included; it needs no permission. */
internal object AndroidUptime : UptimeProbe {
    override fun sinceBoot(): Reading<Duration> {
        val source = Source("SystemClock.elapsedRealtime()")
        return probe(source) { Reading.Value(SystemClock.elapsedRealtime().milliseconds, source) }
    }
}
