package io.github.capitan0n.droynis.platform

import android.content.Context
import android.os.PowerManager
import io.github.capitan0n.droynis.checks.base.BatteryProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The power allowlist, one package at a time. `isIgnoringBatteryOptimizations` needs no permission;
 * Android 11+ answers false for packages hidden from the caller, which QUERY_ALL_PACKAGES prevents.
 */
internal class AndroidBattery(context: Context) : BatteryProbe {

    private val power: PowerManager? = context.getSystemService(PowerManager::class.java)

    override fun unrestricted(packages: List<String>): Reading<Set<String>> {
        val source = Source("PowerManager.isIgnoringBatteryOptimizations()")
        return probe(source) {
            val manager = power ?: return@probe Reading.Unsupported("no power service", source)
            Reading.Value(packages.filterTo(linkedSetOf()) { manager.isIgnoringBatteryOptimizations(it) }, source)
        }
    }
}
