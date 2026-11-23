package io.github.capitan0n.droynis.platform

import android.annotation.TargetApi
import android.content.Context
import android.net.TetheringInterface
import android.net.TetheringManager
import android.os.Build
import io.github.capitan0n.droynis.checks.adb.Dumpsys
import io.github.capitan0n.droynis.checks.adb.TetheringDump
import io.github.capitan0n.droynis.checks.base.TetheringProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

internal class AndroidTethering(private val context: Context, private val dumpsys: Dumpsys) : TetheringProbe {
    override suspend fun active(canDump: Boolean): Reading<Set<String>> {
        if (Build.VERSION.SDK_INT >= 36) {
            val snapshot = publicSnapshot()
            if (snapshot is Reading.Value || !canDump) return snapshot
        }
        if (!canDump) return Reading.Unsupported("requires Android 16 or the ADB tier", Source("TetheringManager"))
        val dump = if (Build.VERSION.SDK_INT >= 30) dumpsys.dump("tethering")
        else dumpsys.dump("connectivity", "tethering")
        return when (dump) {
            is Reading.Value -> TetheringDump.active(dump.value)?.let { Reading.Value(it, dump.source) }
                ?: Reading.Unavailable("no complete tethering state table", dump.source)
            is Reading.Unsupported -> dump
            is Reading.Unavailable -> dump
        }
    }

    @TargetApi(36)
    private suspend fun publicSnapshot(): Reading<Set<String>> {
        val source = Source("TetheringManager.onTetheredInterfacesChanged")
        return probe(source) {
            val manager = context.getSystemService(TetheringManager::class.java)
                ?: return@probe Reading.Unsupported("no tethering service", source)
            val first = CompletableDeferred<Set<String>>()
            val callback = object : TetheringManager.TetheringEventCallback {
                override fun onTetheredInterfacesChanged(interfaces: Set<TetheringInterface>) {
                    first.complete(interfaces.mapTo(sortedSetOf()) {
                        // AOSP TetheringManager type values. Only WIFI has a named public constant.
                        when (it.type) {
                            TetheringManager.TETHERING_WIFI -> "Wi-Fi"
                            1, 4 -> "USB" // USB and USB NCM
                            2 -> "Bluetooth"
                            3 -> "Wi-Fi Direct"
                            5 -> "Ethernet"
                            else -> "another interface"
                        }
                    })
                }
            }
            manager.registerTetheringEventCallback(Runnable::run, callback)
            try {
                withTimeoutOrNull(3_000) { Reading.Value(first.await(), source) }
                    ?: Reading.Unavailable("no initial tethering status received", source)
            } finally {
                manager.unregisterTetheringEventCallback(callback)
            }
        }
    }
}
