package io.github.capitan0n.droynis.platform

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.UserManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import io.github.capitan0n.droynis.checks.base.CellularProbe
import io.github.capitan0n.droynis.checks.base.SimCard
import io.github.capitan0n.droynis.checks.base.SimTelephony
import io.github.capitan0n.droynis.checks.base.TelephonyDump
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * SIMs through public APIs that need no permission, plus [TelephonyReader]'s privileged read through
 * Shizuku or root. Droynis never asks for the phone permission: it reads no number, IMSI or ICCID.
 */
internal class AndroidCellular(context: Context, private val shells: ShellRouter) : CellularProbe {

    private val app = context.applicationContext
    private val lock = Any()

    // The 2G and SIM PIN checks share one successful privileged read per scan; as root it starts a process.
    private var cached: Pair<Long, Reading<List<SimTelephony>>>? = null

    override fun sims(): Reading<List<SimCard>> {
        val source = Source("TelephonyManager.getSimState and SubscriptionManager (no permission)")
        val features = app.packageManager
        if (!features.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
            return Reading.Unsupported("no mobile network hardware", source)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !features.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION)
        ) {
            return Reading.Unsupported("no SIM support", source)
        }
        val telephony = app.getSystemService(TelephonyManager::class.java)
            ?: return Reading.Unsupported("no TelephonyManager service", source)
        return probe(source) {
            val slots = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                telephony.activeModemCount
            } else {
                @Suppress("DEPRECATION")
                telephony.phoneCount
            }
            val ready = (0 until slots).filter { telephony.getSimState(it) == TelephonyManager.SIM_STATE_READY }
            val sims = if (ready.isEmpty()) {
                emptyList()
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ready.map { SimCard(it, subscriptionOf(it)) }
            } else {
                // Android 8 and 9 don't map slots to subscriptions for apps; the default SIMs are the ones in use.
                defaultSubscriptions().map { SimCard(null, it) }.ifEmpty { listOf(SimCard(null, null)) }
            }
            Reading.Value(sims, source)
        }
    }

    @TargetApi(Build.VERSION_CODES.Q)
    private fun subscriptionOf(slot: Int): Int? {
        val id = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            SubscriptionManager.getSubscriptionId(slot)
        } else {
            @Suppress("DEPRECATION")
            app.getSystemService(SubscriptionManager::class.java)?.getSubscriptionIds(slot)?.firstOrNull()
        }
        return id?.takeIf { SubscriptionManager.isValidSubscriptionId(it) }
    }

    private fun defaultSubscriptions(): List<Int> = listOf(
        SubscriptionManager.getDefaultDataSubscriptionId(),
        SubscriptionManager.getDefaultVoiceSubscriptionId(),
        SubscriptionManager.getDefaultSmsSubscriptionId(),
        SubscriptionManager.getDefaultSubscriptionId(),
    ).filter { it >= 0 && it != Int.MAX_VALUE }.distinct()

    override fun twoGDisallowed(): Reading<Boolean> {
        val source = Source("UserManager.hasUserRestriction(DISALLOW_CELLULAR_2G)")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return Reading.Unsupported("needs Android 14", source)
        val users = app.getSystemService(UserManager::class.java) ?: return Reading.Unsupported("no UserManager service", source)
        return probe(source) { Reading.Value(users.hasUserRestriction(UserManager.DISALLOW_CELLULAR_2G), source) }
    }

    override fun privileged(): Reading<List<SimTelephony>> = synchronized(lock) {
        val now = System.nanoTime()
        cached?.let { (at, reading) -> if (now - at < CACHE_NANOS) return reading }
        read().also { if (it is Reading.Value) cached = now to it }
    }

    private fun read(): Reading<List<SimTelephony>> = when (val raw = shells.telephony()) {
        is Reading.Unsupported -> raw
        is Reading.Unavailable -> raw
        is Reading.Value -> when (val parsed = TelephonyDump.parse(raw.value)) {
            is TelephonyDump.Result.Parsed -> Reading.Value(parsed.sims, raw.source)
            is TelephonyDump.Result.Failed -> Reading.Unavailable(parsed.reason, raw.source)
        }
    }

    private companion object {
        const val CACHE_NANOS = 10_000_000_000L
    }
}
