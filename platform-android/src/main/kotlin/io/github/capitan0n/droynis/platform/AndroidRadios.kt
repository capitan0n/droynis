package io.github.capitan0n.droynis.platform

import android.content.Context
import android.location.LocationManager
import android.nfc.NfcAdapter
import android.os.Build
import android.provider.Settings
import io.github.capitan0n.droynis.checks.base.RadioProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** NfcAdapter.isEnabled() and LocationManager.isLocationEnabled() need no permission. */
internal class AndroidRadios(private val context: Context) : RadioProbe {

    override fun nfcEnabled(): Reading<Boolean> {
        val source = Source("NfcAdapter.isEnabled()")
        return probe(source) {
            val adapter = NfcAdapter.getDefaultAdapter(context)
                ?: return@probe Reading.Unsupported("this device has no NFC hardware", source)
            Reading.Value(adapter.isEnabled, source)
        }
    }

    override fun locationEnabled(): Reading<Boolean> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return legacyLocationMode()
        val source = Source("LocationManager.isLocationEnabled()")
        val manager = context.getSystemService(LocationManager::class.java)
            ?: return Reading.Unsupported("no LocationManager service", source)
        return probe(source) { Reading.Value(manager.isLocationEnabled, source) }
    }

    /** Android 8: the switch is the LOCATION_MODE setting, deprecated (but still kept) since Android 9. */
    @Suppress("DEPRECATION")
    private fun legacyLocationMode(): Reading<Boolean> {
        val source = Source("Settings.Secure \"${Settings.Secure.LOCATION_MODE}\"")
        return probe(source) {
            val mode = Settings.Secure.getInt(context.contentResolver, Settings.Secure.LOCATION_MODE)
            Reading.Value(mode != Settings.Secure.LOCATION_MODE_OFF, source)
        }
    }
}
