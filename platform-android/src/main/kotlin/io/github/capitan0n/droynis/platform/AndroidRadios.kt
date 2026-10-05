package io.github.capitan0n.droynis.platform

import android.content.Context
import android.nfc.NfcAdapter
import io.github.capitan0n.droynis.checks.base.RadioProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** NfcAdapter.isEnabled() needs no permission. */
internal class AndroidRadios(private val context: Context) : RadioProbe {

    override fun nfcEnabled(): Reading<Boolean> {
        val source = Source("NfcAdapter.isEnabled()")
        return probe(source) {
            val adapter = NfcAdapter.getDefaultAdapter(context)
                ?: return@probe Reading.Unsupported("this device has no NFC hardware", source)
            Reading.Value(adapter.isEnabled, source)
        }
    }
}
