package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import io.github.capitan0n.droynis.checks.base.UsbProbe
import io.github.capitan0n.droynis.checks.base.UsbState
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The sticky `USB_STATE` broadcast UsbDeviceManager sends on each USB change. Its action and extras
 * are hidden constants, hence the literals. Any app may read it, with no permission; Android 17
 * doesn't redact it the way it redacts `adb_enabled`.
 */
internal class AndroidUsb(private val context: Context) : UsbProbe {

    override fun state(): Reading<UsbState?> {
        val source = Source("sticky broadcast $ACTION_USB_STATE")
        return probe(source) {
            val intent = stickyIntent(IntentFilter(ACTION_USB_STATE))
            val state = intent?.let {
                UsbState(connected = it.getBooleanExtra(EXTRA_CONNECTED, false), adb = it.getBooleanExtra(EXTRA_ADB, false))
            }
            Reading.Value(state, source)
        }
    }

    /**
     * With a null receiver, registerReceiver only returns the last sticky intent and registers
     * nothing, so the export flag exposes nothing. Without a flag Android treats it as exported
     * anyway; passing it keeps lint's UnspecifiedRegisterReceiverFlag quiet from API 33.
     */
    private fun stickyIntent(filter: IntentFilter): Intent? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(null, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(null, filter)
        }

    private companion object {
        /** `UsbManager.ACTION_USB_STATE` (hidden) */
        const val ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE"

        /** `UsbManager.USB_CONNECTED` (hidden): connected to a USB host. */
        const val EXTRA_CONNECTED = "connected"

        /** `UsbManager.USB_FUNCTION_ADB` (hidden): adb is a USB function in use. */
        const val EXTRA_ADB = "adb"
    }
}
