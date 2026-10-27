package io.github.capitan0n.droynis.platform

import android.annotation.SuppressLint
import android.os.IBinder
import io.github.capitan0n.droynis.checks.base.TelephonyDump
import java.lang.reflect.InvocationTargetException
import kotlin.system.exitProcess

/**
 * Reads what Android tells only privileged callers about each active SIM: whether its PIN lock is on
 * (`isIccLockEnabled`, Android 11+) and the network types each reason allows, the Allow 2G switch
 * among them (`getAllowedNetworkTypesForReason`, Android 12+). Then the device-wide mobile network
 * security switches: whether connections without encryption are allowed (Android 14+) and whether
 * the phone warns about them and about identity requests in the clear (Android 15+); a modem without
 * them makes the service throw UnsupportedOperationException. The shell user holds the permission all
 * of these need, READ_PRIVILEGED_PHONE_STATE, and root passes every permission check.
 *
 * It never runs in the app: Droynis' Shizuku shell calls [read] as the shell user, and the root shell
 * starts [main] in an `app_process` for one read, as scrcpy and Shizuku start their own code. It talks
 * to the framework's telephony services directly, calls only getters and keeps no state. The output
 * is [TelephonyDump]'s format.
 *
 * The services are internal APIs, reached by reflection. Android's hidden-API restrictions apply to
 * app processes only, and this code never runs in one.
 */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi", "SoonBlockedPrivateApi", "BlockedPrivateApi")
object TelephonyReader {

    /** Entry point for `app_process`: prints one read to stdout and ends the process. */
    @JvmStatic
    fun main(args: Array<String>) {
        println(read())
        System.out.flush()
        // Binder threads could keep the process alive; the root shell waits for it to end.
        exitProcess(0)
    }

    fun read(): String = buildString {
        appendLine(TelephonyDump.HEADER)
        try {
            val sub = service("isub", "com.android.internal.telephony.ISub")
            val phone = service("phone", "com.android.internal.telephony.ITelephony")
            // Visible subscriptions only: the SIMs Settings lists.
            for (id in sub.call("getActiveSubIdList", true) as IntArray) appendLine(line(sub, phone, id))
            appendLine(security(phone))
        } catch (e: Exception) {
            appendLine("error=${describe(e)}")
        }
    }.trimEnd()

    private fun line(sub: Service, phone: Service, id: Int): String = buildString {
        append("sub=").append(id)
        attempt { sub.call("getSlotIndex", id) as Int }.value?.let { append(" slot=").append(it) }
        val pin = attempt { phone.call("isIccLockEnabled", id) as Boolean }
        append(" pin=").append(pin.value ?: "?")
        pin.error?.let { append(" pin_error=").append(it) }
        // A reason this Android doesn't have fails with IllegalArgumentException and is left out.
        for (reason in REASONS) {
            attempt { phone.call("getAllowedNetworkTypesForReason", id, reason) as Long }.value?.let {
                append(" reason").append(reason).append('=').append(it)
            }
        }
    }

    /** The device-wide switches on one line; a getter this Android or modem lacks reads `?` with its exception. */
    private fun security(phone: Service): String = buildString {
        append(TelephonyDump.SECURITY)
        for ((key, getter) in SECURITY_GETTERS) {
            val read = attempt { phone.call(getter) as Boolean }
            append(' ').append(key).append('=').append(read.value ?: "?")
            read.error?.let { append(' ').append(key).append("_error=").append(it) }
        }
    }

    /** A system service's AIDL interface, called through the interface so the proxy class's access doesn't matter. */
    private class Service(private val api: Class<*>, private val instance: Any) {
        fun call(name: String, vararg args: Any): Any? {
            val types = args.map {
                when (it) {
                    is Int -> Int::class.javaPrimitiveType!!
                    is Boolean -> Boolean::class.javaPrimitiveType!!
                    else -> it.javaClass
                }
            }
            return try {
                api.getMethod(name, *types.toTypedArray()).invoke(instance, *args)
            } catch (e: InvocationTargetException) {
                throw (e.targetException as? Exception ?: e)
            }
        }
    }

    private fun service(name: String, aidl: String): Service {
        val binder = Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java)
            .invoke(null, name) as IBinder? ?: throw IllegalStateException("no $name service")
        val instance = Class.forName("$aidl\$Stub").getMethod("asInterface", IBinder::class.java).invoke(null, binder)
            ?: throw IllegalStateException("the $name service has no $aidl interface")
        return Service(Class.forName(aidl), instance)
    }

    private class Attempt<T>(val value: T?, val error: String?)

    private inline fun <T> attempt(read: () -> T): Attempt<T> = try {
        Attempt(read(), null)
    } catch (e: Exception) {
        Attempt(null, e.javaClass.simpleName)
    }

    private fun describe(e: Exception): String = "${e.javaClass.simpleName}: ${e.message}".replace('\n', ' ').take(MAX_ERROR)

    /** `TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_*`: user, power, carrier, enable 2G, user restrictions. */
    private val REASONS = 0..4

    /** `ITelephony` getters behind [TelephonyDump]'s security keys. */
    private val SECURITY_GETTERS = listOf(
        TelephonyDump.NULL_CIPHER to "isNullCipherAndIntegrityPreferenceEnabled",
        TelephonyDump.NULL_CIPHER_ALERTS to "isNullCipherNotificationsEnabled",
        TelephonyDump.IDENTIFIER_ALERTS to "isCellularIdentifierDisclosureNotificationsEnabled",
    )

    private const val MAX_ERROR = 200
}
