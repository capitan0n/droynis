package io.github.capitan0n.droynis.platform.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import io.github.capitan0n.droynis.checks.shizuku.PrivilegedShell
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.platform.ShellAccess
import io.github.capitan0n.droynis.platform.probe
import io.github.capitan0n.droynis.platform.readDumpsys
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import rikka.shizuku.Shizuku

/** Where Shizuku stands for Droynis, from not installed to connected. */
enum class ShizukuState {
    /** Neither the Shizuku app nor Sui is installed. */
    NOT_INSTALLED,

    /** Installed, but its service is not running: start it in the Shizuku app. */
    NOT_RUNNING,

    /** Running a version before 11, which Droynis can't use. */
    OUTDATED,

    /** Running; Droynis has not been allowed yet. */
    NOT_ALLOWED,

    /** The user denied Droynis and chose not to be asked again: allow it in the Shizuku app. */
    DENIED,

    /** Allowed, but Droynis' shell is not running yet, or failed to start. */
    ALLOWED,

    /** Allowed, and Droynis' read-only shell is running. */
    CONNECTED,
}

data class ShizukuStatus(
    val state: ShizukuState,
    /** Shizuku's service version, while it runs. */
    val version: Int? = null,
    /** True when Shizuku runs as root rather than as the adb shell user. */
    val asRoot: Boolean = false,
    /** Why the shell failed to start last time, if it did. */
    val error: String? = null,
)

/**
 * Droynis' side of Shizuku: its state, the permission request, and the read-only [ShellService],
 * which starts on demand and stops with the app. Shizuku calls back on the main thread.
 */
class ShizukuShell(context: Context) : PrivilegedShell, ShellAccess {

    private val app = context.applicationContext
    private val lock = Any()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    @Volatile
    private var service: IShellService? = null

    @Volatile
    private var lastError: String? = null

    /** Set while a bind is in flight, so concurrent callers wait for the same one. */
    private var pending: CountDownLatch? = null

    private val args = Shizuku.UserServiceArgs(ComponentName(app.packageName, ShellService::class.java.name))
        // Not a daemon: Shizuku stops the shell when Droynis unbinds or its process dies.
        .daemon(false)
        .processNameSuffix("shell")
        .tag("shell")
        .version(SERVICE_VERSION)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (binder != null && binder.pingBinder()) {
                service = IShellService.Stub.asInterface(binder)
                lastError = null
            } else {
                lastError = "Shizuku started the shell, but it did not answer"
            }
            synchronized(lock) { pending?.countDown() }
            notifyChanged()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
            notifyChanged()
        }
    }

    private val binderReceived = Shizuku.OnBinderReceivedListener { notifyChanged() }
    private val binderDead = Shizuku.OnBinderDeadListener {
        service = null
        notifyChanged()
    }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { requestCode, _ ->
        if (requestCode == REQUEST_CODE) notifyChanged()
    }

    init {
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)
    }

    /** True while Droynis' shell is running and reachable. */
    val isConnected: Boolean get() = service?.asBinder()?.isBinderAlive == true

    override val isReady: Boolean get() = isConnected

    /** Called on the main thread whenever Shizuku starts, stops, answers a permission request or connects. */
    fun addListener(listener: () -> Unit) {
        listeners += listener
    }

    fun removeListener(listener: () -> Unit) {
        listeners -= listener
    }

    /** Shizuku's state right now. Asks Shizuku over binder, so call it off the main thread. */
    fun status(): ShizukuStatus {
        if (!Shizuku.pingBinder()) {
            return ShizukuStatus(if (isInstalled()) ShizukuState.NOT_RUNNING else ShizukuState.NOT_INSTALLED)
        }
        return try {
            if (Shizuku.isPreV11()) return ShizukuStatus(ShizukuState.OUTDATED)
            val state = when {
                Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED ->
                    if (Shizuku.shouldShowRequestPermissionRationale()) ShizukuState.DENIED else ShizukuState.NOT_ALLOWED
                isConnected -> ShizukuState.CONNECTED
                else -> ShizukuState.ALLOWED
            }
            ShizukuStatus(state, Shizuku.getVersion(), asRoot = Shizuku.getUid() == ROOT_UID, error = lastError)
        } catch (e: RuntimeException) {
            // Shizuku stopped between the ping and these calls.
            ShizukuStatus(ShizukuState.NOT_RUNNING)
        }
    }

    /** Shows Shizuku's own dialog asking the user to allow Droynis; false when it can't be shown. */
    fun requestPermission(): Boolean = try {
        if (Shizuku.pingBinder() && !Shizuku.isPreV11()) {
            Shizuku.requestPermission(REQUEST_CODE)
            true
        } else {
            false
        }
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Starts Droynis' shell when Shizuku allows it and waits up to [timeoutMillis] for it; returns
     * whether it runs. Shizuku reports the connection on the main thread, so this must not run there.
     */
    fun connect(timeoutMillis: Long = CONNECT_TIMEOUT_MILLIS): Boolean {
        check(Looper.myLooper() != Looper.getMainLooper()) { "connect() blocks; call it off the main thread" }
        if (isConnected) return true
        val latch = synchronized(lock) {
            if (isConnected) return true
            pending ?: run {
                if (!allowed()) return false
                val bind = CountDownLatch(1)
                pending = bind
                try {
                    Shizuku.bindUserService(args, connection)
                } catch (e: RuntimeException) {
                    pending = null
                    lastError = "Shizuku refused to start the shell: ${e.message}"
                    return false
                }
                bind
            }
        }
        latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
        synchronized(lock) {
            if (pending === latch) pending = null
        }
        if (!isConnected && lastError == null) {
            lastError = "Droynis' shell did not start within ${timeoutMillis / 1000} seconds"
        }
        return isConnected
    }

    /** Stops the shell and stops listening to Shizuku. */
    fun close() {
        Shizuku.removeBinderReceivedListener(binderReceived)
        Shizuku.removeBinderDeadListener(binderDead)
        Shizuku.removeRequestPermissionResultListener(permissionResult)
        listeners.clear()
        if (service != null) {
            try {
                Shizuku.unbindUserService(args, connection, true)
            } catch (e: RuntimeException) {
                // Shizuku already stopped, and the shell with it.
            }
        }
        service = null
    }

    override fun readSetting(table: String, key: String): Reading<String?> =
        call(Source("settings get $table $key", Grant.SHIZUKU)) { shell, source ->
            Reading.Value(shell.readSetting(table, key, Process.myUid() / PER_USER_RANGE), source)
        }

    override fun selinuxMode(): Reading<String> =
        call(Source("getenforce", Grant.SHIZUKU)) { shell, source -> Reading.Value(shell.selinuxMode(), source) }

    override fun telephony(): Reading<String> =
        call(Source(TELEPHONY_SOURCE, Grant.SHIZUKU)) { shell, source -> Reading.Value(shell.telephony().orEmpty(), source) }

    /** Streamed through a pipe: the output can be larger than one binder call carries. */
    override fun dumpsys(service: String): Reading<String> =
        call(Source("dumpsys $service", Grant.SHIZUKU)) { shell, source ->
            val pipe = shell.dumpsys(service) ?: return@call Reading.Unavailable("the shell returned no output", source)
            ParcelFileDescriptor.AutoCloseInputStream(pipe).bufferedReader().use { readDumpsys(it, source) }
        }

    private inline fun <T> call(source: Source, block: (IShellService, Source) -> Reading<T>): Reading<T> {
        val shell = service ?: return Reading.Unavailable("Shizuku is not connected", source)
        return probe(source) {
            try {
                block(shell, source)
            } catch (e: DeadObjectException) {
                service = null
                Reading.Unavailable("Shizuku stopped during the scan", source)
            }
        }
    }

    private fun allowed(): Boolean = try {
        Shizuku.pingBinder() && !Shizuku.isPreV11() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (e: RuntimeException) {
        false
    }

    private fun isInstalled(): Boolean = app.packageManager.getLaunchIntentForPackage(MANAGER_PACKAGE) != null

    private fun notifyChanged() {
        listeners.forEach { it() }
    }

    companion object {
        /** The Shizuku app, to open it or tell whether it is installed. */
        const val MANAGER_PACKAGE = "moe.shizuku.privileged.api"

        /** Bump when [ShellService] changes, so Shizuku replaces a shell left from an older Droynis. */
        private const val SERVICE_VERSION = 3

        private const val REQUEST_CODE = 0x0D50
        private const val CONNECT_TIMEOUT_MILLIS = 10_000L
        private const val ROOT_UID = 0

        /** `UserHandle.PER_USER_RANGE`: uids of each Android user start at a multiple of it. */
        private const val PER_USER_RANGE = 100_000

        const val TELEPHONY_SOURCE = "telephony service: isIccLockEnabled, getAllowedNetworkTypesForReason"
    }
}
