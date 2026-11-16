package io.github.capitan0n.droynis.platform

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.ActivityManager
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import android.view.WindowManager
import io.github.capitan0n.droynis.checks.base.ExtraDisplay
import io.github.capitan0n.droynis.checks.base.ScreenCaptureProbe
import io.github.capitan0n.droynis.checks.base.ScreenRecording
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.util.function.Consumer

/** Screen recording and extra displays, as Android shows them to Droynis itself. */
internal class AndroidScreenCapture(private val context: Context) : ScreenCaptureProbe {

    override fun recording(): Reading<ScreenRecording> {
        val source = Source("WindowManager.addScreenRecordingCallback()")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            return Reading.Unsupported("needs Android 15", source)
        }
        return probe(source) {
            // Android answers for the app's own windows only: off screen, "not recorded" would mean nothing.
            if (!onScreen()) return@probe Reading.Unavailable("Droynis isn't on screen, so Android doesn't say", source)
            val windows = context.getSystemService(WindowManager::class.java)
                ?: return@probe Reading.Unavailable("no window manager", source)
            Reading.Value(Recording.state(windows), source)
        }
    }

    override fun extraDisplays(): Reading<List<ExtraDisplay>> {
        val source = Source("DisplayManager.getDisplays()")
        return probe(source) {
            val manager = context.getSystemService(DisplayManager::class.java)
                ?: return@probe Reading.Unavailable("no display manager", source)
            val displays = manager.displays
                .filter { it.displayId != Display.DEFAULT_DISPLAY }
                .map { display ->
                    ExtraDisplay(
                        displayId = display.displayId,
                        name = display.name.orEmpty(),
                        ownerPackage = ownerOf(display),
                        presentation = (display.flags and Display.FLAG_PRESENTATION) != 0,
                    )
                }
            Reading.Value(displays, source)
        }
    }

    /** Droynis has an activity in the foreground, so a recording of the screen would show it. */
    private fun onScreen(): Boolean {
        val state = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(state)
        return state.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    }

    /**
     * The app that made a virtual display. `Display.getOwnerPackageName()` is hidden, so it is read by
     * reflection, and failing that from what `Display.toString()` prints ("owner com.example (uid 10123)").
     * Null for a physical screen, and when Android blocks both.
     */
    @SuppressLint("DiscouragedPrivateApi", "PrivateApi")
    private fun ownerOf(display: Display): String? {
        val reflected = runCatching { Display::class.java.getMethod("getOwnerPackageName").invoke(display) as? String }.getOrNull()
        val printed = OWNER.find(display.toString())?.groupValues?.get(1)
        return (reflected ?: printed)?.takeIf { it.isNotBlank() && it != "null" }
    }

    @TargetApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private object Recording {
        /** Registers a callback only for the answer it returns at once, then removes it. */
        fun state(windows: WindowManager): ScreenRecording {
            val callback = Consumer<Int> { }
            val state = windows.addScreenRecordingCallback(Runnable::run, callback)
            windows.removeScreenRecordingCallback(callback)
            return if (state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE) ScreenRecording.RECORDED else ScreenRecording.NOT_RECORDED
        }
    }

    private companion object {
        val OWNER = Regex("""owner ([A-Za-z0-9_.]+) \(uid""")
    }
}
