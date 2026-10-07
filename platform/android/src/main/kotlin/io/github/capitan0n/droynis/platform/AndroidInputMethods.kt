package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.ApplicationInfo
import android.view.inputmethod.InputMethodManager
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.checks.base.InputMethodProbe
import io.github.capitan0n.droynis.checks.base.Keyboard
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** On Android 11+ the list is filtered by package visibility, which QUERY_ALL_PACKAGES covers. */
internal class AndroidInputMethods(
    private val context: Context,
    private val label: (String) -> String,
) : InputMethodProbe {

    override fun enabledKeyboards(): Reading<List<Keyboard>> {
        val source = Source("InputMethodManager.getEnabledInputMethodList()")
        val manager = context.getSystemService(InputMethodManager::class.java)
            ?: return Reading.Unsupported("no InputMethodManager service", source)
        return probe(source) {
            val keyboards = manager.enabledInputMethodList.map { info ->
                val flags = info.serviceInfo?.applicationInfo?.flags ?: 0
                Keyboard(
                    app = AppRef(info.packageName, label(info.packageName)),
                    isSystem = (flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }
            Reading.Value(keyboards, source)
        }
    }
}
