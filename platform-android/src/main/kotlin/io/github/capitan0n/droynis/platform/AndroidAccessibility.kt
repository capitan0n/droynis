package io.github.capitan0n.droynis.platform

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import io.github.capitan0n.droynis.checks.base.AccessibilityProbe
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal class AndroidAccessibility(
    private val context: Context,
    private val label: (String) -> String,
) : AccessibilityProbe {

    override fun enabledServices(): Reading<List<AppRef>> {
        val source = Source("AccessibilityManager.getEnabledAccessibilityServiceList()")
        val manager = context.getSystemService(AccessibilityManager::class.java)
            ?: return Reading.Unsupported("no AccessibilityManager service", source)
        return probe(source) {
            val apps = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
                .distinct()
                .map { AppRef(it, label(it)) }
            Reading.Value(apps, source)
        }
    }
}
