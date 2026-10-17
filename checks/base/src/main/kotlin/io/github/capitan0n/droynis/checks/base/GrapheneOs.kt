package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading

/**
 * Recognizes GrapheneOS, which replaces some of Android's all-in-one switches with finer settings
 * of its own: it has no Advanced Protection switch, for example.
 */
internal object GrapheneOs {
    /**
     * Vanadium's WebView. Only packages the system image allows can provide WebView, and GrapheneOS
     * allows only this one.
     */
    const val VANADIUM_WEBVIEW = "app.vanadium.webview"

    /**
     * GrapheneOS's own apps (App Store, Info, setup wizard…). Some, such as its camera, are also
     * published for other phones, so only preinstalled ones count.
     */
    const val APP_PREFIX = "app.grapheneos."

    /**
     * What shows that this phone runs GrapheneOS; empty when nothing does. The app list is read only
     * when the WebView doesn't already tell.
     */
    fun signs(webView: WebViewProbe, packages: PackageInventory): List<Evidence> {
        val provider = webView.provider()
        if (provider is Reading.Value && provider.value?.packageName == VANADIUM_WEBVIEW) {
            val note = "Vanadium, GrapheneOS's WebView"
            return listOf(Evidence("WebView provider", VANADIUM_WEBVIEW, provider.source, note = note))
        }
        val apps = packages.installedApps()
        if (apps !is Reading.Value) return emptyList()
        val own = apps.value.filter { it.isSystem && it.packageName.startsWith(APP_PREFIX) }
            .map { it.packageName }
            .sorted()
        if (own.isEmpty()) return emptyList()
        return listOf(Evidence("GrapheneOS apps in the system image", own.joinNames(), apps.source))
    }
}
