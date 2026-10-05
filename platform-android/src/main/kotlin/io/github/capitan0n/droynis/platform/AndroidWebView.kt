package io.github.capitan0n.droynis.platform

import android.webkit.WebView
import io.github.capitan0n.droynis.checks.base.WebViewInfo
import io.github.capitan0n.droynis.checks.base.WebViewProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.time.Instant
import java.time.ZoneId

/** Asks which package provides WebView without loading the browser engine into Droynis. */
internal object AndroidWebView : WebViewProbe {
    override fun provider(): Reading<WebViewInfo?> {
        val source = Source("WebView.getCurrentWebViewPackage()")
        return probe(source) {
            val info = WebView.getCurrentWebViewPackage() ?: return@probe Reading.Value(null, source)
            Reading.Value(
                WebViewInfo(
                    packageName = info.packageName,
                    versionName = info.versionName.orEmpty(),
                    lastUpdated = Instant.ofEpochMilli(info.lastUpdateTime).atZone(ZoneId.systemDefault()).toLocalDate(),
                ),
                source,
            )
        }
    }
}
