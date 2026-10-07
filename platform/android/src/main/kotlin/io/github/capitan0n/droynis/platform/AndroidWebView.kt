package io.github.capitan0n.droynis.platform

import android.content.pm.ApplicationInfo
import android.os.Build
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
            val flags = info.applicationInfo?.flags ?: 0
            // A system WebView that was never updated on its own (LineageOS and other ROMs update it
            // only with the OS) reports the file time from the system image, which reproducible
            // builds fix at 2009-01-01. It is as new as the system image it came with.
            val fromSystemImage = flags and ApplicationInfo.FLAG_SYSTEM != 0 &&
                flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0 &&
                info.lastUpdateTime < Build.TIME
            val updated = if (fromSystemImage) Build.TIME else info.lastUpdateTime
            Reading.Value(
                WebViewInfo(
                    packageName = info.packageName,
                    versionName = info.versionName.orEmpty(),
                    lastUpdated = Instant.ofEpochMilli(updated).atZone(ZoneId.systemDefault()).toLocalDate(),
                    fromSystemImage = fromSystemImage,
                ),
                source,
            )
        }
    }
}
