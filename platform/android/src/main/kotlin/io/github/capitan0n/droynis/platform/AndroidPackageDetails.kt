package io.github.capitan0n.droynis.platform

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import io.github.capitan0n.droynis.checks.base.PackageDetails
import io.github.capitan0n.droynis.checks.base.PackageDetailsProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.security.MessageDigest

/** One package in detail; needs QUERY_ALL_PACKAGES like [AndroidPackages]. */
internal class AndroidPackageDetails(context: Context) : PackageDetailsProbe {

    private val packageManager: PackageManager = context.packageManager

    override fun details(packageName: String): Reading<PackageDetails?> {
        val source = Source("PackageManager.getPackageInfo(\"$packageName\")")
        return probe(source) {
            val info = try {
                packageInfo(packageName, SIGNERS)
            } catch (e: PackageManager.NameNotFoundException) {
                return@probe Reading.Value(null, source)
            }
            val app = info.applicationInfo ?: return@probe Reading.Unavailable("no application info", source)
            val details = PackageDetails(
                isEnabled = app.enabled,
                inSystemImage = inSystemImage(packageName),
                signerSha1 = signers(info).mapTo(sortedSetOf()) { sha1(it.toByteArray()) },
                activities = activities(packageName),
            )
            Reading.Value(details, source)
        }
    }

    /**
     * `MATCH_SYSTEM_ONLY` filters on the package manager's own record of where the package was
     * installed, not on the flags it reports, which GrapheneOS sets on its sandboxed Google Play.
     */
    @Suppress("DEPRECATION")
    private fun inSystemImage(packageName: String): Boolean =
        try {
            val flags = PackageManager.MATCH_SYSTEM_ONLY or PackageManager.MATCH_DISABLED_COMPONENTS
            packageManager.getApplicationInfo(packageName, flags)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }

    /** Every signer, past keys included where the package rotated its key (API 28+). */
    @Suppress("DEPRECATION") // PackageInfo.signatures is all Android 8 has
    private fun signers(info: PackageInfo): List<Signature> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = info.signingInfo ?: return emptyList()
            val signers = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
            signers.orEmpty().toList()
        } else {
            info.signatures.orEmpty().toList()
        }

    /** Its activities' class names, or null when they can't be read: a large app can exceed the binder limit. */
    private fun activities(packageName: String): List<String>? =
        try {
            packageInfo(packageName, PackageManager.GET_ACTIVITIES).activities.orEmpty().map { it.name }
        } catch (e: Exception) {
            null
        }

    @Suppress("DEPRECATION") // the PackageInfoFlags overload needs API 33
    private fun packageInfo(packageName: String, flags: Int): PackageInfo = packageManager.getPackageInfo(packageName, flags)

    private fun sha1(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        // GET_SIGNATURES is what Android 8 has. Droynis only names the key, it doesn't trust it.
        @Suppress("DEPRECATION")
        @SuppressLint("PackageManagerGetSignatures")
        val SIGNERS =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
    }
}
