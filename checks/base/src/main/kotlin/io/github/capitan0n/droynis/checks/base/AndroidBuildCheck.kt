package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source

class AndroidBuildCheck(
    private val build: BuildInfo,
    private val properties: SystemProperties,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1060",
        category = Category.DEVICE_INTEGRITY,
        title = "Android build",
        severity = Severity.WARNING,
        explanation = "Phones ship \"user\" builds signed with the vendor's private keys. A userdebug or eng " +
            "build lets adb run as root, and a build signed with the public AOSP test keys lets anyone sign " +
            "an app or update that the system trusts as its own. With ro.adb.secure=0, any computer plugged " +
            "in while USB debugging is on gets adb without the \"Allow USB debugging?\" prompt, a critical " +
            "finding.",
        remediation = Remediation(
            text = "Install the official firmware, or a maintained OS that publishes signed user builds.",
        ),
        failsWhen = "it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 " +
            "(critical when ro.adb.secure=0 lets adb in without authorization)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val device = build.device()
        val props = properties.all()
        val visible = (props as? Reading.Value)?.value
        val debuggable = visible?.get(DEBUGGABLE)
        // SELinux may hide it from apps; a missing value proves nothing either way.
        val adbSecure = visible?.get(ADB_SECURE)
        val source = Source("Build.TYPE, Build.TAGS")
        val evidence = listOfNotNull(
            Evidence("Build type", device.buildType.ifEmpty { "(empty)" }, source),
            Evidence("Build tags", device.buildTags.ifEmpty { "(empty)" }, source),
            debuggable?.let { Evidence(DEBUGGABLE, it, props.source) },
            adbSecure?.let { Evidence(ADB_SECURE, it, props.source) },
        )
        val tags = device.buildTags.split(',').map { it.trim() }
        val unauthenticatedAdb = adbSecure?.trim() == "0"
        val problems = buildList {
            if (device.buildType.isNotEmpty() && device.buildType != "user") add("${device.buildType} build")
            if ("test-keys" in tags) add("public test keys")
            if (debuggable == "1") add("$DEBUGGABLE=1")
            if (unauthenticatedAdb) add("adb without authorization ($ADB_SECURE=0)")
        }
        return when {
            problems.isNotEmpty() -> Outcome.fail(
                "Insecure Android build: ${problems.joinNames(limit = 4)}",
                evidence,
                escalation = Severity.CRITICAL.takeIf { unauthenticatedAdb },
            )
            device.buildType == "user" -> Outcome.pass("A user build signed with ${device.buildTags.ifEmpty { "unknown keys" }}", evidence)
            else -> Outcome.unknown("The build type is not reported", evidence)
        }
    }

    companion object {
        const val DEBUGGABLE = "ro.debuggable"

        /** 0 tells adbd to accept every computer without the RSA key prompt. */
        const val ADB_SECURE = "ro.adb.secure"
    }
}
