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
            "an app or update that the system trusts as its own.",
        remediation = Remediation(
            text = "Install the official firmware, or a maintained OS that publishes signed user builds.",
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val device = build.device()
        val props = properties.all()
        val debuggable = (props as? Reading.Value)?.value?.get(DEBUGGABLE)
        val source = Source("Build.TYPE, Build.TAGS")
        val evidence = listOfNotNull(
            Evidence("Build type", device.buildType.ifEmpty { "(empty)" }, source),
            Evidence("Build tags", device.buildTags.ifEmpty { "(empty)" }, source),
            debuggable?.let { Evidence(DEBUGGABLE, it, props.source) },
        )
        val tags = device.buildTags.split(',').map { it.trim() }
        val problems = buildList {
            if (device.buildType.isNotEmpty() && device.buildType != "user") add("${device.buildType} build")
            if ("test-keys" in tags) add("public test keys")
            if (debuggable == "1") add("$DEBUGGABLE=1")
        }
        return when {
            problems.isNotEmpty() -> Outcome.fail("Insecure Android build: ${problems.joinNames(limit = 3)}", evidence)
            device.buildType == "user" -> Outcome.pass("A user build signed with ${device.buildTags.ifEmpty { "unknown keys" }}", evidence)
            else -> Outcome.unknown("The build type is not reported", evidence)
        }
    }

    companion object {
        const val DEBUGGABLE = "ro.debuggable"
    }
}
