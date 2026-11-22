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
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

/**
 * States Droynis' blind spot. Android shows an app only the apps, permissions and settings of the
 * user or profile it runs in, so a work profile, a Private Space or another user is never part of a
 * scan. `UserManager.getUserProfiles()` counts the profiles of the caller's own group without any
 * permission; other users of the phone are not visible at all.
 */
class OtherProfilesCheck(private val profiles: ProfileProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4017",
        category = Category.APPS,
        title = "Profiles this scan doesn't cover",
        severity = Severity.INFO,
        explanation = "Android keeps each user and profile apart: an app sees only the apps and " +
            "permissions of the one it runs in. Apps in a work profile, a Private Space, a cloned-apps " +
            "profile or another user of the phone are not checked by this scan, whatever it reports " +
            "elsewhere. Android tells Droynis how many profiles share this user, but not what they are, " +
            "and nothing about other users; with the ADB tier, Shizuku or root Droynis reads the phone's " +
            "list of users too. This check is for your information and doesn't count in the score.",
        remediation = Remediation(
            text = "To check another profile or user, install Droynis there too and scan from inside it: " +
                "each copy sees only its own side. Remove profiles and users you no longer need under " +
                "Settings › System › Users, Settings › Security & privacy › Private Space, or Settings › " +
                "Passwords & accounts › Work.",
        ),
        failsWhen = "another profile shares this user, Droynis doesn't run in the phone's main user, or (ADB tier " +
            "and up) the phone has another user or profile (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val state = profiles.state()
        val evidence = listOf(
            state.toEvidence("Profiles of this user") { it.profiles.toString() },
            state.toEvidence("Runs in the phone's main user") { if (it.isSystemUser) "yes" else "no" },
        )
        return state.evaluate("The profiles of this user", evidence) { found ->
            // The list always holds the caller's own user; anything else is not what Android documents.
            if (found.profiles < 1) {
                return@evaluate Outcome.unknown("Android listed no profile at all, not even this one", evidence)
            }
            val others = found.profiles - 1
            // With the adb grants, Shizuku or root, the phone's whole user list is readable.
            val dump = profiles.usersDump()
            val users = (dump as? Reading.Value)?.value?.let(UserDump::parse)?.takeIf { it.size >= found.profiles }
            val outside = users?.let { it.size - found.profiles } ?: 0
            val userEvidence = users?.let { list ->
                listOf(Evidence("Users and profiles of the phone", list.size.toString(), dump.source)) + list.map { user ->
                    // A user's name is whatever its owner typed, often their own.
                    // The kind goes in the label: a report that hides personal details hides a personal row's note too.
                    Evidence("User ${user.id} (${user.kind})", user.name ?: "(no name)", dump.source, personal = user.name != null)
                }
            }.orEmpty()
            val alsoOutside = if (outside == 0) "" else "; ${count(outside, "more user or profile exists", "more users or profiles exist")} on the phone"
            when {
                others > 0 && !found.isSystemUser -> Outcome.fail(
                    "Droynis runs in a profile or secondary user that shares the phone with " +
                        "${count(others, "other profile")}: only this one was checked$alsoOutside",
                    evidence + userEvidence,
                )
                others > 0 -> Outcome.fail(
                    "${count(others, "other profile shares", "other profiles share")} this user, such as a " +
                        "work profile or Private Space: its apps were not checked$alsoOutside",
                    evidence + userEvidence,
                )
                !found.isSystemUser -> Outcome.fail(
                    "Droynis runs in a secondary user: the phone's other users were not checked",
                    evidence + userEvidence,
                )
                outside > 0 -> Outcome.fail(
                    "${count(outside, "other user or profile exists", "other users or profiles exist")} on this phone, " +
                        "such as a second user or a Secure Folder: ${if (outside == 1) "its" else "their"} apps were not checked",
                    evidence + userEvidence,
                )
                users != null -> Outcome.pass("This user is the only user and profile on the phone", evidence + userEvidence)
                else -> Outcome.pass(
                    "Android lists no other profile for this user",
                    evidence + Evidence("Other users of the phone", null, state.source, note = "not visible to apps"),
                )
            }
        }
    }
}

/** One user or profile of the phone, as `dumpsys user` lists it. */
data class DeviceUser(val id: Int, val name: String?, val flags: Int) {
    /** What kind of user the flags say it is, in words. */
    val kind: String
        get() = when {
            flags and FLAG_GUEST != 0 -> "guest"
            flags and FLAG_MANAGED_PROFILE != 0 -> "work or managed profile"
            flags and FLAG_PROFILE != 0 -> "profile"
            id == 0 -> "the phone's main user"
            else -> "another user"
        }

    private companion object {
        // `UserInfo.FLAG_*`, unchanged since they were added.
        const val FLAG_GUEST = 0x4
        const val FLAG_MANAGED_PROFILE = 0x20
        const val FLAG_PROFILE = 0x1000
    }
}

/**
 * Reads the users out of `dumpsys user`, which prints each as `UserInfo{<id>:<name>:<flags in hex>}`,
 * the form `UserInfo.toString()` has had since Android 4.2. Only those lines are read; the rest of
 * the dump differs by release.
 */
object UserDump {
    private val USER = Regex("""UserInfo\{(\d+):(.*):([0-9a-fA-F]+)\}""")

    /** Every user once, by id; null when the dump names none, so that it is never read as "no other user". */
    fun parse(text: String): List<DeviceUser>? {
        val users = LinkedHashMap<Int, DeviceUser>()
        for (line in text.lineSequence()) {
            val match = USER.find(line) ?: continue
            val (id, name, flags) = match.destructured
            val userId = id.toIntOrNull() ?: continue
            // Past Int.MAX_VALUE with OEM flags in the top bit: only the low bits are read.
            val bits = flags.toLongOrNull(16)?.toInt() ?: continue
            users.putIfAbsent(userId, DeviceUser(userId, name.takeUnless { it.isEmpty() || it == "null" }, bits))
        }
        return users.values.toList().takeIf { it.isNotEmpty() }
    }
}
