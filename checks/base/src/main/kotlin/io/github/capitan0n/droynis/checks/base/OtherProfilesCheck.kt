package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
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
            "and nothing about other users. This check is for your information and doesn't count in the " +
            "score.",
        remediation = Remediation(
            text = "To check another profile or user, install Droynis there too and scan from inside it: " +
                "each copy sees only its own side. Remove profiles and users you no longer need under " +
                "Settings › System › Users, Settings › Security & privacy › Private Space, or Settings › " +
                "Passwords & accounts › Work.",
        ),
        failsWhen = "another profile shares this user, or Droynis doesn't run in the phone's main user (information only)",
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
            when {
                others > 0 && !found.isSystemUser -> Outcome.fail(
                    "Droynis runs in a profile or secondary user that shares the phone with " +
                        "${count(others, "other profile")}: only this one was checked",
                    evidence,
                )
                others > 0 -> Outcome.fail(
                    "${count(others, "other profile shares", "other profiles share")} this user, such as a " +
                        "work profile or Private Space: its apps were not checked",
                    evidence,
                )
                !found.isSystemUser -> Outcome.fail(
                    "Droynis runs in a secondary user: the phone's other users were not checked",
                    evidence,
                )
                else -> Outcome.pass(
                    "Android lists no other profile for this user",
                    evidence + Evidence("Other users of the phone", null, state.source, note = "not visible to apps"),
                )
            }
        }
    }
}
