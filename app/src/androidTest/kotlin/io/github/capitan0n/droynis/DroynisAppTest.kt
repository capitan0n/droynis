package io.github.capitan0n.droynis

import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.capitan0n.droynis.checks.adb.adbChecks
import io.github.capitan0n.droynis.checks.base.SecurityPatchAgeCheck
import io.github.capitan0n.droynis.checks.base.SmsAccessCheck
import io.github.capitan0n.droynis.checks.base.UsbDebuggingCheck
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.checks.root.rootChecks
import io.github.capitan0n.droynis.checks.shizuku.shizukuChecks
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.ui.CHECKS_LIST_TAG
import io.github.capitan0n.droynis.ui.CHECKS_SEARCH_TAG
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Launches the real app: probes, scanner, scoring and UI together. */
@RunWith(AndroidJUnit4::class)
class DroynisAppTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private fun text(id: Int) = compose.activity.getString(id)

    private fun waitForScan() {
        // The gauge reads "/ 100" once the first scan has finished; before, it shows the logo.
        compose.waitUntil(SCAN_TIMEOUT_MS) {
            compose.onAllNodesWithText(text(R.string.score_out_of)).fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test
    fun checksTabListsEveryCheckAndOpensItsDetails() {
        waitForScan()
        compose.onNodeWithText(text(R.string.tab_checks)).performClick()

        val list = compose.onNodeWithTag(CHECKS_LIST_TAG)
        val checks = AndroidPlatform(compose.activity).use { baseChecks(it) + adbChecks(it) + shizukuChecks(it) + rootChecks(it) }
        for (title in checks.map { it.spec.title }) {
            list.performScrollToNode(hasText(title))
        }

        val usb = checks.single { it is UsbDebuggingCheck }.spec.title
        list.performScrollToNode(hasText(usb))
        compose.onNodeWithText(usb).performClick()
        compose.onNodeWithText(text(R.string.detail_why)).assertExists()
        assertTrue(
            "the evidence should name the setting it read",
            compose.onAllNodesWithText(UsbDebuggingCheck.ADB_ENABLED).fetchSemanticsNodes().isNotEmpty(),
        )

        compose.onNodeWithContentDescription(text(R.string.navigate_back)).performClick()
        compose.onNodeWithTag(CHECKS_LIST_TAG).assertExists()
    }

    @Test
    fun toolsAndHelpTabsShowTheirSections() {
        waitForScan()

        compose.onNodeWithText(text(R.string.tab_tools)).performClick()
        compose.onNodeWithText(text(R.string.tools_network)).assertExists()
        // IP addresses start hidden; the eye shows them and hides them again.
        compose.onNodeWithContentDescription(text(R.string.net_show_addresses)).performClick()
        compose.onNodeWithContentDescription(text(R.string.net_hide_addresses)).performClick()
        compose.onNodeWithContentDescription(text(R.string.net_show_addresses)).assertExists()

        compose.onNodeWithText(text(R.string.tab_help)).performClick()
        compose.onNodeWithText(text(R.string.help_legend)).assertExists()
    }

    @Test
    fun aboutScreenShowsTheAuthorAndFeedbackAddress() {
        waitForScan()

        compose.onNodeWithContentDescription(text(R.string.more_options)).performClick()
        compose.onNodeWithText(text(R.string.menu_about)).performClick()
        compose.onNodeWithText(AppInfo.HANDLE, substring = true).assertExists()
        compose.onNodeWithText(AppInfo.FEEDBACK_EMAIL).assertExists()
        compose.onNodeWithText("not affiliated", substring = true).assertExists()

        // The Help tab links to the same page.
        compose.onNodeWithContentDescription(text(R.string.navigate_back)).performClick()
        compose.onNodeWithText(text(R.string.tab_help)).performClick()
        compose.onNodeWithText(text(R.string.about_title)).performClick()
        compose.onNodeWithText(AppInfo.FEEDBACK_EMAIL).assertExists()
    }

    @Test
    fun checksCanBeFilteredByTier() {
        waitForScan()
        compose.onNodeWithText(text(R.string.tab_checks)).performClick()

        compose.onNodeWithText(text(R.string.tier_adb)).performClick()
        val (adb, patch) = AndroidPlatform(compose.activity).use { platform ->
            adbChecks(platform).first().spec.title to
                baseChecks(platform).single { it is SecurityPatchAgeCheck }.spec.title
        }
        compose.onNodeWithText(adb).assertExists()
        compose.onNodeWithText(patch).assertDoesNotExist()
    }

    @Test
    fun searchFindsTheChecksAboutATopic() {
        waitForScan()
        compose.onNodeWithText(text(R.string.tab_checks)).performClick()

        compose.onNodeWithTag(CHECKS_SEARCH_TAG).performTextInput("sms")
        val (sms, patch) = AndroidPlatform(compose.activity).use { platform ->
            val checks = baseChecks(platform)
            checks.single { it is SmsAccessCheck }.spec.title to checks.single { it is SecurityPatchAgeCheck }.spec.title
        }
        compose.onNodeWithText(sms).assertExists()
        compose.onNodeWithText(patch).assertDoesNotExist()

        compose.onNodeWithContentDescription(text(R.string.clear_search)).performClick()
        compose.onNodeWithTag(CHECKS_LIST_TAG).performScrollToNode(hasText(patch))
    }

    @Test
    fun catalogListsTheTiersAndHowToSetThemUp() {
        waitForScan()

        compose.onNodeWithContentDescription(text(R.string.more_options)).performClick()
        compose.onNodeWithText(text(R.string.catalog_title)).performClick()
        compose.onNodeWithText(text(R.string.tier_base_body)).assertExists()

        compose.onNodeWithText(text(R.string.tier_adb)).performClick()
        // Without adb grants the ADB tab offers the setup commands.
        compose.onNodeWithText("pm grant", substring = true).assertExists()

        // The Shizuku tab always explains how to set Shizuku up, whatever its state on this phone.
        compose.onNodeWithText(text(R.string.tier_shizuku)).performClick()
        compose.onNodeWithText(text(R.string.tier_shizuku_body)).assertExists()

        compose.onNodeWithText(text(R.string.tier_root)).performClick()
        compose.onNodeWithText(text(R.string.tier_root_note)).assertExists()
        // Root stays off until the user turns it on, so no root manager prompt appears in tests.
        compose.onNodeWithText(text(R.string.root_allow)).assertExists()
    }

    @Test
    fun mutingACheckTakesItOutOfTheScoreAndBackIn() {
        waitForScan()
        compose.onNodeWithText(text(R.string.tab_checks)).performClick()
        val patch = AndroidPlatform(compose.activity).use { platform ->
            baseChecks(platform).single { it is SecurityPatchAgeCheck }.spec.title
        }
        compose.onNodeWithTag(CHECKS_LIST_TAG).performScrollToNode(hasText(patch))
        compose.onNodeWithText(patch).performClick()

        val mute = compose.onNodeWithText(text(R.string.detail_mute_body))
        mute.performScrollTo().performClick()
        mute.assertIsOn()
        compose.onNodeWithContentDescription(text(R.string.navigate_back)).performClick()
        compose.onNodeWithText("${text(R.string.muted)} 1").assertExists() // the Muted filter chip

        compose.onNodeWithTag(CHECKS_LIST_TAG).performScrollToNode(hasText(patch))
        compose.onNodeWithText(patch).performClick()
        mute.performScrollTo().performClick() // unmute, so other tests start clean
        mute.assertIsOff()
    }

    private companion object {
        const val SCAN_TIMEOUT_MS = 20_000L
    }
}
