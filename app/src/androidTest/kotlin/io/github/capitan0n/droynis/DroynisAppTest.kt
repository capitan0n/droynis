package io.github.capitan0n.droynis

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.capitan0n.droynis.checks.base.UsbDebuggingCheck
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.ui.CHECKS_LIST_TAG
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
        // The gauge reads "/ 100" once the first scan has finished, "/ <checks>" before.
        compose.waitUntil(SCAN_TIMEOUT_MS) {
            compose.onAllNodesWithText(text(R.string.score_out_of)).fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test
    fun checksTabListsEveryCheckAndOpensItsDetails() {
        waitForScan()
        compose.onNodeWithText(text(R.string.tab_checks)).performClick()

        val list = compose.onNodeWithTag(CHECKS_LIST_TAG)
        val checks = baseChecks(AndroidPlatform(compose.activity))
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

        // The Help tab links to the same page.
        compose.onNodeWithContentDescription(text(R.string.navigate_back)).performClick()
        compose.onNodeWithText(text(R.string.tab_help)).performClick()
        compose.onNodeWithText(text(R.string.about_title)).performClick()
        compose.onNodeWithText(AppInfo.FEEDBACK_EMAIL).assertExists()
    }

    private companion object {
        const val SCAN_TIMEOUT_MS = 20_000L
    }
}
