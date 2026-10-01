package io.github.capitan0n.droynis

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.capitan0n.droynis.checks.base.UsbDebuggingCheck
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.ui.FINDINGS_LIST_TAG
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Launches the real app: probes, scanner, scoring and UI together. */
@RunWith(AndroidJUnit4::class)
class HomeScreenTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun scanListsEveryBaseCheckAndShowsEvidence() {
        val activity = compose.activity
        val hardeningIndex = activity.getString(R.string.hardening_index)
        compose.waitUntil(SCAN_TIMEOUT_MS) {
            compose.onAllNodesWithText(hardeningIndex).fetchSemanticsNodes().isNotEmpty()
        }

        val list = compose.onNodeWithTag(FINDINGS_LIST_TAG)
        val checks = baseChecks(AndroidPlatform(activity))
        for (title in checks.map { it.spec.title }) {
            list.performScrollToNode(hasText(title))
        }

        val usb = checks.single { it is UsbDebuggingCheck }.spec.title
        list.performScrollToNode(hasText(usb))
        compose.onNodeWithText(usb).performClick()
        list.performScrollToNode(hasText("${UsbDebuggingCheck.ADB_ENABLED}:", substring = true))
        compose.onNodeWithText(activity.getString(R.string.why_it_matters)).assertExists()
    }

    private companion object {
        const val SCAN_TIMEOUT_MS = 20_000L
    }
}
