package io.github.capitan0n.droynis.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SettingsActionsTest {

    private fun targets(route: SettingsRoute) = route.targets.map { it.target }

    @Test
    fun `every route ends with the main Settings screen, once`() {
        assertEquals(listOf(SettingsActions.WIFI, SettingsActions.SETTINGS), targets(SettingsActions.route(listOf(SettingsActions.WIFI), 35)))
        assertEquals(listOf(SettingsActions.SETTINGS), targets(SettingsActions.route(listOf(SettingsActions.SETTINGS), 35)))
        assertEquals(listOf(SettingsActions.SETTINGS), targets(SettingsActions.route(emptyList(), 35)))
    }

    @Test
    fun `the highlight key goes to the listed screens, not to the fallback`() {
        val route = SettingsActions.route(listOf(SettingsActions.SCREEN_TIMEOUT, SettingsActions.DISPLAY), 35, highlightKey = "screen_timeout")
        assertEquals(
            listOf(
                SettingsTarget(SettingsActions.SCREEN_TIMEOUT, "screen_timeout"),
                SettingsTarget(SettingsActions.DISPLAY, "screen_timeout"),
                SettingsTarget(SettingsActions.SETTINGS),
            ),
            route.targets,
        )
    }

    @Test
    fun `developer options that are off open About phone at Build number instead`() {
        val actions = listOf(SettingsActions.DEVELOPER_OPTIONS)
        val off = SettingsActions.route(actions, 35, highlightKey = "oem_unlock_enable", developerOptionsOn = false)
        assertTrue(off.developerOptionsOff)
        assertEquals(
            listOf(SettingsTarget(SettingsActions.DEVICE_INFO, SettingsActions.BUILD_NUMBER_KEY), SettingsTarget(SettingsActions.SETTINGS)),
            off.targets,
        )

        for (state in listOf(true, null)) {
            val route = SettingsActions.route(actions, 35, highlightKey = "oem_unlock_enable", developerOptionsOn = state)
            assertFalse(route.developerOptionsOff)
            assertEquals(SettingsTarget(SettingsActions.DEVELOPER_OPTIONS, "oem_unlock_enable"), route.targets.first())
        }

        // Other screens don't care whether developer options are on.
        assertFalse(SettingsActions.route(listOf(SettingsActions.WIFI), 35, developerOptionsOn = false).developerOptionsOff)
    }

    @Test
    fun `screens are skipped on releases where they show something else`() {
        val privacy = listOf(SettingsActions.PRIVACY, SettingsActions.APPS)
        assertEquals(listOf(SettingsActions.APPS, SettingsActions.SETTINGS), targets(SettingsActions.route(privacy, 28)))
        assertEquals(SettingsActions.PRIVACY, targets(SettingsActions.route(privacy, 29)).first())

        // The autofill picker: Languages & input up to Android 11, Passwords & accounts from Android 12.
        val autofill = listOf(SettingsActions.LANGUAGE_AND_INPUT, SettingsActions.ACCOUNTS)
        assertEquals(listOf(SettingsActions.LANGUAGE_AND_INPUT, SettingsActions.SETTINGS), targets(SettingsActions.route(autofill, 30)))
        assertEquals(listOf(SettingsActions.ACCOUNTS, SettingsActions.SETTINGS), targets(SettingsActions.route(autofill, 31)))
    }

    @Test
    fun `face unlock settings need face hardware`() {
        val actions = listOf(SettingsActions.FACE, SettingsActions.SECURITY)
        assertEquals(SettingsActions.FACE, targets(SettingsActions.route(actions, 35)).first())
        val noFace = SettingsActions.route(actions, 35, hasFeature = { it != "android.hardware.biometrics.face" })
        assertEquals(listOf(SettingsActions.SECURITY, SettingsActions.SETTINGS), targets(noFace))
    }

    @Test
    fun `explicit activities are told apart from actions`() {
        assertTrue(SettingsActions.isComponent(SettingsActions.DEVICE_ADMINS))
        assertTrue(SettingsActions.isComponent(SettingsActions.LANGUAGE_AND_INPUT))
        assertTrue(SettingsTarget(SettingsActions.DEVICE_ADMINS).isComponent)
        assertFalse(SettingsActions.isComponent(SettingsActions.SECURITY))
        assertFalse(SettingsActions.isComponent(SettingsActions.WIFI_SAVED_NETWORKS))
    }

    @Test
    fun `a highlight key needs a screen`() {
        assertFailsWith<IllegalArgumentException> { Remediation("Do this.", highlightKey = "enable_adb") }
        Remediation("Do this.", listOf(SettingsActions.DEVELOPER_OPTIONS), highlightKey = "enable_adb")
    }
}
