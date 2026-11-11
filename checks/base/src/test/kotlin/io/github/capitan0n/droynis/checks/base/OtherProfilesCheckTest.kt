package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Profiles this scan doesn't cover (APPS-4017). */
class OtherProfilesCheckTest {

    private suspend fun outcome(state: Reading<ProfileState>) = OtherProfilesCheck(FakeProfiles(state)).outcome()

    @Test
    fun `it is information only`() {
        assertEquals(Severity.INFO, OtherProfilesCheck(FakeProfiles()).spec.severity)
    }

    @Test
    fun `the main user alone passes, and says other users can't be seen`() = runTest {
        val outcome = outcome(value(ProfileState(profiles = 1, isSystemUser = true)))

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Android lists no other profile for this user", outcome.summary)
        val users = outcome.evidence.single { it.label == "Other users of the phone" }
        assertNull(users.value)
        assertEquals("not visible to apps", users.note)
    }

    @Test
    fun `another profile fails, with the count`() = runTest {
        val one = outcome(value(ProfileState(profiles = 2, isSystemUser = true)))
        assertEquals(Status.FAIL, one.status)
        assertNull(one.escalation)
        assertTrue(one.summary.startsWith("1 other profile shares this user"), one.summary)
        assertEquals("2", one.evidence.single { it.label == "Profiles of this user" }.value)

        val two = outcome(value(ProfileState(profiles = 3, isSystemUser = true)))
        assertTrue(two.summary.startsWith("2 other profiles share this user"), two.summary)
    }

    @Test
    fun `running outside the main user fails, alone or inside a profile`() = runTest {
        val secondary = outcome(value(ProfileState(profiles = 1, isSystemUser = false)))
        assertEquals(Status.FAIL, secondary.status)
        assertEquals("Droynis runs in a secondary user: the phone's other users were not checked", secondary.summary)

        val profile = outcome(value(ProfileState(profiles = 2, isSystemUser = false)))
        assertEquals(Status.FAIL, profile.status)
        assertTrue(profile.summary.startsWith("Droynis runs in a profile or secondary user"), profile.summary)
    }

    @Test
    fun `an unreadable or empty list is unknown, never passed`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(unavailable("no user service")).status)
        assertEquals(Status.UNKNOWN, outcome(value(ProfileState(profiles = 0, isSystemUser = true))).status)
    }
}
