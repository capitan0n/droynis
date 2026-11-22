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
    fun `with a privileged read the phone's other users are found`() = runTest {
        // A Galaxy with a Secure Folder, which is a user of its own that getUserProfiles() doesn't list.
        val dump = """
            Users:
              UserInfo{0:Owner:c13} serialNo=0 isPrimary=true
                Type: android.os.usertype.full.SYSTEM
              UserInfo{150:Secure Folder:10061030} serialNo=150 isPrimary=false
            Owner name: Owner
              UserInfo{0:Owner:c13}
        """.trimIndent()
        val main = value(ProfileState(profiles = 1, isSystemUser = true))
        val outcome = OtherProfilesCheck(FakeProfiles(main, users = value(dump))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "1 other user or profile exists on this phone, such as a second user or a Secure Folder: its apps were not checked",
            outcome.summary,
        )
        assertEquals("2", outcome.evidence.single { it.label == "Users and profiles of the phone" }.value)
        // What kind of user it is stays readable when the name is hidden: it is in the label.
        val folder = outcome.evidence.single { it.label == "User 150 (work or managed profile)" }
        assertEquals("Secure Folder", folder.value)
        assertNull(folder.note)
        assertTrue(folder.personal) // a name its owner typed

        val alone = OtherProfilesCheck(FakeProfiles(main, users = value("  UserInfo{0:null:c13} serialNo=0"))).outcome()
        assertEquals(Status.PASS, alone.status)
        assertEquals("This user is the only user and profile on the phone", alone.summary)
        assertEquals("(no name)", alone.evidence.single { it.label == "User 0 (the phone's main user)" }.value)

        // A dump that names no user, or fewer than Android itself listed, proves nothing.
        for (odd in listOf("Permission Denial", "")) {
            val fallback = OtherProfilesCheck(FakeProfiles(main, users = value(odd))).outcome()
            assertEquals("Android lists no other profile for this user", fallback.summary)
        }
        val fewer = OtherProfilesCheck(FakeProfiles(value(ProfileState(2, true)), users = value("UserInfo{0:Owner:c13}"))).outcome()
        assertTrue(fewer.evidence.none { it.label == "Users and profiles of the phone" })
    }

    @Test
    fun `user lines are read whatever surrounds them`() {
        val users = UserDump.parse("x UserInfo{10:Work: A:B:1030} y\nUserInfo{11:Guest:414}\nUserInfo{10:again:0}")!!
        assertEquals(listOf(10, 11), users.map { it.id })
        assertEquals("Work: A:B", users[0].name)
        assertEquals("work or managed profile", users[0].kind)
        assertEquals("guest", users[1].kind)
        assertNull(UserDump.parse("no users here"))
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
