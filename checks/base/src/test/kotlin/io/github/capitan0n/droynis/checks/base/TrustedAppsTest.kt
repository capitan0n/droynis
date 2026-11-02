package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class TrustedAppsTest {

    private val watch = "nodomain.freeyourgadget.gadgetbridge"
    private val tasker = "net.dinglisch.android.taskerm"
    private val launcher = "com.sec.android.app.launcher"
    private val labels = mapOf(watch to "Gadgetbridge", tasker to "Tasker")

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private suspend fun Check.outcomeTrusting(vararg trusted: String): Outcome =
        run(scanContext().copy(trustedApps = trusted.toSet()))

    private fun notificationAccess(listeners: String, apps: List<InstalledApp>) = NotificationAccessCheck(
        FakeSettings(secure = mapOf("enabled_notification_listeners" to value(listeners))),
        FakePackages(value(apps), labels),
    )

    @Test
    fun `a trusted app is listed but not counted`() = runTest {
        val check = notificationAccess("$watch/.L", listOf(app(watch)))

        val untrusted = check.outcomeTrusting()
        assertEquals(Status.FAIL, untrusted.status)
        assertEquals(Trust.COUNTED, untrusted.evidence.single().trust)

        val trusted = check.outcomeTrusting(watch)
        assertEquals(Status.PASS, trusted.status)
        assertEquals("Only apps you trust can read your notifications: Gadgetbridge", trusted.summary)
        val evidence = trusted.evidence.single()
        assertEquals("Gadgetbridge ($watch)", evidence.value)
        assertEquals("from an app store; $TRUSTED_NOTE", evidence.note)
        assertEquals(Trust.TRUSTED, evidence.trust)
    }

    @Test
    fun `other apps still count`() = runTest {
        val outcome = notificationAccess("$watch/.L:$tasker/.L", listOf(app(watch), app(tasker)))
            .outcomeTrusting(watch)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app can read your notifications: Tasker", outcome.summary)
        assertEquals(listOf(Trust.TRUSTED, Trust.COUNTED), outcome.evidence.map { it.trust })
    }

    @Test
    fun `one trust covers every check`() = runTest {
        val battery = BatteryOptimizationCheck(FakeBattery(value(setOf(watch))), FakePackages(value(listOf(app(watch))), labels))
        val notifications = notificationAccess("$watch/.L", listOf(app(watch)))

        assertEquals(Status.FAIL, battery.outcomeTrusting(tasker).status)
        val trustedBattery = battery.outcomeTrusting(watch)
        assertEquals(Status.PASS, trustedBattery.status)
        assertEquals("Only apps you trust skip battery optimization: Gadgetbridge", trustedBattery.summary)
        assertEquals(Status.PASS, notifications.outcomeTrusting(watch).status)
    }

    @Test
    fun `a trusted app from outside an app store raises nothing`() = runTest {
        val sideloaded = listOf(app(watch, installer = null), app(tasker, installer = null))
        val check = notificationAccess("$watch/.L:$tasker/.L", sideloaded)

        assertEquals(Severity.WARNING, check.outcomeTrusting().escalation)
        assertEquals(Severity.WARNING, check.outcomeTrusting(watch).escalation)
        val both = check.outcomeTrusting(watch, tasker)
        assertEquals(Status.PASS, both.status)
        assertNull(both.escalation)
    }

    @Test
    fun `apps that never count can't be trusted`() = runTest {
        val outcome = notificationAccess("$launcher/.Badges:$watch/.L", listOf(app(launcher, system = true), app(watch)))
            .outcomeTrusting(watch, launcher)

        assertEquals(Status.PASS, outcome.status)
        assertEquals(
            "Only apps that came with the phone and apps you trust can read your notifications: Gadgetbridge",
            outcome.summary,
        )
        assertEquals(listOf(Trust.NOT_COUNTED, Trust.TRUSTED), outcome.evidence.map { it.trust })
        assertEquals("came with the phone; not counted", outcome.evidence.first().note)
    }

    @Test
    fun `apps you install and apps you trust`() = runTest {
        val sideloaded = UnknownSourceAppsCheck(FakePackages(value(listOf(app(watch, installer = null))), labels))
        assertEquals(Status.FAIL, sideloaded.outcomeTrusting().status)
        assertEquals(
            "Only apps you trust come from outside an app store: Gadgetbridge",
            sideloaded.outcomeTrusting(watch).summary,
        )

        val sms = SmsSendingCheck(
            FakePermissions(value(mapOf(watch to SmsSendingCheck.SEND))),
            FakeDefaultApps(),
            FakePackages(value(listOf(app(watch))), labels),
        )
        assertEquals(Status.FAIL, sms.outcomeTrusting().status)
        val trustedSms = sms.outcomeTrusting(watch)
        assertEquals(Status.PASS, trustedSms.status)
        assertEquals(Trust.TRUSTED, trustedSms.evidence.single { it.packageName == watch }.trust)
    }

    @Test
    fun `default SMS and phone apps say why they have no trust button, or get one where they count`() = runTest {
        val messages = "com.google.android.apps.messaging"
        val dialer = "com.samsung.android.dialer"
        fun check(messagesHolds: Set<String>) = SmsAccessCheck(
            FakePermissions(value(mapOf(messages to messagesHolds, dialer to SmsAccessCheck.CALL_LOG))),
            FakeDefaultApps(sms = value(messages), phone = value(dialer)),
            FakePackages(value(listOf(app(messages, installer = "com.android.vending"), app(dialer, system = true))), labels),
        )

        // Each holds only what its role needs: nothing counts, nothing to trust.
        val roles = check(SmsAccessCheck.SMS).outcomeTrusting()
        assertEquals(Status.PASS, roles.status)
        assertEquals(listOf("allowed for your SMS app; not counted", "allowed for your phone app; not counted"), roles.evidence.take(2).map { it.note })
        assertEquals(listOf(Trust.NOT_COUNTED, Trust.NOT_COUNTED), roles.evidence.take(2).map { it.trust })

        // Messages also reads the call log: it counts, and its role row offers Trust too.
        val more = check(SmsAccessCheck.SMS + SmsAccessCheck.CALL_LOG)
        val counted = more.outcomeTrusting()
        assertEquals(Status.FAIL, counted.status)
        assertEquals(Trust.COUNTED, counted.evidence.first().trust)
        assertEquals(Trust.COUNTED, counted.evidence.single { it.label.startsWith("Can read") }.trust)

        val trusted = more.outcomeTrusting(messages)
        assertEquals(Status.PASS, trusted.status)
        assertEquals(Trust.TRUSTED, trusted.evidence.first().trust)
    }

    @Test
    fun `apps that came with a Samsung phone are marked not counted, apps you installed can be trusted`() = runTest {
        val oneUiHome = "com.sec.android.app.launcher"
        val androidAuto = "com.google.android.projection.gearhead"
        val listeners = "$oneUiHome/.Badges:$androidAuto/.Notifications:$watch/.L"
        val phone = listOf(app(oneUiHome, system = true), app(androidAuto, system = true), app(watch))
        val check = notificationAccess(listeners, phone)

        val before = check.outcomeTrusting()
        assertEquals(Status.FAIL, before.status)
        assertEquals("1 app can read your notifications: Gadgetbridge", before.summary)
        assertEquals(
            listOf(Trust.NOT_COUNTED, Trust.NOT_COUNTED, Trust.COUNTED),
            before.evidence.map { it.trust },
        )
        assertEquals(listOf("came with the phone; not counted", "came with the phone; not counted"), before.evidence.take(2).map { it.note })

        val after = check.outcomeTrusting(watch)
        assertEquals(Status.PASS, after.status)
        assertEquals(
            "Only apps that came with the phone and apps you trust can read your notifications: Gadgetbridge",
            after.summary,
        )
        assertEquals(listOf(Trust.NOT_COUNTED, Trust.NOT_COUNTED, Trust.TRUSTED), after.evidence.map { it.trust })

        // Android Auto installed from Google Play instead counts, and so can be trusted.
        val fromPlay = notificationAccess(listeners, listOf(app(oneUiHome, system = true), app(androidAuto, installer = "com.android.vending")))
        assertEquals(Trust.COUNTED, fromPlay.outcomeTrusting().evidence.single { it.packageName == androidAuto }.trust)
    }

    @Test
    fun `a trusted service or assistant passes by name`() = runTest {
        val accessibility = AccessibilityServicesCheck(FakeAccessibility(value(listOf(AppRef(watch, "Gadgetbridge")))), FakePackages())
        val trusted = accessibility.outcomeTrusting(watch)
        assertEquals(Status.PASS, trusted.status)
        assertEquals("Only accessibility services you trust are enabled: Gadgetbridge", trusted.summary)

        val autofill = AutofillServiceCheck(
            FakeAutofill(value(AutofillState("com.x8bit.bitwarden/.Autofill"))),
            FakePackages(value(listOf(app("com.x8bit.bitwarden"))), mapOf("com.x8bit.bitwarden" to "Bitwarden")),
        )
        assertEquals(Status.FAIL, autofill.outcomeTrusting().status)
        val trustedAutofill = autofill.outcomeTrusting("com.x8bit.bitwarden")
        assertEquals(Status.PASS, trustedAutofill.status)
        assertEquals("Bitwarden, which you trust, fills in forms", trustedAutofill.summary)
    }

    @Test
    fun `trust helpers`() {
        assertEquals("Only apps you trust can send SMS: A and B", onlyTrusted("can send SMS", listOf("A", "B", "A")))
        assertEquals(
            "Only apps that came with the phone and apps you trust can send SMS: A",
            onlyTrusted("can send SMS", listOf("A"), others = "apps that came with the phone"),
        )
        assertEquals(TRUSTED_NOTE, withTrustNote(null, trusted = true))
        assertEquals("only while in use; $TRUSTED_NOTE", withTrustNote("only while in use", trusted = true))
        assertEquals("only while in use", withTrustNote("only while in use", trusted = false))
        assertEquals(Trust.TRUSTED, trustOf(counted = false, trusted = true))
        assertEquals(Trust.COUNTED, trustOf(counted = true, trusted = false))
        assertEquals(Trust.NOT_COUNTED, trustOf(counted = false, trusted = false))
    }
}
