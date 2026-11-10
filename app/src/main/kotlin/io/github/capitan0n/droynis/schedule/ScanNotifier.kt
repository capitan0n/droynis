package io.github.capitan0n.droynis.schedule

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import io.github.capitan0n.droynis.DroynisActivity
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.report.HardeningIndex

/**
 * The notification a scheduled scan ends with. On the lock screen it only says that a scan
 * finished: which checks fail is a map of the phone's weak spots.
 */
object ScanNotifier {
    /** Set on the notification's intent: the app scans again, so it shows what the notification says. */
    const val EXTRA_RESCAN = "io.github.capitan0n.droynis.RESCAN"

    private const val CHANNEL_WORSE = "scan_worse"
    private const val CHANNEL_RESULTS = "scan_results"
    private const val NOTIFICATION_ID = 1
    private const val MAX_NAMED = 4

    /** Whether Droynis may post notifications at all. */
    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        return context.getSystemService(NotificationManager::class.java)?.areNotificationsEnabled() == true
    }

    fun show(
        context: Context,
        findings: List<Finding>,
        index: HardeningIndex,
        changes: ScanChanges,
        previousScore: Int?,
        verbose: Boolean,
    ) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        createChannels(context, manager)
        val channel = if (changes.worse) CHANNEL_WORSE else CHANNEL_RESULTS

        val score = index.score
        val lines = if (verbose) detailedLines(context, findings, changes) else listOf(previousLine(context, previousScore))
        val title = when {
            score == null -> context.getString(R.string.notify_title_no_score)
            // The short text already names the previous score.
            verbose && previousScore != null && previousScore != score ->
                context.getString(R.string.notify_title_changed, score, previousScore)
            else -> context.getString(R.string.notify_title, score)
        }
        post(context, manager, channel, title, lines)
    }

    /** The short notification's only line: the score of the scan before. */
    private fun previousLine(context: Context, previousScore: Int?): String =
        if (previousScore == null) {
            context.getString(R.string.notify_short_no_previous)
        } else {
            context.getString(R.string.notify_short_previous, previousScore)
        }

    /** What got worse, got fixed or could not run, or that nothing changed. */
    private fun detailedLines(context: Context, findings: List<Finding>, changes: ScanChanges): List<String> {
        val titles = findings.associate { it.spec.id to it.spec.title }
        val res = context.resources
        return buildList {
            if (changes.newIssues.isNotEmpty()) {
                val n = changes.newIssues.size
                add(res.getQuantityString(R.plurals.notify_new_issues, n, n, names(context, changes.newIssues, titles)))
            }
            if (changes.fixed.isNotEmpty()) {
                val n = changes.fixed.size
                add(res.getQuantityString(R.plurals.notify_fixed, n, n, names(context, changes.fixed, titles)))
            }
            if (changes.notRun.isNotEmpty()) {
                val n = changes.notRun.size
                add(res.getQuantityString(R.plurals.notify_not_run, n, n))
            }
            if (isEmpty()) add(context.getString(R.string.notify_no_changes))
        }
    }

    private fun post(context: Context, manager: NotificationManager, channel: String, title: String, lines: List<String>) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val open = Intent(context, DroynisActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(EXTRA_RESCAN, true)
        val contentIntent = PendingIntent.getActivity(
            context,
            0,
            open,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val lockScreen = Notification.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notify_public))
            .build()
        val notification = Notification.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(lines.first())
            .setStyle(Notification.BigTextStyle().bigText(lines.joinToString("\n")))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_STATUS)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }

    /** "USB debugging, Developer options and 2 more". */
    private fun names(context: Context, ids: List<String>, titles: Map<String, String>): String {
        val named = ids.take(MAX_NAMED).joinToString(", ") { titles[it] ?: it }
        val rest = ids.size - MAX_NAMED
        return if (rest > 0) context.getString(R.string.notify_and_more, named, rest) else named
    }

    /** Two channels, so the user can silence the routine score and keep the warnings. */
    private fun createChannels(context: Context, manager: NotificationManager) {
        val worse = NotificationChannel(
            CHANNEL_WORSE,
            context.getString(R.string.channel_worse),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = context.getString(R.string.channel_worse_desc)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        val results = NotificationChannel(
            CHANNEL_RESULTS,
            context.getString(R.string.channel_results),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.channel_results_desc)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        manager.createNotificationChannels(listOf(worse, results))
    }
}
