package com.example.phoneshield

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** Turns background scanning on/off. Everything stays on the device. */
object AutoManager {
    private const val WORK_NAME = "phoneshield_auto_scan"
    const val PREFS = "phoneshield"
    private const val KEY_ENABLED = "auto_enabled"
    const val KEY_LAST_SCAN = "last_scan"

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isEnabled(c: Context) = prefs(c).getBoolean(KEY_ENABLED, false)

    fun lastScan(c: Context) = prefs(c).getLong(KEY_LAST_SCAN, 0L)

    fun enable(c: Context) {
        prefs(c).edit().putBoolean(KEY_ENABLED, true).apply()
        val request = PeriodicWorkRequestBuilder<ScanWorker>(12, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .build()
        WorkManager.getInstance(c)
            .enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    fun disable(c: Context) {
        prefs(c).edit().putBoolean(KEY_ENABLED, false).apply()
        WorkManager.getInstance(c).cancelUniqueWork(WORK_NAME)
    }

    fun runNow(c: Context) {
        WorkManager.getInstance(c).enqueue(OneTimeWorkRequestBuilder<ScanWorker>().build())
    }
}

/** Rescans, compares with the previous scan, and alerts only about NEW problems. */
class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        return try {
            scanAndAlert()
            Result.success()
        } catch (e: Exception) {
            Result.success() // never crash-loop a background job
        }
    }

    private fun scanAndAlert() {
        val c = applicationContext
        val checker = SecurityChecker(c)
        val results = checker.runAll()
        val risky = PermissionAuditor(c).audit().filter { it.score >= 6 }
        val prefs = c.getSharedPreferences(AutoManager.PREFS, Context.MODE_PRIVATE)

        val firstRun = !prefs.contains("last_failing")
        val oldFailing: Set<String> = prefs.getStringSet("last_failing", emptySet()) ?: emptySet()
        val oldRisky: Set<String> = prefs.getStringSet("last_risky", emptySet()) ?: emptySet()

        val failingNow = results.filter { !it.passed }
        val newFailing = failingNow.filter { it.id !in oldFailing }
        val newRisky = risky.filter { it.pkg !in oldRisky }

        if (!firstRun) {
            if (newFailing.isNotEmpty()) {
                Notifier.alert(
                    c, "PhoneShield: security setting changed",
                    "Now failing: " + newFailing.joinToString { it.title } + ". Score: ${checker.score(results)}/100.",
                    1001
                )
            }
            if (newRisky.isNotEmpty()) {
                Notifier.alert(
                    c, "PhoneShield: app worth reviewing",
                    "New app(s) with sensitive access: " + newRisky.take(3).joinToString { it.label } +
                        ". Check Settings > Apps > Permissions.",
                    1002
                )
            }
        }

        prefs.edit()
            .putStringSet("last_failing", failingNow.map { it.id }.toSet())
            .putStringSet("last_risky", risky.map { it.pkg }.toSet())
            .putLong(AutoManager.KEY_LAST_SCAN, System.currentTimeMillis())
            .apply()
    }
}

object Notifier {
    private const val CHANNEL = "phoneshield_alerts"

    fun alert(c: Context, title: String, text: String, id: Int) {
        val nm = NotificationManagerCompat.from(c)
        if (!nm.areNotificationsEnabled()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val m = c.getSystemService(NotificationManager::class.java)
            m.createNotificationChannel(
                NotificationChannel(CHANNEL, "PhoneShield alerts", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val open = PendingIntent.getActivity(
            c, 0, Intent(c, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try { nm.notify(id, n) } catch (e: SecurityException) { /* notifications blocked */ }
    }
}
