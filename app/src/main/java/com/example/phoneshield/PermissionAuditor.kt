package com.example.phoneshield

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

data class AppRisk(val label: String, val pkg: String, val granted: List<String>, val score: Int)

/**
 * Attacker view: spyware needs mic, camera, location, SMS or contacts.
 * Find user-installed apps holding the riskiest GRANTED permissions.
 * Needs QUERY_ALL_PACKAGES (declare it for a security app).
 */
class PermissionAuditor(private val context: Context) {

    private val weights = mapOf(
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 4,
        "android.permission.READ_SMS" to 4,
        "android.permission.RECEIVE_SMS" to 3,
        "android.permission.RECORD_AUDIO" to 3,
        "android.permission.CAMERA" to 3,
        "android.permission.READ_CALL_LOG" to 3,
        "android.permission.ACCESS_FINE_LOCATION" to 2,
        "android.permission.READ_CONTACTS" to 2
    )

    fun audit(): List<AppRisk> {
        val pm = context.packageManager
        val pkgs = if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        return pkgs.mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 &&
                    ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
            if (isSystem || p.packageName == context.packageName) return@mapNotNull null

            val perms = p.requestedPermissions ?: return@mapNotNull null
            val flags = p.requestedPermissionsFlags ?: return@mapNotNull null
            val granted = perms.indices
                .filter { flags[it] and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
                .map { perms[it] }
                .filter { it in weights }
            if (granted.isEmpty()) null
            else AppRisk(
                pm.getApplicationLabel(ai).toString(), p.packageName,
                granted.map { it.substringAfterLast('.') },
                granted.sumOf { weights[it] ?: 0 }
            )
        }.sortedByDescending { it.score }
    }
}
