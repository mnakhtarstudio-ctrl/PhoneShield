package com.example.phoneshield

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit

// minSdk 26 (needed for java.time). No special permissions required.

enum class Severity(val penalty: Int) { OK(0), LOW(5), MEDIUM(15), HIGH(30) }

data class CheckResult(
    val id: String,
    val title: String,
    val passed: Boolean,
    val severity: Severity,   // severity if the check FAILS
    val advice: String
)

class SecurityChecker(private val context: Context) {

    fun runAll(): List<CheckResult> = listOf(
        checkScreenLock(),
        checkEncryption(),
        checkSecurityPatch(),
        checkDeveloperOptions(),
        checkUsbDebugging(),
        checkAccessibilityServices(),
        checkRootIndicators()
    )

    /** 100 = perfect. Each failed check subtracts its severity penalty. */
    fun score(results: List<CheckResult>): Int =
        (100 - results.filter { !it.passed }.sumOf { it.severity.penalty }).coerceIn(0, 100)

    private fun checkScreenLock(): CheckResult {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return CheckResult(
            "screen_lock", "Screen lock enabled",
            km.isDeviceSecure, Severity.HIGH,
            "Set a PIN (6+ digits) or an alphanumeric password in Settings > Security."
        )
    }

    private fun checkEncryption(): CheckResult {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val status = dpm.storageEncryptionStatus
        val ok = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
        return CheckResult(
            "encryption", "Storage encrypted",
            ok, Severity.HIGH,
            "Storage should be encrypted by default on modern Android. If not, your device may be unsupported."
        )
    }

    private fun checkSecurityPatch(): CheckResult {
        val patch = Build.VERSION.SECURITY_PATCH // e.g. "2025-06-05"
        val ageDays = runCatching {
            ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now())
        }.getOrDefault(Long.MAX_VALUE)
        return CheckResult(
            "patch", "Security patch is recent (under 90 days)",
            ageDays <= 90, Severity.HIGH,
            "Your patch level is $patch. Install system updates, or consider a newer device if updates ended."
        )
    }

    private fun checkDeveloperOptions(): CheckResult {
        val on = Settings.Global.getInt(
            context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 1
        return CheckResult(
            "dev_options", "Developer options off",
            !on, Severity.LOW,
            "Turn off Developer options unless you actively need them."
        )
    }

    private fun checkUsbDebugging(): CheckResult {
        val on = Settings.Global.getInt(
            context.contentResolver, Settings.Global.ADB_ENABLED, 0
        ) == 1
        return CheckResult(
            "adb", "USB debugging off",
            !on, Severity.MEDIUM,
            "USB debugging lets a connected computer control your phone. Disable it."
        )
    }

    /** Accessibility is the most common stalkerware/banking-trojan route. */
    private fun checkAccessibilityServices(): CheckResult {
        val enabled = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ).orEmpty()
        val services = enabled.split(":").filter { it.isNotBlank() }
        return CheckResult(
            "accessibility", "No unexpected accessibility services",
            services.isEmpty(), Severity.MEDIUM,
            if (services.isEmpty()) "None enabled."
            else "Enabled: ${services.joinToString { it.substringBefore('/') }}. " +
                 "Disable any you don't recognize."
        )
    }

    /** Heuristic only: root can be hidden, so a pass is NOT proof of safety. */
    private fun checkRootIndicators(): CheckResult {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/bin/su"
        )
        val rooted = Build.TAGS?.contains("test-keys") == true ||
                suPaths.any { File(it).exists() }
        return CheckResult(
            "root", "Device not rooted",
            !rooted, Severity.HIGH,
            "Rooting removes Android's core protections. Unroot unless you know exactly why it's needed."
        )
    }
}
