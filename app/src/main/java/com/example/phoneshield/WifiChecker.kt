package com.example.phoneshield

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

/** A cautious Wi-Fi snapshot. Android does not expose the current AP's cipher reliably on all versions. */
data class WifiVerdict(val ssid: String, val safe: Boolean, val findings: List<String>)

class WifiChecker(private val context: Context) {
    @Suppress("DEPRECATION")
    fun check(): WifiVerdict {
        val findings = mutableListOf<String>()
        val permission = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        if (permission != PackageManager.PERMISSION_GRANTED) {
            return WifiVerdict("Unknown network", false, listOf("Location permission is needed by Android to read the Wi-Fi name."))
        }

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = network?.let { cm.getNetworkCapabilities(it) }
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return WifiVerdict("Not connected to Wi-Fi", false, listOf("Connect to a Wi-Fi network and scan again."))
        }

        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val rawSsid = runCatching { wm.connectionInfo?.ssid }.getOrNull()
        val ssid = rawSsid?.takeIf { it.isNotBlank() && it != "<unknown ssid>" }
            ?.removeSurrounding("\"") ?: "Current Wi-Fi network"
        if (Build.VERSION.SDK_INT >= 29 && !(context.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager).isLocationEnabled) {
            findings += "Android location services are off; Wi-Fi details may be hidden."
        }
        findings += "PhoneShield cannot reliably verify this access point's encryption on every Android version. Check the router or network details for WPA2-AES or WPA3."
        findings += "Avoid banking or sensitive activity on unfamiliar public Wi-Fi; HTTPS helps but does not prove the hotspot is genuine."
        return WifiVerdict(ssid, false, findings)
    }
}
