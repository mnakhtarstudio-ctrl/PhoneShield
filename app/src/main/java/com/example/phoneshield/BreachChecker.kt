package com.example.phoneshield

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Pwned Passwords with k-anonymity: only the first 5 hex chars of the SHA-1
 * leave the phone. The server can't tell which password you checked.
 * Returns the breach count, or null if the lookup failed.
 */
object BreachChecker {
    suspend fun timesPwned(password: String): Int? = withContext(Dispatchers.IO) {
        try {
            val sha = MessageDigest.getInstance("SHA-1").digest(password.toByteArray())
                .joinToString("") { "%02X".format(it) }
            val (prefix, suffix) = sha.take(5) to sha.drop(5)
            val c = URL("https://api.pwnedpasswords.com/range/$prefix").openConnection() as HttpURLConnection
            c.setRequestProperty("Add-Padding", "true")   // hides response size too
            c.connectTimeout = 5000; c.readTimeout = 5000
            c.inputStream.bufferedReader().useLines { lines ->
                lines.map { it.split(":") }
                    .firstOrNull { it[0] == suffix }?.get(1)?.trim()?.toInt() ?: 0
            }
        } catch (e: Exception) { null }
    }
}
