package com.example.phoneshield

import java.net.URI

data class LinkVerdict(val score: Int, val reasons: List<String>) {
    val level get() = when {
        score >= 60 -> "HIGH RISK"
        score >= 30 -> "SUSPICIOUS"
        else -> "No red flags (not a guarantee)"
    }
}

/** 100% offline: the URL never leaves the phone. */
object LinkChecker {
    private val shorteners = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy")
    private val riskyTlds = setOf("zip", "mov", "top", "xyz", "click", "country", "tk", "gq", "ml", "cf")
    private val brands = listOf("paypal", "apple", "google", "microsoft", "amazon", "netflix",
        "facebook", "instagram", "whatsapp", "binance", "coinbase", "bank")

    fun check(raw: String): LinkVerdict {
        val text = raw.trim()
        val uri = runCatching { URI(if ("://" in text) text else "http://$text") }.getOrNull()
        val host = uri?.host?.lowercase() ?: return LinkVerdict(70, listOf("Malformed or hidden host"))
        val why = mutableListOf<String>()
        var s = 0
        fun flag(pts: Int, msg: String) { s += pts; why += msg }

        if (uri.scheme == "http") flag(15, "Not encrypted (http)")
        if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) flag(40, "Raw IP address instead of a domain")
        if ("@" in text.substringAfter("://")) flag(40, "Contains '@' (hides the real destination)")
        if (host.contains("xn--")) flag(35, "Punycode: may use look-alike characters")
        if (host in shorteners) flag(25, "Link shortener hides the destination")
        if (host.split('.').last() in riskyTlds) flag(20, "High-abuse domain ending")
        if (host.count { it == '.' } >= 4) flag(20, "Unusually many subdomains")
        if (text.length > 150) flag(10, "Very long URL")

        val norm = host.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
        val reg = host.split('.').takeLast(2).joinToString(".")
        brands.firstOrNull { norm.contains(it) && !reg.startsWith("$it.") }
            ?.let { flag(40, "Looks like it imitates '$it' but isn't the real domain") }

        return LinkVerdict(s.coerceAtMost(100), why)
    }
}
