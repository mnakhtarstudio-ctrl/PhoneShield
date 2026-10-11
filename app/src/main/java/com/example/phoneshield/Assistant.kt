package com.example.phoneshield

data class Snapshot(val results: List<CheckResult>, val risky: List<AppRisk>, val score: Int)

data class ChatMsg(val fromUser: Boolean, val text: String)

/**
 * Offline rule-based assistant. No AI model, no network, nothing leaves the phone.
 * It matches keywords in the question and answers from the latest scan results.
 */
object Assistant {
    const val WELCOME = "Hi, I'm your PhoneShield assistant. I run fully offline on simple rules " +
        "(no AI model, nothing leaves your phone). Ask what to fix first or which apps look risky, " +
        "or tap a suggestion below."

    val suggestions = listOf(
        "What's my score?",
        "What should I fix first?",
        "Which apps are risky?",
        "Is my Wi-Fi safe?",
        "What is the DNS shield?",
        "Help"
    )

    private const val SCANNING = "I'm still scanning your phone. Try again in a moment."

    private fun has(q: String, vararg words: String) = words.any { q.contains(it) }

    fun reply(input: String, s: Snapshot?): String {
        val q = input.lowercase().trim()
        if (q.isEmpty()) return "Type a question, or tap one of the suggestions."
        val tokens = q.split(Regex("[^a-z0-9']+")).toSet()

        return when {
            q.length <= 12 && (tokens.contains("hi") || tokens.contains("hello") || tokens.contains("hey")) ->
                "Hello! Ask me about your security score, risky apps, Wi-Fi, passwords, or links."

            has(q, "thank") -> "You're welcome. Stay safe!"

            has(q, "help", "what can you", "commands") ->
                "I can help with:\n" +
                    "• your security score\n" +
                    "• what to fix first\n" +
                    "• apps with sensitive access\n" +
                    "• Wi-Fi safety\n" +
                    "• the DNS shield\n" +
                    "• password leaks and suspicious links\n" +
                    "• USB debugging, root, updates, screen lock, accessibility\n" +
                    "• the auto-manager (background checks)"

            has(q, "wifi", "wi-fi", "hotspot", "network") ->
                "Use \"Scan this network\" in the Wi-Fi section. Android hides the encryption type from apps, " +
                    "so I can't verify it for you. Check that your router uses WPA2-AES or WPA3, and avoid " +
                    "banking on unfamiliar public Wi-Fi. A mobile hotspot is safer than an open cafe network."

            has(q, "dns", "vpn", "tracker", "ads", "shield") ->
                "The DNS shield uses a local VPN so DNS lookups (domain names) pass through PhoneShield. " +
                    "Domains on the blocklist are refused, and the rest go to Quad9 over encrypted DNS-over-HTTPS. " +
                    "Only DNS traffic enters the tunnel. It's experimental: it handles IPv4 UDP DNS only and the " +
                    "blocklist is small, so don't rely on it as your only protection."

            has(q, "leak", "breach", "pwned") || (has(q, "password") && !has(q, "lock")) ->
                "Use \"Has my password leaked?\" below. Only the first 5 characters of a SHA-1 hash are sent to " +
                    "Have I Been Pwned, never the password itself. If a password was found in breaches, stop using " +
                    "it everywhere, and use a password manager with unique passwords plus two-factor login."

            has(q, "link", "url", "phish", "scam") ->
                "Paste the link into \"Check a link (offline)\". It looks for raw IP addresses, look-alike brand " +
                    "names, shorteners, risky endings and more, all on your phone. A clean result is not a " +
                    "guarantee. When in doubt, don't tap links from unexpected messages."

            has(q, "auto", "schedule", "background", "alert", "notif") ->
                "The auto-manager rescans your phone about every 12 hours in the background. It alerts you when " +
                    "a new check starts failing or a new app appears with sensitive access (mic, camera, SMS, " +
                    "location, contacts). The first scan only sets a baseline. Turn it on in the Auto-manager " +
                    "section and allow notifications."

            has(q, "score", "how safe", "am i safe") -> {
                if (s == null) SCANNING else {
                    val failing = s.results.filter { !it.passed }
                    val top = failing.maxByOrNull { it.severity.penalty }
                    val tail = if (top == null) "All device checks passed." else
                        "${failing.size} check(s) need attention. Biggest issue: ${top.title}."
                    "Your security score is ${s.score}/100. $tail\n\n" +
                        "This score only reflects device settings. It is not a malware scan or a guarantee."
                }
            }

            has(q, "fix", "first", "improve", "priority", "should i do", "recommend", "todo") -> {
                if (s == null) SCANNING else {
                    val failing = s.results.filter { !it.passed }.sortedByDescending { it.severity.penalty }
                    if (failing.isEmpty()) {
                        "Nothing urgent from the device checks. Keep system updates on, and review app " +
                            "permissions now and then."
                    } else {
                        "Fix these in order:\n" + failing.take(3).mapIndexed { i, r ->
                            "${i + 1}. ${r.title}: ${r.advice}"
                        }.joinToString("\n")
                    }
                }
            }

            has(q, "app", "permission", "spy", "stalker", "camera", "microphone", "mic", "location") -> {
                if (s == null) SCANNING else if (s.risky.isEmpty()) {
                    "No user-installed apps hold the high-risk permissions I check (mic, camera, SMS, " +
                        "call log, contacts, location)."
                } else {
                    "Apps with the most sensitive access:\n" + s.risky.take(5).joinToString("\n") {
                        "• ${it.label} (risk ${it.score}): ${it.granted.joinToString(", ")}"
                    } + "\n\nHigh access isn't proof an app is bad. Maps and messengers need these. " +
                        "Review: Settings > Apps > the app > Permissions. Remove what it doesn't need, " +
                        "and uninstall apps you don't recognize."
                }
            }

            has(q, "usb", "adb", "debug") ->
                about(s, "adb", "USB debugging lets a connected computer control your phone.")

            has(q, "developer") ->
                about(s, "dev_options", "Developer options expose advanced settings that most people don't need.")

            has(q, "root", "jailbreak") ->
                about(s, "root", "Rooting removes Android's core protections. My check is only a heuristic, " +
                    "since root can be hidden.")

            has(q, "patch", "update") ->
                about(s, "patch", "Security patches fix known vulnerabilities. Old patch levels are a real risk.")

            has(q, "lock", "pin") ->
                about(s, "screen_lock", "A PIN or password protects your data if the phone is lost or stolen.")

            has(q, "encrypt") ->
                about(s, "encryption", "Encrypted storage protects your files if someone extracts the data.")

            has(q, "accessib") ->
                about(s, "accessibility", "Accessibility services can read your screen and tap for you, " +
                    "which makes them a favorite route for stalkerware and banking trojans.")

            else ->
                "I'm an offline rules assistant, so I only understand topics like your score, what to fix, " +
                    "risky apps, Wi-Fi, the DNS shield, passwords, links, USB debugging, root and updates. " +
                    "Try a suggestion button, or type \"help\"."
        }
    }

    private fun about(s: Snapshot?, id: String, explain: String): String {
        val r = s?.results?.firstOrNull { it.id == id }
        val state = when {
            r == null -> "I haven't finished scanning yet."
            r.passed -> "Good news: this check passed on your phone."
            else -> "This check failed. ${r.advice}"
        }
        return "$explain\n\n$state"
    }
}
