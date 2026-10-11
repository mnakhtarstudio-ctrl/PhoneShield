package com.example.phoneshield

import android.content.Context
import android.content.Intent
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Local DNS firewall. Only DNS traffic enters the tunnel; all other traffic
 * bypasses it. Blocked domains get NXDOMAIN, the rest go to Quad9 over
 * DNS-over-HTTPS (encrypted; Quad9 also blocks known malware domains).
 * Nothing is logged or sent to us.
 */
class ShieldVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private val pool = Executors.newFixedThreadPool(8)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stop(); return START_NOT_STICKY }
        showForegroundNotification()
        if (!running) start()
        return START_STICKY
    }

    @Suppress("DEPRECATION")
    private fun showForegroundNotification() {
        val channelId = "phoneshield_dns"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(NotificationChannel(
                channelId, "PhoneShield DNS protection", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows when PhoneShield DNS protection is active." })
        }
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            Notification.Builder(this)
        }.setContentTitle("PhoneShield DNS protection")
            .setContentText("DNS filtering service is running")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
        startForeground(42, notification)
    }

    private fun start() {
        tun = Builder()
            .setSession("PhoneShield DNS")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)      // ONLY DNS goes through us
            .addDisallowedApplication(packageName)   // our own HTTPS bypasses the tunnel
            .setBlocking(true)
            .establish() ?: return
        running = true
        Thread { loop(tun!!) }.start()
    }

    private fun loop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val len = try { input.read(buf) } catch (e: Exception) { break }
            if (len <= 0) continue
            val pkt = buf.copyOf(len)
            pool.execute { runCatching { handle(pkt, output) } }
        }
    }

    private fun handle(p: ByteArray, out: FileOutputStream) {
        if (p.size < 28 || (p[0].toInt() shr 4) != 4 || p[9].toInt() != 17) return // IPv4 UDP only
        val ihl = (p[0].toInt() and 0xF) * 4
        val dport = ((p[ihl + 2].toInt() and 0xFF) shl 8) or (p[ihl + 3].toInt() and 0xFF)
        if (dport != 53) return
        val dns = p.copyOfRange(ihl + 8, p.size)
        val (name, qEnd) = parseQuestion(dns) ?: return

        val reply = if (Blocklist.isBlocked(name)) nxdomain(dns, qEnd) else forward(dns) ?: return
        val resp = buildUdpReply(p, ihl, reply)
        synchronized(out) { out.write(resp) }
    }

    /**
     * DNS-over-HTTPS (RFC 8484) to Quad9. The app is excluded from its own VPN,
     * so the resolver hostname can be resolved outside the tunnel and normal TLS
     * hostname verification remains enabled. Fails CLOSED: no plaintext fallback.
     */
    private fun forward(query: ByteArray): ByteArray? = try {
        val originalId = query.copyOf(2)
        val q = query.copyOf().also { it[0] = 0; it[1] = 0 }      // ID 0 per RFC 8484
        val c = URL("https://dns.quad9.net/dns-query").openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.doOutput = true
        c.connectTimeout = 4000; c.readTimeout = 4000
        c.setRequestProperty("Content-Type", "application/dns-message")
        c.setRequestProperty("Accept", "application/dns-message")
        c.outputStream.use { it.write(q) }
        if (c.responseCode != 200) null
        else c.inputStream.use { it.readBytes() }.also { it[0] = originalId[0]; it[1] = originalId[1] }
    } catch (e: Exception) { null }

    /** Returns (domain, index just past the question section). */
    private fun parseQuestion(d: ByteArray): Pair<String, Int>? {
        if (d.size < 17) return null
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val l = d[i].toInt() and 0xFF
            if (l == 0) { i++; break }
            if (l and 0xC0 != 0 || i + 1 + l > d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, l, Charsets.US_ASCII))
            i += 1 + l
        }
        return if (i + 4 <= d.size) sb.toString().lowercase() to (i + 4) else null
    }

    private fun nxdomain(q: ByteArray, qEnd: Int): ByteArray {
        val r = q.copyOf(qEnd)
        r[2] = 0x81.toByte(); r[3] = 0x83.toByte()          // response, RA, RCODE=3
        for (i in 6..11) r[i] = 0                          // no answer/authority/extra
        return r
    }

    private fun buildUdpReply(req: ByteArray, ihl: Int, payload: ByteArray): ByteArray {
        val total = 28 + payload.size
        val r = ByteArray(total)
        r[0] = 0x45; r[8] = 64; r[9] = 17
        r[2] = (total shr 8).toByte(); r[3] = total.toByte()
        System.arraycopy(req, 16, r, 12, 4)               // src = original dst
        System.arraycopy(req, 12, r, 16, 4)               // dst = original src
        System.arraycopy(req, ihl + 2, r, 20, 2)          // src port = original dst port
        System.arraycopy(req, ihl, r, 22, 2)              // dst port = original src port
        val ulen = 8 + payload.size
        r[24] = (ulen shr 8).toByte(); r[25] = ulen.toByte()
        System.arraycopy(payload, 0, r, 28, payload.size)
        var sum = 0
        for (i in 0 until 20 step 2) sum += ((r[i].toInt() and 0xFF) shl 8) or (r[i + 1].toInt() and 0xFF)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val cs = sum.inv() and 0xFFFF
        r[10] = (cs shr 8).toByte(); r[11] = cs.toByte()
        return r
    }

    private fun stop() {
        running = false
        tun?.close(); tun = null
        stopSelf()
    }

    override fun onDestroy() { running = false; tun?.close(); pool.shutdownNow(); super.onDestroy() }

    companion object {
        const val ACTION_STOP = "STOP"
        fun start(c: Context) {
            val intent = Intent(c, ShieldVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) c.startForegroundService(intent) else c.startService(intent)
        }
        fun stop(c: Context) {
            val intent = Intent(c, ShieldVpnService::class.java).setAction(ACTION_STOP)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) c.startForegroundService(intent) else c.startService(intent)
        }
    }
}

object Blocklist {
    // Starter set. In production, load StevenBlack / URLhaus host lists from assets/.
    private val domains = hashSetOf(
        "doubleclick.net", "googlesyndication.com", "scorecardresearch.com",
        "adservice.google.com", "ads.mopub.com", "analytics.tiktok.com"
    )
    fun load(extra: Collection<String>) { domains.addAll(extra) }

    /** Matches the domain and every parent (a.b.evil.com -> b.evil.com -> evil.com). */
    fun isBlocked(host: String): Boolean {
        var h = host
        while (true) {
            if (h in domains) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
    }
}
