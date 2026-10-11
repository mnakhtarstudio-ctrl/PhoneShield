package com.example.phoneshield

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Block screenshots and the recent-apps preview of our own screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { MaterialTheme { Surface { ShieldApp() } } }
    }
}

@Composable
fun ShieldApp() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var results by remember { mutableStateOf(emptyList<CheckResult>()) }
    var riskyAll by remember { mutableStateOf(emptyList<AppRisk>()) }
    var shieldOn by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    var verdict by remember { mutableStateOf<LinkVerdict?>(null) }
    var pwd by remember { mutableStateOf("") }
    var pwdMsg by remember { mutableStateOf("") }
    var wifi by remember { mutableStateOf<WifiVerdict?>(null) }
    var autoOn by remember { mutableStateOf(AutoManager.isEnabled(ctx)) }
    var autoMsg by remember { mutableStateOf("") }
    var chatInput by remember { mutableStateOf("") }
    val chat = remember { mutableStateListOf(ChatMsg(false, Assistant.WELCOME)) }

    val score = if (results.isEmpty()) 0 else SecurityChecker(ctx).score(results)
    val snapshot = if (results.isEmpty()) null else Snapshot(results, riskyAll, score)

    fun send(text: String) {
        val t = text.trim()
        if (t.isEmpty()) return
        chat.add(ChatMsg(true, t))
        chat.add(ChatMsg(false, Assistant.reply(t, snapshot)))
        while (chat.size > 30) chat.removeAt(0)
        chatInput = ""
    }

    fun refresh() {
        scope.launch {
            results = withContext(Dispatchers.Default) { SecurityChecker(ctx).runAll() }
            riskyAll = withContext(Dispatchers.Default) { PermissionAuditor(ctx).audit() }
        }
    }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) { ShieldVpnService.start(ctx); shieldOn = true }
    }

    val locLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        if (it) wifi = WifiChecker(ctx).check()
    }

    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        AutoManager.enable(ctx)
        autoOn = true
        autoMsg = if (granted) "Auto-manager is on. It rescans about every 12 hours."
        else "Auto-manager is on, but notifications are blocked. Allow them in Settings to get alerts."
    }

    LaunchedEffect(Unit) { refresh() }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            Column {
                Text("PhoneShield", style = MaterialTheme.typography.headlineMedium)
                Text(
                    if (snapshot == null) "Scanning…" else "Security score: $score/100",
                    style = MaterialTheme.typography.titleLarge
                )
            }
        }

        // ---------- Auto-manager ----------
        item {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Auto-manager", style = MaterialTheme.typography.titleMedium)
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Background checks about every 12 hours", Modifier.weight(1f))
                    Switch(checked = autoOn, onCheckedChange = { on ->
                        if (!on) {
                            AutoManager.disable(ctx); autoOn = false; autoMsg = "Auto-manager is off."
                        } else if (Build.VERSION.SDK_INT >= 33 &&
                            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
                            != PackageManager.PERMISSION_GRANTED
                        ) {
                            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        } else {
                            AutoManager.enable(ctx); autoOn = true
                            autoMsg = "Auto-manager is on. It rescans about every 12 hours."
                        }
                    })
                }
                val last = AutoManager.lastScan(ctx)
                if (last > 0) {
                    Text(
                        "Last background scan: " + DateFormat.getDateTimeInstance().format(Date(last)),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                if (autoMsg.isNotEmpty()) Text(autoMsg, style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = { refresh(); if (autoOn) AutoManager.runNow(ctx) }) { Text("Scan now") }
            }
        }

        // ---------- Assistant ----------
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Assistant (offline, private)", style = MaterialTheme.typography.titleMedium)
                chat.takeLast(6).forEach { m ->
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = if (m.fromUser) Arrangement.End else Arrangement.Start
                    ) {
                        Card(
                            Modifier.fillMaxWidth(0.88f),
                            colors = CardDefaults.cardColors(
                                containerColor = if (m.fromUser) MaterialTheme.colorScheme.primaryContainer
                                else MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Text(m.text, Modifier.padding(10.dp), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                Row(
                    Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Assistant.suggestions.forEach { s ->
                        OutlinedButton(onClick = { send(s) }) { Text(s) }
                    }
                }
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = chatInput,
                        onValueChange = { chatInput = it },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        placeholder = { Text("Ask about your security") },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                        keyboardActions = KeyboardActions(onSend = { send(chatInput) })
                    )
                    Button(onClick = { send(chatInput) }) { Text("Send") }
                }
            }
        }

        // ---------- Device checks ----------
        items(results) { r ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text((if (r.passed) "✅ " else "⚠️ ") + r.title)
                    if (!r.passed) Text(r.advice, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        item { Text("Apps with sensitive access", style = MaterialTheme.typography.titleMedium) }
        items(riskyAll.take(10)) { a ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("${a.label}  (risk ${a.score})")
                    Text(a.granted.joinToString(", "), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // ---------- DNS shield ----------
        item {
            Column {
                Text("DNS shield (blocks malware & trackers)", style = MaterialTheme.typography.titleMedium)
                Button(onClick = {
                    if (shieldOn) { ShieldVpnService.stop(ctx); shieldOn = false }
                    else VpnService.prepare(ctx)?.let { vpnLauncher.launch(it) }
                        ?: run { ShieldVpnService.start(ctx); shieldOn = true }
                }) { Text(if (shieldOn) "Turn OFF" else "Turn ON") }
            }
        }

        // ---------- Wi-Fi ----------
        item {
            Column {
                Text("Wi-Fi safety", style = MaterialTheme.typography.titleMedium)
                Button(onClick = { locLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) }) { Text("Scan this network") }
                wifi?.let { w ->
                    Text(if (w.safe) "✅ ${w.ssid}: no problems found" else "⚠️ ${w.ssid}")
                    w.findings.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }

        // ---------- Link checker ----------
        item {
            Column {
                Text("Check a link (offline)", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(link, { link = it }, Modifier.fillMaxWidth(), singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
                Button(onClick = { verdict = LinkChecker.check(link) }) { Text("Scan") }
                verdict?.let { v ->
                    Text("${v.level} (${v.score})")
                    v.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }

        // ---------- Password check ----------
        item {
            Column {
                Text("Has my password leaked? (k-anonymity)", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(pwd, { pwd = it }, Modifier.fillMaxWidth(), singleLine = true,
                    visualTransformation = PasswordVisualTransformation())
                Button(onClick = {
                    val p = pwd; pwd = ""            // clear from memory/UI immediately
                    scope.launch {
                        pwdMsg = when (val n = BreachChecker.timesPwned(p)) {
                            null -> "Couldn't check (offline?)"
                            0 -> "Not found in known breaches"
                            else -> "Seen $n times in breaches. Never use it again."
                        }
                    }
                }) { Text("Check") }
                if (pwdMsg.isNotEmpty()) Text(pwdMsg)
            }
        }
    }
}
