package com.example.phoneshield

import android.Manifest
import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
    var risky by remember { mutableStateOf(emptyList<AppRisk>()) }
    var shieldOn by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    var verdict by remember { mutableStateOf<LinkVerdict?>(null) }
    var pwd by remember { mutableStateOf("") }
    var pwdMsg by remember { mutableStateOf("") }
    var wifi by remember { mutableStateOf<WifiVerdict?>(null) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) { ShieldVpnService.start(ctx); shieldOn = true }
    }

    val locLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        if (it) wifi = WifiChecker(ctx).check()
    }

    LaunchedEffect(Unit) {
        results = SecurityChecker(ctx).runAll()
        risky = withContext(Dispatchers.Default) { PermissionAuditor(ctx).audit().take(10) }
    }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item { Column {
            Text("PhoneShield", style = MaterialTheme.typography.headlineMedium)
            Text("Security score: ${SecurityChecker(ctx).score(results)}/100",
                style = MaterialTheme.typography.titleLarge)
        } }
        items(results) { r ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text((if (r.passed) "✅ " else "⚠️ ") + r.title)
                    if (!r.passed) Text(r.advice, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        item { Text("Apps with sensitive access", style = MaterialTheme.typography.titleMedium) }
        items(risky) { a ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("${a.label}  (risk ${a.score})")
                    Text(a.granted.joinToString(", "), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        item { Column {
            Text("DNS shield (blocks malware & trackers)", style = MaterialTheme.typography.titleMedium)
            Button(onClick = {
                if (shieldOn) { ShieldVpnService.stop(ctx); shieldOn = false }
                else VpnService.prepare(ctx)?.let { vpnLauncher.launch(it) }
                    ?: run { ShieldVpnService.start(ctx); shieldOn = true }
            }) { Text(if (shieldOn) "Turn OFF" else "Turn ON") }
        } }

        item { Column {
            Text("Wi-Fi safety", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { locLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) }) { Text("Scan this network") }
            wifi?.let { w ->
                Text(if (w.safe) "✅ ${w.ssid}: no problems found" else "⚠️ ${w.ssid}")
                w.findings.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        } }

        item { Column {
            Text("Check a link (offline)", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(link, { link = it }, Modifier.fillMaxWidth(), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            Button(onClick = { verdict = LinkChecker.check(link) }) { Text("Scan") }
            verdict?.let { v ->
                Text("${v.level} (${v.score})")
                v.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            }
        } }

        item { Column {
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
        } }
    }
}
