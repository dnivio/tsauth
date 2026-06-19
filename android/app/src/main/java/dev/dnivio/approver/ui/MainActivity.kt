package dev.dnivio.approver.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.key.SecurityLevel
import dev.dnivio.approver.ui.theme.DnivioTheme

/**
 * Main activity showing device status, enrollment state, and pending approvals.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val app = DnivioApplication.instance

        // Start background service if enrolled
        if (app.keyManager.isDeviceAuthAvailable()) {
            dev.dnivio.approver.messaging.DevicePoPService.start(this)
        }

        setContent {
            DnivioTheme {
                MainScreen(
                    isEnrolled = app.keyManager.isDeviceAuthAvailable(),
                    securityLevel = app.keyManager.getSecurityLevel(
                        app.keyManager.DEVICE_AUTH_ALIAS
                    ),
                    counter = app.keyManager.getCurrentCounter(),
                    deviceId = getDeviceId()
                )
            }
        }
    }

    private fun getDeviceId(): String {
        val prefs = getSharedPreferences("dnivio_prefs", MODE_PRIVATE)
        return prefs.getString("device_id", "Not enrolled") ?: "Not enrolled"
    }
}

@Composable
fun MainScreen(
    isEnrolled: Boolean,
    securityLevel: SecurityLevel,
    counter: Long,
    deviceId: String
) {
    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            Text(
                text = "Dnivio",
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold
            )

            Text(
                text = if (isEnrolled) "Approver Active" else "Not Enrolled",
                style = MaterialTheme.typography.bodyLarge,
                color = if (isEnrolled) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.error
            )

            Spacer(modifier = Modifier.height(32.dp))

            if (isEnrolled) {
                StatusCard("Device ID", deviceId.take(16) + "…")
                StatusCard("Security Level", securityLevel.name)
                StatusCard("Signatures", counter.toString())
            } else {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Device Not Enrolled",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "This device has not been set up as an approval device. " +
                                   "Contact your administrator for an enrollment ticket.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun StatusCard(label: String, value: String) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(text = label, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = value,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
        }
    }
}
