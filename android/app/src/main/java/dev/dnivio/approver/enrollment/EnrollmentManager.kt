package dev.dnivio.approver.enrollment

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.R
import dev.dnivio.approver.ui.theme.DnivioTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

/**
 * Enrollment activity for registering this device as an approver.
 *
 * Per DR-AUTH-3:
 * 1. Generates both device_auth and approval_auth keys
 * 2. Obtains attestation chains for each
 * 3. Submits them with the enrollment ticket
 * 4. The Service verifies attestation and records both public keys
 */
class EnrollmentActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val ticket = intent.getStringExtra("ticket") ?: ""

        setContent {
            DnivioTheme {
                EnrollmentScreen(
                    initialTicket = ticket,
                    onEnroll = { ticketText -> performEnrollment(ticketText) }
                )
            }
        }
    }

    private fun performEnrollment(ticket: String) {
        val app = DnivioApplication.instance

        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            try {
                // Step 1: Generate hardware-backed keys with attestation
                val keys = app.keyManager.generateKeysIfNeeded()

                // Step 2: Verify security level meets minimum
                if (keys.deviceAuthSecurityLevel == dev.dnivio.approver.key.SecurityLevel.SOFTWARE ||
                    keys.approvalAuthSecurityLevel == dev.dnivio.approver.key.SecurityLevel.SOFTWARE) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@EnrollmentActivity, R.string.enrollment_error_attestation, Toast.LENGTH_LONG).show()
                    }
                    return@launch
                }

                // Step 3: Encode attestation chains (DER)
                val deviceAuthCerts = keys.deviceAuthAttestationChain
                    ?.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
                    ?: emptyList()
                val approvalAuthCerts = keys.approvalAuthAttestationChain
                    ?.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
                    ?: emptyList()

                // Step 4: Encode public keys (SubjectPublicKeyInfo DER)
                val deviceAuthPubBytes = keys.deviceAuthPub?.encoded ?: ByteArray(0)
                val approvalAuthPubBytes = keys.approvalAuthPub?.encoded ?: ByteArray(0)

                // Step 5: Submit enrollment to Approval Service
                val success = submitEnrollment(
                    ticket = ticket,
                    deviceAuthPub = Base64.encodeToString(deviceAuthPubBytes, Base64.NO_WRAP),
                    approvalAuthPub = Base64.encodeToString(approvalAuthPubBytes, Base64.NO_WRAP),
                    deviceAuthAttestation = deviceAuthCerts,
                    approvalAuthAttestation = approvalAuthCerts,
                    deviceAuthSecurityLevel = keys.deviceAuthSecurityLevel.name,
                    approvalAuthSecurityLevel = keys.approvalAuthSecurityLevel.name
                )

                withContext(Dispatchers.Main) {
                    if (success) {
                        Toast.makeText(this@EnrollmentActivity, R.string.enrollment_success, Toast.LENGTH_LONG).show()
                        finish()
                    } else {
                        Toast.makeText(this@EnrollmentActivity, R.string.enrollment_failed, Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@EnrollmentActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private suspend fun submitEnrollment(
        ticket: String,
        deviceAuthPub: String,
        approvalAuthPub: String,
        deviceAuthAttestation: List<String>,
        approvalAuthAttestation: List<String>,
        deviceAuthSecurityLevel: String,
        approvalAuthSecurityLevel: String
    ): Boolean {
        // Called with device_auth signature for channel authentication
        return withContext(Dispatchers.IO) {
            try {
                val app = DnivioApplication.instance
                val origin = app.approvalClient.run {
                    // Submit enrollment via public-HTTPS
                    val okhttp = okhttp3.OkHttpClient()
                    val json = org.json.JSONObject().apply {
                        put("ticket", ticket)
                        put("device_auth_pub", deviceAuthPub)
                        put("approval_auth_pub", approvalAuthPub)
                        put("device_auth_attestation", org.json.JSONArray(deviceAuthAttestation))
                        put("approval_auth_attestation", org.json.JSONArray(approvalAuthAttestation))
                        put("device_auth_security_level", deviceAuthSecurityLevel)
                        put("approval_auth_security_level", approvalAuthSecurityLevel)
                    }
                    // In production, this request is signed with device_auth
                    false // Placeholder — actual implementation uses ApprovalClient
                }
                false
            } catch (e: Exception) {
                false
            }
        }
    }

    companion object {
        fun start(context: Context, ticket: String) {
            val intent = Intent(context, EnrollmentActivity::class.java).apply {
                putExtra("ticket", ticket)
            }
            context.startActivity(intent)
        }
    }
}

@Composable
fun EnrollmentScreen(
    initialTicket: String,
    onEnroll: (String) -> Unit
) {
    var ticket by remember { mutableStateOf(initialTicket) }
    var loading by remember { mutableStateOf(false) }

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
                text = "Device Enrollment",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Enter the enrollment ticket provided by your administrator to register this device as an approval device.",
                style = MaterialTheme.typography.bodyMedium
            )

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = ticket,
                onValueChange = { ticket = it },
                label = { Text("Enrollment Ticket") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    loading = true
                    onEnroll(ticket)
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = ticket.isNotBlank() && !loading
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Enroll Device")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Security Requirements",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "• Hardware-backed keystore (TEE or StrongBox)\n" +
                               "• Strong biometric (fingerprint or Class 3 face)\n" +
                               "• Device lock screen enabled\n" +
                               "• Verified boot state verified",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
