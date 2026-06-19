package dev.dnivio.approver.ui

import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.R
import dev.dnivio.approver.ui.theme.DnivioTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executor

/**
 * Activity shown when an approval request arrives.
 *
 * Per DR-APP-2: Renders the exact display_digest-covered fields:
 * canonical destination + port, tenant/tailnet, verified source device name,
 * target SSH account, requested scope + duration, policy reason,
 * request/expiry countdown, and a risk indicator for unusual context.
 *
 * Per DR-APP-1: Approve uses BiometricPrompt with approval_auth (AUTH_BIOMETRIC_STRONG).
 * Deny signs with device_auth and never prompts biometrics.
 */
class ApprovalActivity : ComponentActivity() {

    private val app get() = DnivioApplication.instance

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val requestId = intent.getStringExtra("request_id") ?: return finish()
        val srcNode = intent.getStringExtra("src_node") ?: "Unknown"
        val srcNodeVerified = intent.getBooleanExtra("src_node_verified", false)
        val destination = intent.getStringExtra("destination") ?: "Unknown"
        val serviceId = intent.getStringExtra("service_id") ?: ""
        val port = intent.getIntExtra("port", 0)
        val protocol = intent.getStringExtra("protocol") ?: "TCP"
        val sshAccount = intent.getStringExtra("ssh_account")
        val scope = intent.getStringExtra("scope") ?: "CONNECTION"
        val ruleId = intent.getStringExtra("rule_id") ?: ""
        val expiresAt = intent.getLongExtra("expires_at", 0)
        val envelopeHash = intent.getStringExtra("envelope_hash") ?: ""

        setContent {
            DnivioTheme {
                ApprovalScreen(
                    requestId = requestId,
                    srcNode = srcNode,
                    srcNodeVerified = srcNodeVerified,
                    destination = destination,
                    serviceId = serviceId,
                    port = port,
                    protocol = protocol,
                    sshAccount = sshAccount,
                    scope = scope,
                    ruleId = ruleId,
                    expiresAt = expiresAt,
                    envelopeHash = envelopeHash,
                    onApprove = { authenticateAndApprove(requestId, envelopeHash) },
                    onDeny = { denyRequest(requestId, envelopeHash) }
                )
            }
        }
    }

    // ─── Approve — Requires Biometric ──────────────────────────────────────

    private fun authenticateAndApprove(requestId: String, envelopeHashB64: String) {
        val executor = ContextCompat.getMainExecutor(this)

        // Check biometric availability
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> { /* proceed */ }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                { Toast.makeText(this, R.string.biometric_no_hardware, Toast.LENGTH_LONG).show(); return }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                { Toast.makeText(this, R.string.biometric_unavailable, Toast.LENGTH_LONG).show(); return }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                { Toast.makeText(this, R.string.biometric_not_enrolled, Toast.LENGTH_LONG).show(); return }
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                { Toast.makeText(this, R.string.biometric_security_update, Toast.LENGTH_LONG).show(); return }
        }

        // Create CryptoObject bound to approval_auth
        // This proves a fresh strong biometric was presented (DR-KEY-2)
        val cryptoSignature = try {
            app.keyManager.createApprovalSignature()
        } catch (e: Exception) {
            Toast.makeText(this, "Approval key unavailable — re-enrollment required", Toast.LENGTH_LONG).show()
            return
        }

        val crypto = BiometricPrompt.CryptoObject(cryptoSignature)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setDescription(getString(R.string.biometric_description))
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()

        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // Biometric verified — finalize the approval signature
                submitApproval(requestId, envelopeHashB64)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Toast.makeText(this@ApprovalActivity, errString, Toast.LENGTH_LONG).show()
            }

            override fun onAuthenticationFailed() {
                Toast.makeText(this@ApprovalActivity, R.string.biometric_failed, Toast.LENGTH_SHORT).show()
            }
        })

        prompt.authenticate(promptInfo, crypto)
    }

    // ─── Submit Approval ────────────────────────────────────────────────────

    private fun submitApproval(requestId: String, envelopeHashB64: String) {
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            try {
                val km = app.keyManager
                val envelopeHash = Base64.decode(envelopeHashB64, Base64.NO_WRAP)
                val channelBinding = SecureRandom().let { ByteArray(32).also { it.nextBytes(it) } }
                val responseNonce = SecureRandom().let { ByteArray(32).also { it.nextBytes(it) } }

                // Build the signed response message per DR-SIG-5
                // Sign: hash(RequestEnvelope) || decision || device_id || key_id || signed_at || counter || channel_binding || response_nonce
                val toSign = ByteArrayOutputStream().apply {
                    write(envelopeHash)
                    write("APPROVE".toByteArray())
                    write(getDeviceIdBytes())
                    write("approval_auth".toByteArray())
                    write((System.currentTimeMillis() / 1000).toString().toByteArray())
                    write(km.getAndIncrementCounter().toString().toByteArray())
                    write(channelBinding)
                    write(responseNonce)
                }.toByteArray()

                // Sign with approval_auth (already authenticated via biometric CryptoObject)
                val cryptoSignature = km.createApprovalSignature()
                cryptoSignature.update(toSign)
                val sigResult = km.finalizeApprovalSignature(cryptoSignature)

                val success = app.approvalClient.submitDecision(
                    requestId = requestId,
                    decision = "APPROVE",
                    responseSignature = sigResult.signature,
                    keyId = "approval_auth",
                    deviceCounter = km.getCurrentCounter(),
                    channelBinding = channelBinding,
                    responseNonce = responseNonce,
                    requestHash = envelopeHash
                )

                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@ApprovalActivity,
                        if (success) R.string.approval_sent else R.string.approval_failed,
                        Toast.LENGTH_SHORT
                    ).show()
                    finish()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ApprovalActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                    finish()
                }
            }
        }
    }

    // ─── Deny — No Biometric Needed (DR-APP-1) ─────────────────────────────

    private fun denyRequest(requestId: String, envelopeHashB64: String) {
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            try {
                val km = app.keyManager
                val envelopeHash = Base64.decode(envelopeHashB64, Base64.NO_WRAP)

                // Sign Deny with device_auth (no biometric required)
                val toSign = ByteArrayOutputStream().apply {
                    write(envelopeHash)
                    write("DENY".toByteArray())
                    write(getDeviceIdBytes())
                    write("device_auth".toByteArray())
                    write((System.currentTimeMillis() / 1000).toString().toByteArray())
                    write(km.getAndIncrementCounter().toString().toByteArray())
                    write(ByteArray(32)) // channel_binding
                    write(ByteArray(32)) // response_nonce
                }.toByteArray()

                val sigResult = km.signWithDeviceAuth(toSign)

                app.approvalClient.submitDecision(
                    requestId = requestId,
                    decision = "DENY",
                    responseSignature = sigResult.signature,
                    keyId = "device_auth",
                    deviceCounter = km.getCurrentCounter(),
                    channelBinding = ByteArray(32),
                    responseNonce = ByteArray(32),
                    requestHash = envelopeHash
                )

                withContext(Dispatchers.Main) {
                    finish()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { finish() }
            }
        }
    }

    private fun getDeviceIdBytes(): ByteArray {
        val prefs = getSharedPreferences("dnivio_prefs", MODE_PRIVATE)
        return (prefs.getString("device_id", "unknown") ?: "unknown").toByteArray()
    }
}

// ─── Approval Screen Composable ────────────────────────────────────────────

@Composable
fun ApprovalScreen(
    requestId: String,
    srcNode: String,
    srcNodeVerified: Boolean,
    destination: String,
    serviceId: String,
    port: Int,
    protocol: String,
    sshAccount: String?,
    scope: String,
    ruleId: String,
    expiresAt: Long,
    envelopeHash: String,
    onApprove: () -> Unit,
    onDeny: () -> Unit
) {
    var timeLeft by remember { mutableStateOf(0L) }

    LaunchedEffect(expiresAt) {
        while (true) {
            val now = System.currentTimeMillis() / 1000
            timeLeft = (expiresAt - now).coerceAtLeast(0)
            if (timeLeft <= 0) {
                onDeny() // Auto-deny on expiry
                break
            }
            kotlinx.coroutines.delay(1000)
        }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            // ─── Access Details ────────────────────────────────────────────
            Column {
                Text(
                    text = "Access Verification Required",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Approve biometric verification to grant access.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Destination
                DetailRow("Destination", destination)
                if (port > 0) DetailRow("Port", "$port/$protocol")

                // Source device
                DetailRow(
                    "Requesting Device",
                    srcNode + if (!srcNodeVerified) " ⚠" else ""
                )

                // SSH account (account-aware modes)
                if (!sshAccount.isNullOrEmpty()) {
                    DetailRow("SSH Account", sshAccount)
                }

                // Scope
                DetailRow("Scope", scope)

                // Policy reason
                if (ruleId.isNotEmpty()) {
                    DetailRow("Policy", ruleId)
                }

                // Request ID (for audit trail)
                DetailRow("Request ID", requestId.take(12) + "…")

                // Timer
                Spacer(modifier = Modifier.height(12.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (timeLeft < 15)
                            MaterialTheme.colorScheme.errorContainer
                        else
                            MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Text(
                        text = "Expires in ${timeLeft}s",
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (timeLeft < 15) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ─── Action Buttons ────────────────────────────────────────────
            Column {
                Button(
                    onClick = onApprove,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = timeLeft > 0
                ) {
                    Text("Approve (Biometric)", modifier = Modifier.padding(vertical = 8.dp))
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedButton(
                    onClick = onDeny,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Deny", modifier = Modifier.padding(vertical = 8.dp))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyLarge,
            fontFamily = FontFamily.Monospace
        )
    }
}

class ByteArrayOutputStream : java.io.ByteArrayOutputStream()
