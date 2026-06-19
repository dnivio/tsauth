package dev.dnivio.approver.messaging

import android.content.Context
import android.content.Intent
import android.util.Base64
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.crypto.RequestVerifier
import dev.dnivio.approver.crypto.VerificationException
import dev.dnivio.approver.key.KeyManager
import dev.dnivio.approver.ui.ApprovalActivity
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Client for communicating with the Dnivio Approval Service.
 *
 * Uses two paths:
 * 1. Public-HTTPS device-PoP (primary, independent of tailnet) — DR-APP-4
 * 2. Authenticated gRPC channel (when tailnet is available)
 *
 * All requests carry device_auth signatures over the request parameters.
 * Approve responses additionally carry approval_auth signatures.
 */
class ApprovalClient(
    private val context: Context,
    private val verifier: RequestVerifier,
    private val keyManager: KeyManager
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    private val serviceOrigin: String
        get() = getPreference("service_origin", "https://approval.dnivio.dev")

    private val tenantId: String
        get() = getPreference("tenant_id", "")

    private val deviceId: String
        get() = getPreference("device_id", "")

    // ─── Channel Authentication ─────────────────────────────────────────────

    /**
     * Establishes an authenticated session with the Approval Service.
     * Sends an ApproverHello signed with device_auth (no biometric needed).
     */
    suspend fun establishChannel(): Boolean {
        if (deviceId.isEmpty()) return false

        val hello = buildHelloMessage()
        val signature = keyManager.signWithDeviceAuth(hello)

        val body = mapOf(
            "tenant_id" to tenantId,
            "device_id" to deviceId,
            "hello" to Base64.encodeToString(hello, Base64.NO_WRAP),
            "signature" to Base64.encodeToString(signature.signature, Base64.NO_WRAP)
        )

        return try {
            val response = post("$serviceOrigin/v1/approver/hello", body)
            response.isSuccessful
        } catch (e: Exception) {
            false
        }
    }

    // ─── Envelope Fetch ─────────────────────────────────────────────────────

    /**
     * Fetches a single pending request envelope by request_id.
     * Called after FCM wake hint or during polling.
     */
    suspend fun fetchEnvelope(requestId: String): ByteArray? {
        val sigData = "$tenantId:$deviceId:$requestId:${System.currentTimeMillis() / 1000}".toByteArray()
        val sig = keyManager.signWithDeviceAuth(sigData)

        return try {
            val response = get("$serviceOrigin/v1/approver/requests/$requestId", mapOf(
                "X-Dnivio-Device-Signature" to Base64.encodeToString(sig.signature, Base64.NO_WRAP),
                "X-Dnivio-Device-Id" to deviceId,
                "X-Dnivio-Tenant-Id" to tenantId
            ))
            if (response.isSuccessful) {
                response.body?.bytes()
            } else null
        } catch (e: Exception) {
            null
        }
    }

    // ─── Polling ────────────────────────────────────────────────────────────

    /**
     * Polls for pending approval requests.
     * Called periodically by the DevicePoPService background loop.
     */
    suspend fun pollPendingRequests() {
        if (deviceId.isEmpty()) return

        val sigData = "$tenantId:$deviceId:poll:${System.currentTimeMillis() / 1000}".toByteArray()
        val sig = keyManager.signWithDeviceAuth(sigData)

        try {
            val response = get("$serviceOrigin/v1/approver/pending", mapOf(
                "X-Dnivio-Device-Signature" to Base64.encodeToString(sig.signature, Base64.NO_WRAP),
                "X-Dnivio-Device-Id" to deviceId,
                "X-Dnivio-Tenant-Id" to tenantId
            ))
            if (response.isSuccessful) {
                val body = response.body?.string() ?: return
                // Parse pending request list and process each envelope
                val json = org.json.JSONObject(body)
                val envelopes = json.optJSONArray("envelopes") ?: return
                for (i in 0 until envelopes.length()) {
                    val envelopeB64 = envelopes.getString(i)
                    val envelopeBytes = Base64.decode(envelopeB64, Base64.NO_WRAP)
                    processEnvelope(envelopeBytes)
                }
            }
        } catch (e: Exception) {
            // Connectivity errors are expected — polling will retry
        }
    }

    // ─── Envelope Processing ────────────────────────────────────────────────

    /**
     * Verifies and processes a received request envelope.
     * Per DR-SIG-1/DR-APP-2: verify-before-render.
     */
    fun processEnvelope(envelopeBytes: ByteArray) {
        try {
            val request = verifier.verify(envelopeBytes)

            // Verification passed — present to user
            showApprovalActivity(request)
        } catch (e: VerificationException) {
            // Unsigned, non-canonical, duplicate, expired, or unknown-key request
            // Rejected without display per DR-SIG-1
        }
    }

    private fun showApprovalActivity(request: RequestVerifier.VerifiedRequest) {
        val intent = Intent(context, ApprovalActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("request_id", request.requestId)
            putExtra("src_node", request.initiating.srcNodeDisplay)
            putExtra("src_node_verified", request.initiating.srcNodeVerified)
            putExtra("destination", request.resource.displayName)
            putExtra("service_id", request.resource.serviceId)
            putExtra("port", request.resource.port)
            putExtra("protocol", request.protocol)
            putExtra("ssh_account", request.sshAccount)
            putExtra("scope", request.scope)
            putExtra("rule_id", request.ruleId)
            putExtra("expires_at", request.expiresAt)
            putExtra("challenge", Base64.encodeToString(request.challenge, Base64.NO_WRAP))
            putExtra("display_digest", Base64.encodeToString(request.displayDigest, Base64.NO_WRAP))
            putExtra("envelope_hash", Base64.encodeToString(
                MessageDigest.getInstance("SHA-256").digest(envelopeBytes), Base64.NO_WRAP
            ))
        }
        context.startActivity(intent)
    }

    // ─── Submit Decision ────────────────────────────────────────────────────

    /**
     * Submits the approval decision to the Approval Service.
     *
     * For APPROVE: signature must be from approval_auth (proves fresh biometric).
     * For DENY: signature is from device_auth (no biometric needed, per DR-APP-1).
     */
    suspend fun submitDecision(
        requestId: String,
        decision: String,         // "APPROVE" or "DENY"
        responseSignature: ByteArray,
        keyId: String,
        deviceCounter: Long,
        channelBinding: ByteArray,
        responseNonce: ByteArray,
        requestHash: ByteArray
    ): Boolean {
        val body = mapOf(
            "request_id" to requestId,
            "decision" to decision,
            "device_id" to deviceId,
            "key_id" to keyId,
            "signed_at" to (System.currentTimeMillis() / 1000).toString(),
            "device_counter" to deviceCounter.toString(),
            "channel_binding" to Base64.encodeToString(channelBinding, Base64.NO_WRAP),
            "response_nonce" to Base64.encodeToString(responseNonce, Base64.NO_WRAP),
            "request_hash" to Base64.encodeToString(requestHash, Base64.NO_WRAP),
            "signature" to Base64.encodeToString(responseSignature, Base64.NO_WRAP)
        )

        return try {
            val response = post("$serviceOrigin/v1/approver/decide", body)
            response.isSuccessful
        } catch (e: Exception) {
            false
        }
    }

    // ─── Push Token Registration ────────────────────────────────────────────

    fun registerPushToken(token: String) {
        // Store and register with service in background
        val prefs = context.getSharedPreferences("dnivio_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("push_token", token).apply()

        // Async registration
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val sigData = "$tenantId:$deviceId:push_token:$token".toByteArray()
                val sig = keyManager.signWithDeviceAuth(sigData)
                post("$serviceOrigin/v1/approver/push-token", mapOf(
                    "device_id" to deviceId,
                    "token" to token,
                    "signature" to Base64.encodeToString(sig.signature, Base64.NO_WRAP)
                ))
            } catch (_: Exception) {}
        }
    }

    // ─── HTTP Helpers ───────────────────────────────────────────────────────

    private suspend fun get(url: String, headers: Map<String, String>): Response {
        return withContext(Dispatchers.IO) {
            val request = Request.Builder().url(url).apply {
                headers.forEach { (k, v) -> addHeader(k, v) }
            }.build()
            client.newCall(request).execute()
        }
    }

    private suspend fun post(url: String, body: Map<String, String>): Response {
        return withContext(Dispatchers.IO) {
            val json = org.json.JSONObject(body.toMap()).toString()
            val requestBody = json.toRequestBody("application/json".toMediaType())
            val request = Request.Builder().url(url).post(requestBody).build()
            client.newCall(request).execute()
        }
    }

    // ─── Preferences ────────────────────────────────────────────────────────

    private fun getPreference(key: String, default: String): String {
        return context.getSharedPreferences("dnivio_prefs", Context.MODE_PRIVATE)
            .getString(key, default) ?: default
    }

    private fun buildHelloMessage(): ByteArray {
        val nonce = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val ts = (System.currentTimeMillis() / 1000).toString()
        return "$tenantId:$deviceId:$ts:${Base64.encodeToString(nonce, Base64.NO_WRAP)}".toByteArray()
    }
}
