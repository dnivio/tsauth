package dev.dnivio.approver.crypto

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.Signature

/**
 * Verifies COSE_Sign1 request envelopes from the Approval Service.
 * Per DR-SIG-1: Verify-before-render — must validate the signed envelope
 * before displaying any request to the user.
 *
 * Uses deterministic CBOR encoding rules: sorted map keys, definite lengths.
 */
class RequestVerifier(
    private val keyResolver: TrustedKeyResolver
) {
    /**
     * Trusted key resolver provides the pinned request_sig public key
     * for signature verification. Anchored by the offline root.
     */
    interface TrustedKeyResolver {
        fun getRequestSigPublicKey(kid: String): ECPublicKey?
        fun getExpectedTenantId(): String
        fun getDeviceId(): String
    }

    // ─── Verification Result ───────────────────────────────────────────────

    data class VerifiedRequest(
        val requestId: String,
        val tenantId: String,
        val tailnetId: String,
        val audienceDeviceId: String,
        val initiating: InitiatingInfo,
        val resource: ResourceInfo,
        val protocol: String,
        val sshAccount: String?,
        val scope: String,
        val policyVersion: Long,
        val ruleId: String,
        val issuedAt: Long,       // epoch seconds
        val expiresAt: Long,
        val challenge: ByteArray,
        val displayDigest: ByteArray,
        val binding: BindingInfo
    )

    data class InitiatingInfo(
        val srcNodeId: String,
        val srcNodeDisplay: String,
        val srcNodeVerified: Boolean,
        val requestingIp: String
    )

    data class ResourceInfo(
        val protectedNodeId: String,
        val serviceId: String,
        val port: Int,
        val transport: String,
        val deploymentMode: String,
        val displayName: String
    )

    data class BindingInfo(
        val bindingType: String,  // "http_request", "connection", "session"
        val bindingId: String     // request_nonce, connection_id, or session_id
    )

    // ─── Main Verification Entry Point ─────────────────────────────────────

    /**
     * Verifies a COSE_Sign1 request envelope and returns the verified payload.
     * Throws VerificationException if any check fails.
     *
     * Per DR-SIG-1 checks:
     * - Signature valid against pinned request_sig trust root
     * - alg/kid known
     * - audience_device_id == this device
     * - tenant_id expected
     * - challenge unseen (replay protection)
     * - issued_at/expires_at valid with skew bound
     * - canonical encoding exact
     * - display_digest matches
     */
    fun verify(envelopeBytes: ByteArray): VerifiedRequest {
        // Step 1: Parse COSE_Sign1 structure
        val cose = CoseSign1.parse(envelopeBytes)

        // Step 2: Verify algorithm
        if (cose.algorithm != ALG_EDDSA && cose.algorithm != ALG_ES256) {
            throw VerificationException("Unsupported algorithm: ${cose.algorithm}")
        }

        // Step 3: Get trusted public key for this kid
        val kid = cose.kid ?: throw VerificationException("Missing kid in protected headers")
        val publicKey = keyResolver.getRequestSigPublicKey(kid)
            ?: throw VerificationException("Unknown kid: $kid")

        // Step 4: Verify signature over SigStructure
        val sigStructure = buildSigStructure(cose)
        if (!verifySignature(publicKey, sigStructure, cose.signature)) {
            throw VerificationException("Signature verification failed")
        }

        // Step 5: Decode payload (deterministic CBOR)
        val payload = CborMap.parse(cose.payload)

        // Step 6: DR-SIG-1 checks
        val audienceDeviceId = payload.getString(7)    // audience_device_id
        if (audienceDeviceId != keyResolver.getDeviceId()) {
            throw VerificationException("Audience device mismatch: $audienceDeviceId != ${keyResolver.getDeviceId()}")
        }

        val tenantId = payload.getString(3)            // tenant_id
        if (tenantId != keyResolver.getExpectedTenantId()) {
            throw VerificationException("Tenant mismatch: $tenantId")
        }

        val issuedAt = payload.getLong(5)              // issued_at
        val expiresAt = payload.getLong(6)             // expires_at
        val now = System.currentTimeMillis() / 1000
        if (now > expiresAt + SKEW_SECONDS) {
            throw VerificationException("Request expired: now=$now expires=$expiresAt")
        }
        if (now < issuedAt - SKEW_SECONDS) {
            throw VerificationException("Request issued in future: now=$now issued=$issuedAt")
        }

        // Step 7: Verify display_digest
        val expectedDigest = computeDisplayDigest(payload)
        val actualDigest = payload.getBytes(18)        // display_digest
        if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
            throw VerificationException("Display digest mismatch")
        }

        // Step 8: Replay check — challenge must be unseen
        val challenge = payload.getBytes(17)           // challenge
        if (ReplayProtector.hasSeen(challenge)) {
            throw VerificationException("Duplicate request — challenge replay detected")
        }
        ReplayProtector.markSeen(challenge, expiresAt)

        // Step 9: Build verified request
        val initiating = payload.getMap(8)
        val resource = payload.getMap(9)
        val resourceDisplay = payload.getMap(10)

        return VerifiedRequest(
            requestId = payload.getString(2),
            tenantId = tenantId,
            tailnetId = payload.getString(4),
            audienceDeviceId = audienceDeviceId,
            initiating = InitiatingInfo(
                srcNodeId = initiating.getString(1),
                srcNodeDisplay = initiating.getString(2),
                srcNodeVerified = initiating.getBool(3),
                requestingIp = initiating.getString(4)
            ),
            resource = ResourceInfo(
                protectedNodeId = resource.getString(2),
                serviceId = resource.getString(3),
                port = resource.getInt(4),
                transport = resource.getString(5),
                deploymentMode = resource.getString(6),
                displayName = resourceDisplay.getString(1)
            ),
            protocol = payload.getString(11),
            sshAccount = payload.getOptionalString(12),
            scope = payload.getString(15),
            policyVersion = payload.getLong(13),
            ruleId = payload.getString(14),
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            challenge = challenge,
            displayDigest = actualDigest,
            binding = parseBinding(payload.getMap(16))
        )
    }

    // ─── Signature Verification ────────────────────────────────────────────

    private fun verifySignature(publicKey: ECPublicKey, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(publicKey)
            sig.update(message)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    // ─── SigStructure Construction ─────────────────────────────────────────

    private fun buildSigStructure(cose: CoseSign1): ByteArray {
        // SigStructure = [ "Signature1", protected, external_aad, payload ]
        val cbor = CborArray()
        cbor.add("Signature1")
        cbor.add(cose.protectedRaw)
        cbor.add(ByteArray(0))  // external_aad = empty for Dnivio
        cbor.add(cose.payload)
        return cbor.encode()
    }

    // ─── Display Digest Computation ────────────────────────────────────────

    private fun computeDisplayDigest(payload: CborMap): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(payload.getString(3).toByteArray())      // tenant_id
        md.update(payload.getString(4).toByteArray())      // tailnet_id
        val init = payload.getMap(8)
        md.update(init.getString(1).toByteArray())          // src_node_id
        md.update(init.getString(2).toByteArray())          // src_node_display
        val res = payload.getMap(9)
        md.update(res.getString(2).toByteArray())           // protected_node_id
        md.update(res.getString(3).toByteArray())           // service_id
        md.update(res.getInt(4).toString().toByteArray())   // port
        md.update(res.getString(5).toByteArray())           // transport
        md.update(res.getString(6).toByteArray())           // deployment_mode
        val display = payload.getMap(10)
        md.update(display.getString(1).toByteArray())       // display_name
        md.update(payload.getString(11).toByteArray())      // protocol
        payload.getOptionalString(12)?.let { md.update(it.toByteArray()) } // ssh_account
        md.update(payload.getLong(13).toString().toByteArray())  // policy_version
        md.update(payload.getString(14).toByteArray())      // rule_id
        md.update(payload.getString(15).toByteArray())      // scope
        md.update(payload.getLong(5).toString().toByteArray())  // issued_at
        md.update(payload.getLong(6).toString().toByteArray())  // expires_at
        return md.digest()
    }

    // ─── Binding Parser ────────────────────────────────────────────────────

    private fun parseBinding(bindingMap: CborMap): BindingInfo {
        return when {
            bindingMap.hasKey(1) -> {  // HTTP_REQUEST
                val hr = bindingMap.getMap(1)
                BindingInfo("http_request", Base64.encodeToString(hr.getBytes(7), Base64.NO_WRAP))
            }
            bindingMap.hasKey(2) -> {  // CONNECTION
                val conn = bindingMap.getMap(2)
                BindingInfo("connection", Base64.encodeToString(conn.getBytes(1), Base64.NO_WRAP))
            }
            bindingMap.hasKey(3) -> {  // SESSION
                val sess = bindingMap.getMap(3)
                BindingInfo("session", Base64.encodeToString(sess.getBytes(1), Base64.NO_WRAP))
            }
            else -> BindingInfo("unknown", "")
        }
    }

    companion object {
        const val ALG_EDDSA = -8
        const val ALG_ES256 = -7
        const val SKEW_SECONDS = 5L
    }
}

class VerificationException(message: String) : Exception(message)
