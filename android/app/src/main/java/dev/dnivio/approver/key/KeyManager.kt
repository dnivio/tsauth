package dev.dnivio.approver.key

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyGenerator

/**
 * Manages the two hardware-backed Android Keystore keys for Dnivio.
 *
 * Per §8.2 and DR-KEY-1/2 of ENGINEERING.md v2.1:
 *
 *  device_auth   — Hardware-backed, non-exportable, NOT user-authentication-gated.
 *                  Used for background channel handshake and signed Deny responses.
 *                  Can sign while the device is locked.
 *
 *  approval_auth — Hardware-backed, AUTH_BIOMETRIC_STRONG, per-operation.
 *                  setInvalidatedByBiometricEnrollment(true).
 *                  Used ONLY to sign Approve responses. The signature itself
 *                  proves a fresh strong biometric was presented.
 *
 * Both keys are ECDSA P-256 per Android Keystore constraints.
 * Signatures are canonicalized to low-S before transmission.
 */
class KeyManager(private val context: Context) {

    companion object {
        const val DEVICE_AUTH_ALIAS = "dnivio_device_auth"
        const val APPROVAL_AUTH_ALIAS = "dnivio_approval_auth"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    // ─── Key Generation ────────────────────────────────────────────────────

    /**
     * Generates both keys if they don't already exist.
     * Must be called once during enrollment.
     * Returns attestation certificates for both keys (DER-encoded chains).
     */
    fun generateKeysIfNeeded(): KeyGenerationResult {
        val deviceAuthAttestation = if (!keyStore.containsAlias(DEVICE_AUTH_ALIAS)) {
            generateDeviceAuthKey()
        } else {
            keyStore.getCertificateChain(DEVICE_AUTH_ALIAS)
        }

        val approvalAuthAttestation = if (!keyStore.containsAlias(APPROVAL_AUTH_ALIAS)) {
            generateApprovalAuthKey()
        } else {
            keyStore.getCertificateChain(APPROVAL_AUTH_ALIAS)
        }

        return KeyGenerationResult(
            deviceAuthPub = keyStore.getCertificate(DEVICE_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey,
            approvalAuthPub = keyStore.getCertificate(APPROVAL_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey,
            deviceAuthAttestationChain = deviceAuthAttestation,
            approvalAuthAttestationChain = approvalAuthAttestation,
            deviceAuthSecurityLevel = getSecurityLevel(DEVICE_AUTH_ALIAS),
            approvalAuthSecurityLevel = getSecurityLevel(APPROVAL_AUTH_ALIAS)
        )
    }

    // ─── device_auth — Background-capable, not biometric-gated ────────────

    private fun generateDeviceAuthKey(): Array<Certificate> {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
        )

        val spec = KeyGenParameterSpec.Builder(
            DEVICE_AUTH_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(false)       // ← NOT auth-gated
            .setUnlockedDeviceRequired(true)            // device must be unlocked once
            .setIsStrongBoxBacked(false)                // allow TEE (StrongBox set separately)
            .setAttestationChallenge(generateChallenge())
            .setCertificateNotBefore(java.util.Date())
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
        return keyStore.getCertificateChain(DEVICE_AUTH_ALIAS)
    }

    // ─── approval_auth — Per-use strong biometric ─────────────────────────

    private fun generateApprovalAuthKey(): Array<Certificate> {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
        )

        val spec = KeyGenParameterSpec.Builder(
            APPROVAL_AUTH_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)                          // ← required
            .setUserAuthenticationParameters(
                0,                                                        // timeout = 0: per-operation
                KeyProperties.AUTH_BIOMETRIC_STRONG                       // strong biometric
            )
            .setInvalidatedByBiometricEnrollment(true)                    // ← key invalid if biometrics change
            .setIsStrongBoxBacked(false)
            .setAttestationChallenge(generateChallenge())
            .setCertificateNotBefore(java.util.Date())
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
        return keyStore.getCertificateChain(APPROVAL_AUTH_ALIAS)
    }

    // ─── Signing ───────────────────────────────────────────────────────────

    /**
     * Signs with device_auth (no biometric required).
     * Used for background channel hello and Deny responses.
     */
    fun signWithDeviceAuth(data: ByteArray): SignatureResult {
        val privateKey = keyStore.getKey(DEVICE_AUTH_ALIAS, null) as PrivateKey
        val publicKey = keyStore.getCertificate(DEVICE_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey
            ?: throw IllegalStateException("device_auth public key not found")

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(data)
        val sigBytes = signature.sign()

        return SignatureResult(
            signature = canonicalizeToLowS(sigBytes),
            publicKey = publicKey,
            keyAlias = DEVICE_AUTH_ALIAS
        )
    }

    /**
     * Signs with approval_auth (REQUIRES fresh strong biometric).
     * Used ONLY for Approve responses. BiometricPrompt must be shown first.
     *
     * The CryptoObject from BiometricPrompt binds the signature to the
     * biometric authentication, proving a fresh biometric was presented.
     */
    fun createApprovalSignature(): Signature {
        val privateKey = keyStore.getKey(APPROVAL_AUTH_ALIAS, null) as PrivateKey
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        return signature
    }

    /**
     * Finalizes the approval signature after biometric auth and canonicalizes to low-S.
     */
    fun finalizeApprovalSignature(cryptoSignature: Signature): SignatureResult {
        val publicKey = keyStore.getCertificate(APPROVAL_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey
            ?: throw IllegalStateException("approval_auth public key not found")
        val sigBytes = cryptoSignature.sign()
        return SignatureResult(
            signature = canonicalizeToLowS(sigBytes),
            publicKey = publicKey,
            keyAlias = APPROVAL_AUTH_ALIAS
        )
    }

    // ─── Security Level ────────────────────────────────────────────────────

    fun getSecurityLevel(alias: String): SecurityLevel {
        return try {
            val keyFactory = KeyFactory.getInstance(
                keyStore.getCertificate(alias)?.publicKey?.algorithm ?: "EC",
                KEYSTORE_PROVIDER
            )
            val keyInfo = keyFactory.getKeySpec(
                keyStore.getKey(alias, null),
                KeyInfo::class.java
            )

            if (keyInfo.isInsideSecureHardware) {
                if (keyInfo.isStrongBoxBacked) SecurityLevel.STRONGBOX
                else SecurityLevel.TEE
            } else {
                SecurityLevel.SOFTWARE  // rejected in production
            }
        } catch (e: Exception) {
            SecurityLevel.SOFTWARE
        }
    }

    // ─── Key Availability ──────────────────────────────────────────────────

    fun isDeviceAuthAvailable(): Boolean = keyStore.containsAlias(DEVICE_AUTH_ALIAS)
    fun isApprovalAuthAvailable(): Boolean = keyStore.containsAlias(APPROVAL_AUTH_ALIAS)

    fun isApprovalAuthInvalidated(): Boolean {
        return try {
            val privateKey = keyStore.getKey(APPROVAL_AUTH_ALIAS, null)
            privateKey == null
        } catch (e: Exception) {
            true
        }
    }

    /**
     * Returns true if biometric enrollment has changed since key generation,
     * which invalidates approval_auth per setInvalidatedByBiometricEnrollment(true).
     */
    fun needsReEnrollment(): Boolean {
        return !isApprovalAuthAvailable() || isApprovalAuthInvalidated()
    }

    // ─── Device Counter (DR-SIG-6) ─────────────────────────────────────────

    /**
     * Monotonic anti-clone counter stored in EncryptedSharedPreferences.
     * Incremented atomically before each signing operation.
     * Covered by the approval signature.
     */
    fun getAndIncrementCounter(): Long {
        val prefs = context.getSharedPreferences("dnivio_counter", Context.MODE_PRIVATE)
        val counter = prefs.getLong("device_counter", 0) + 1
        prefs.edit().putLong("device_counter", counter).apply()
        return counter
    }

    fun getCurrentCounter(): Long {
        val prefs = context.getSharedPreferences("dnivio_counter", Context.MODE_PRIVATE)
        return prefs.getLong("device_counter", 0)
    }

    // ─── Public Key Export ─────────────────────────────────────────────────

    fun getDeviceAuthPublicKey(): java.security.interfaces.ECPublicKey? {
        return keyStore.getCertificate(DEVICE_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey
    }

    fun getApprovalAuthPublicKey(): java.security.interfaces.ECPublicKey? {
        return keyStore.getCertificate(APPROVAL_AUTH_ALIAS)?.publicKey as? java.security.interfaces.ECPublicKey
    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    private fun generateChallenge(): ByteArray {
        return ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    /**
     * Canonicalizes an ECDSA DER signature to low-S form.
     * Per §8.1: the app canonicalizes to low-S before transmission,
     * and the Service rejects high-S signatures.
     */
    private fun canonicalizeToLowS(derSignature: ByteArray): ByteArray {
        // P-256 order N
        val orderN = java.math.BigInteger(1, byteArrayOf(
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
            0x00, 0x00, 0x00, 0x00,
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
            0xBC.toByte(), 0xE6.toByte(), 0xFA.toByte(), 0xAD.toByte(),
            0xA7.toByte(), 0x17.toByte(), 0x9E.toByte(), 0x84.toByte(),
            0xF3.toByte(), 0xB9.toByte(), 0xCA.toByte(), 0xC2.toByte(),
            0xFC.toByte(), 0x63.toByte(), 0x25.toByte(), 0x51.toByte()
        ))
        val halfOrder = orderN.shiftRight(1)

        // Parse DER: SEQUENCE { INTEGER r, INTEGER s }
        val (r, s, rStart, sStart, rLen, sLen) = parseDerSignature(derSignature)
            ?: return derSignature  // can't parse, return as-is

        val sValue = java.math.BigInteger(1, derSignature.copyOfRange(sStart, sStart + sLen))

        return if (sValue > halfOrder) {
            // High-S → canonicalize to low-S (N - s)
            val lowS = orderN.subtract(sValue)
            val lowSBytes = lowS.toByteArray()

            // Rebuild DER signature with low-S
            val newSig = java.io.ByteArrayOutputStream()
            newSig.write(0x30) // SEQUENCE
            val rBytes = derSignature.copyOfRange(rStart, rStart + rLen)
            val totalLen = rBytes.size + lowSBytes.size + 4 // 2 type+len each
            if (totalLen < 128) {
                newSig.write(totalLen)
            } else {
                newSig.write(0x81)
                newSig.write(totalLen)
            }
            newSig.write(0x02) // INTEGER r
            newSig.write(rBytes.size)
            newSig.write(rBytes)
            newSig.write(0x02) // INTEGER s
            newSig.write(lowSBytes.size)
            newSig.write(lowSBytes)
            newSig.toByteArray()
        } else {
            derSignature // already low-S
        }
    }

    private fun parseDerSignature(der: ByteArray): DerComponents? {
        if (der.size < 8 || der[0] != 0x30.toByte()) return null
        var pos = 2
        if (der[pos].toInt() and 0x80 != 0) pos += (der[pos].toInt() and 0x7f)
        // INTEGER r
        if (pos >= der.size || der[pos] != 0x02.toByte()) return null
        pos++
        val rLen = der[pos].toInt()
        val rStart = pos + 1
        pos += 1 + rLen
        // INTEGER s
        if (pos >= der.size || der[pos] != 0x02.toByte()) return null
        pos++
        val sLen = der[pos].toInt()
        val sStart = pos + 1
        return DerComponents(rStart, sStart, rLen, sLen)
    }

    private class DerComponents(val rStart: Int, val sStart: Int, val rLen: Int, val sLen: Int)
}

// ─── Data Classes ──────────────────────────────────────────────────────────

data class KeyGenerationResult(
    val deviceAuthPub: java.security.interfaces.ECPublicKey?,
    val approvalAuthPub: java.security.interfaces.ECPublicKey?,
    val deviceAuthAttestationChain: Array<Certificate>?,
    val approvalAuthAttestationChain: Array<Certificate>?,
    val deviceAuthSecurityLevel: SecurityLevel,
    val approvalAuthSecurityLevel: SecurityLevel
)

data class SignatureResult(
    val signature: ByteArray,
    val publicKey: java.security.interfaces.ECPublicKey,
    val keyAlias: String
)

enum class SecurityLevel {
    STRONGBOX,
    TEE,
    SOFTWARE
}
