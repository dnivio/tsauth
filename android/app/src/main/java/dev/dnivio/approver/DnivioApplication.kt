package dev.dnivio.approver

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import dev.dnivio.approver.key.KeyManager
import dev.dnivio.approver.crypto.RequestVerifier
import dev.dnivio.approver.messaging.ApprovalClient

/**
 * Application entry point for the Dnivio Approver.
 * Initializes key infrastructure, notification channels, and background services.
 */
class DnivioApplication : Application() {

    lateinit var keyManager: KeyManager
        private set
    lateinit var requestVerifier: RequestVerifier
        private set
    lateinit var approvalClient: ApprovalClient
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        createNotificationChannels()
        initializeKeyInfrastructure()
        initializeNetworkClient()
    }

    private fun createNotificationChannels() {
        val manager = getSystemService(NotificationManager::class.java)

        // High-priority channel for approval requests
        val approvalChannel = NotificationChannel(
            CHANNEL_APPROVAL,
            getString(R.string.channel_approval_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = getString(R.string.channel_approval_desc)
            setShowBadge(true)
            enableVibration(true)
            enableLights(true)
        }

        // Low-priority channel for status updates
        val statusChannel = NotificationChannel(
            CHANNEL_STATUS,
            getString(R.string.channel_status_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.channel_status_desc)
            setShowBadge(false)
        }

        manager.createNotificationChannel(approvalChannel)
        manager.createNotificationChannel(statusChannel)
    }

    private fun initializeKeyInfrastructure() {
        keyManager = KeyManager(this)
        requestVerifier = RequestVerifier(keyManager)
    }

    private fun initializeNetworkClient() {
        approvalClient = ApprovalClient(this, requestVerifier, keyManager)
    }

    companion object {
        const val CHANNEL_APPROVAL = "dnivio_approval"
        const val CHANNEL_STATUS = "dnivio_status"

        lateinit var instance: DnivioApplication
            private set
    }
}
