package dev.dnivio.approver.messaging

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.R
import dev.dnivio.approver.key.KeyManager

/**
 * Background service maintaining the public-HTTPS device Proof-of-Possession channel.
 *
 * Per DR-APP-4 and ADR-017: provides a durable public-HTTPS device-PoP
 * fetch/respond path INDEPENDENT of the Tailscale network.
 * This is the correctness path — the phone does not need to be on the tailnet.
 *
 * The service:
 * 1. Maintains a persistent authenticated session with the Approval Service
 * 2. Polls for pending approval requests
 * 3. Handles VPN conflicts, captive portals, DNS failures, and offline state
 */
class DevicePoPService : Service() {

    private lateinit var wakeLock: PowerManager.WakeLock
    private var running = false

    override fun onCreate() {
        super.onCreate()
        startForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_FETCH) {
            val requestId = intent.getStringExtra("request_id") ?: return START_NOT_STICKY
            fetchAndProcessEnvelope(requestId)
        } else {
            // Start polling loop
            startPolling()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startForeground() {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, dev.dnivio.approver.ui.MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, DnivioApplication.CHANNEL_STATUS)
            .setContentTitle(getString(R.string.service_active_title))
            .setContentText(getString(R.string.service_active_text))
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun startPolling() {
        if (running) return
        running = true

        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "dnivio:device_pop"
        ).apply { acquire(30 * 60 * 1000L) } // 30 min max

        Thread {
            val app = DnivioApplication.instance
            while (running) {
                try {
                    app.approvalClient.pollPendingRequests()
                } catch (e: Exception) {
                    // Connectivity issues — retry after backoff
                    Thread.sleep(5000)
                    continue
                }
                Thread.sleep(15_000) // Poll every 15 seconds
            }
        }.start()
    }

    private fun fetchAndProcessEnvelope(requestId: String) {
        Thread {
            try {
                val app = DnivioApplication.instance
                val envelope = app.approvalClient.fetchEnvelope(requestId)
                if (envelope != null) {
                    app.approvalClient.processEnvelope(envelope)
                }
            } catch (e: Exception) {
                // FCM wake failed — the polling loop will catch it
            }
        }.start()
    }

    override fun onDestroy() {
        running = false
        if (::wakeLock.isInitialized && wakeLock.isHeld) {
            wakeLock.release()
        }
        super.onDestroy()
    }

    companion object {
        const val ACTION_FETCH = "dev.dnivio.approver.FETCH_REQUEST"
        const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            context.startForegroundService(Intent(context, DevicePoPService::class.java))
        }

        fun startFetch(context: Context, requestId: String) {
            val intent = Intent(context, DevicePoPService::class.java).apply {
                action = ACTION_FETCH
                putExtra("request_id", requestId)
            }
            context.startForegroundService(intent)
        }
    }
}
