package dev.dnivio.approver.messaging

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dev.dnivio.approver.DnivioApplication
import dev.dnivio.approver.R
import dev.dnivio.approver.ui.ApprovalActivity

/**
 * Firebase Cloud Messaging receiver.
 *
 * Per ADR-006 and DR-APP-5: FCM is a WAKE HINT only.
 * It carries an opaque request_id; the app fetches the signed request envelope
 * over the authenticated channel or public-HTTPS device-PoP path.
 *
 * FCM delivery does NOT represent guaranteed delivery. The correctness path
 * is the public-HTTPS device-PoP fetch.
 */
class FcmReceiver : FirebaseMessagingService() {

    override fun onMessageReceived(message: RemoteMessage) {
        // FCM delivers a hint — extract the request_id
        val requestId = message.data["request_id"] ?: run {
            // Not a Dnivio message
            return
        }

        // Wake the device and fetch the full signed envelope
        // via public-HTTPS device-PoP or authenticated channel
        val app = DnivioApplication.instance

        // Show a heads-up notification while we fetch
        showNotification(requestId)

        // Trigger background fetch of the signed envelope
        DevicePoPService.startFetch(app, requestId)
    }

    override fun onNewToken(token: String) {
        // Push token rotated — register with the Approval Service
        val app = DnivioApplication.instance
        app.approvalClient.registerPushToken(token)
    }

    private fun showNotification(requestId: String) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            putExtra("request_id", requestId)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this, requestId.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, DnivioApplication.CHANNEL_APPROVAL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.notification_approval_title))
            .setContentText(getString(R.string.notification_approval_text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setFullScreenIntent(pendingIntent, true)
            .build()

        NotificationManagerCompat.from(this).notify(requestId.hashCode(), notification)
    }
}

// ─── Boot Receiver ─────────────────────────────────────────────────────────

class BootReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Re-establish the background authenticated channel
            DevicePoPService.start(context)
        }
    }
}
