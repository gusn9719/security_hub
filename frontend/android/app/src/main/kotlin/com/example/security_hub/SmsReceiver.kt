package com.example.security_hub

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class SmsReceiver : BroadcastReceiver() {

    companion object {
        const val EXTRA_SMS_BODY  = "extra_sms_body"
        const val CHANNEL_ID      = "sms_phishing_alert"
        private const val NOTIFICATION_ID = 2001

        private val urlPattern = Regex("""https?://[^\s\[\]()<>"']+|www\.[^\s\[\]()<>"'.]+\.[a-zA-Z]{2,}""")

        var mainActivityRef: MainActivity? = null
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null) return
        if (intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        for (sms in messages) {
            val address = sms.originatingAddress ?: ""
            val body    = sms.messageBody ?: ""

            if (!urlPattern.containsMatchIn(body)) continue  // URL 없는 문자 무시

            if (mainActivityRef?.isInForeground == true) {
                // 포그라운드: EventChannel로 Flutter에 직접 전달
                mainActivityRef?.sendSmsEvent(mapOf("address" to address, "body" to body))
            } else {
                // 백그라운드/종료: 시스템 알림 표시
                showNotification(context, address, body)
            }
        }
    }

    private fun showNotification(context: Context, sender: String, body: String) {
        // 앱이 종료된 상태에서도 동작하도록 채널을 여기서 직접 생성
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SMS 피싱 분석 알림",
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "URL이 포함된 문자 수신 시 피싱 분석 알림" }
            context.getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }

        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_SMS_BODY, body)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("링크가 포함된 문자가 도착했습니다")
            .setContentText("피싱 여부를 확인하시겠습니까?")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("발신: $sender\n\n${body.take(120)}")
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }
}
