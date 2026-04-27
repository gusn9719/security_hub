package com.example.security_hub

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    companion object {
        private const val METHOD_CHANNEL = "com.security_hub/platform"
        private const val EVENT_CHANNEL  = "com.security_hub/sms_stream"
        private const val SMS_INBOX_URI  = "content://sms/inbox"
    }

    private var pendingSharedText: String? = null
    private var methodChannel: MethodChannel? = null
    private var smsSink: EventChannel.EventSink? = null
    var isInForeground = false

    fun sendSmsEvent(data: Map<String, String>) {
        smsSink?.success(data)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SmsReceiver.mainActivityRef = this
        handleIncomingIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        isInForeground = true
    }

    override fun onPause() {
        super.onPause()
        isInForeground = false
    }

    override fun onDestroy() {
        SmsReceiver.mainActivityRef = null
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
        pendingSharedText?.let {
            methodChannel?.invokeMethod("onSharedText", it)
            pendingSharedText = null
        }
    }

    // INP-02 공유하기 + INP-05 알림 탭 두 경로를 한 곳에서 처리
    private fun handleIncomingIntent(intent: Intent?) {
        when {
            intent?.action == Intent.ACTION_SEND && intent.type == "text/plain" ->
                pendingSharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            intent?.hasExtra(SmsReceiver.EXTRA_SMS_BODY) == true ->
                pendingSharedText = intent.getStringExtra(SmsReceiver.EXTRA_SMS_BODY)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
        methodChannel!!.setMethodCallHandler { call, result ->
            when (call.method) {
                "getSharedText"   -> { result.success(pendingSharedText); pendingSharedText = null }
                "getSmsMessages"  -> result.success(readSmsInbox())
                else              -> result.notImplemented()
            }
        }

        // 앱이 포그라운드일 때 SMS 수신을 Flutter 스트림으로 전달
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) { smsSink = events }
                override fun onCancel(arguments: Any?) { smsSink = null }
            })
    }

    private fun readSmsInbox(): List<Map<String, String>> {
        val messages = mutableListOf<Map<String, String>>()
        val cursor = contentResolver.query(
            Uri.parse(SMS_INBOX_URI),
            arrayOf("_id", "address", "body", "date"),
            null, null,
            "date DESC LIMIT 20"
        ) ?: return messages

        cursor.use {
            val addressIdx = it.getColumnIndex("address")
            val bodyIdx    = it.getColumnIndex("body")
            val dateIdx    = it.getColumnIndex("date")
            while (it.moveToNext()) {
                messages.add(mapOf(
                    "address" to (it.getString(addressIdx) ?: ""),
                    "body"    to (it.getString(bodyIdx)    ?: ""),
                    "date"    to (it.getLong(dateIdx).toString())
                ))
            }
        }
        return messages
    }
}
