package com.example.w035harness

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class HarnessReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "org.adcos.w035.harness.OBSERVE") {
            val snapshot = ObservationProvider.getSnapshot(context)
            Log.i("W035_HARNESS", "OBSERVATION: $snapshot")
        }
    }
}
