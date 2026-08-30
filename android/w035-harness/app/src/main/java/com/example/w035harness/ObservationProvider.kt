package com.example.w035harness

import android.app.ActivityManager
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import androidx.lifecycle.ProcessLifecycleOwner
import org.json.JSONObject
import java.time.Instant
import java.time.format.DateTimeFormatter

object ObservationProvider {

    fun getSnapshot(context: Context): JSONObject {
        val json = JSONObject()
        json.put("timestamp", DateTimeFormatter.ISO_INSTANT.format(Instant.now()))

        // 1. Lifecycle (app_phase)
        val isForeground = ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)
        json.put("app_phase", if (isForeground) "foreground" else "background")

        // 2. Power & Display
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
            context.registerReceiver(null, filter)
        }
        val status = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                status == BatteryManager.BATTERY_STATUS_FULL

        json.put("power_state", if (isCharging) "charging" else "on-battery")
        json.put("screen_on", powerManager.isInteractive)

        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        json.put("locked", keyguardManager.isKeyguardLocked)

        // 3. Connectivity
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val capabilities = cm.getNetworkCapabilities(activeNetwork)

        val networkKind = when {
            capabilities == null -> "none"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> "none"
        }
        json.put("network_kind", networkKind)
        json.put("metered", cm.isActiveNetworkMetered)

        // 4. Background Restrictions
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val isRestricted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            am.isBackgroundRestricted
        } else {
            false
        }
        val isPowerSave = powerManager.isPowerSaveMode

        json.put("background_restricted", isRestricted || isPowerSave)

        return json
    }
}
