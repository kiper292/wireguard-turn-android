/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets

/**
 * Simple JSON-based storage for per-tunnel TURN settings.
 *
 * TURN settings are stored alongside the .conf files used by [com.wireguard.android.configStore.FileConfigStore],
 * using file names of the form "<tunnel>.turn.json".
 */
class TurnSettingsStore(private val context: Context) {
    private fun fileFor(name: String): File {
        return File(context.filesDir, "$name.turn.json")
    }

    fun load(name: String): TurnSettings? {
        val file = fileFor(name)
        if (!file.isFile) return null
        return try {
            FileInputStream(file).use { stream ->
                val bytes = stream.readBytes()
                val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
                TurnSettings(
                    enabled = json.optBoolean("enabled", false),
                    peer = json.optString("peer", ""),
                    vkLink = json.optString("vkLink", ""),
                    streams = json.optInt("streams", 4),
                    useUdp = json.optBoolean("useUdp", true),
                    localPort = json.optInt("localPort", 9000),
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to load TURN settings for tunnel $name", t)
            null
        }
    }

    fun save(name: String, settings: TurnSettings?) {
        val file = fileFor(name)
        if (settings == null || !settings.enabled) {
            if (file.isFile && !file.delete()) {
                Log.w(TAG, "Failed to delete TURN settings file for $name")
            }
            return
        }

        val validated = try {
            TurnSettings.validate(settings)
        } catch (iae: IllegalArgumentException) {
            Log.e(TAG, "Refusing to save invalid TURN settings for tunnel $name: ${iae.message}")
            return
        }

        val json = JSONObject()
            .put("enabled", validated.enabled)
            .put("peer", validated.peer)
            .put("vkLink", validated.vkLink)
            .put("streams", validated.streams)
            .put("useUdp", validated.useUdp)
            .put("localPort", validated.localPort)

        file.parentFile?.mkdirs()
        FileOutputStream(file, false).use { stream ->
            stream.write(json.toString().toByteArray(StandardCharsets.UTF_8))
        }
    }

    fun delete(name: String) {
        val file = fileFor(name)
        if (file.isFile && !file.delete()) {
            Log.w(TAG, "Failed to delete TURN settings file for $name")
        }
    }

    fun rename(name: String, replacement: String) {
        val file = fileFor(name)
        if (!file.isFile) return
        val replacementFile = fileFor(replacement)
        if (replacementFile.isFile && !replacementFile.delete()) {
            Log.w(TAG, "Failed to delete existing TURN settings for $replacement")
        }
        if (!file.renameTo(replacementFile)) {
            Log.w(TAG, "Failed to rename TURN settings from $name to $replacement")
        }
    }

    companion object {
        private const val TAG = "WireGuard/TurnSettingsStore"
    }
}

