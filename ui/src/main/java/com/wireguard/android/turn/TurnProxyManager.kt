/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.util.Log
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 */
class TurnProxyManager(private val context: Context) {
    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): Boolean =
        withContext(Dispatchers.IO) {
            val instance = instances.getOrPut(tunnelName) { Instance() }
            
            val listenAddr = "127.0.0.1:${settings.localPort}"
            val ret = GoBackend.wgTurnProxyStart(
                settings.peer,
                settings.vkLink,
                settings.streams,
                settings.useUdp,
                listenAddr
            )

            if (ret == 0) {
                instance.running = true
                appendLogLine(
                    tunnelName,
                    "TURN started for tunnel \"$tunnelName\" listening on $listenAddr",
                )
                true
            } else {
                appendLogLine(tunnelName, "Failed to start TURN proxy (error $ret)")
                false
            }
        }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            val instance = instances[tunnelName] ?: return@withContext
            GoBackend.wgTurnProxyStop()
            instance.running = false
            appendLogLine(tunnelName, "TURN stopped for tunnel \"$tunnelName\"")
        }

    fun isRunning(tunnelName: String): Boolean {
        return instances[tunnelName]?.running == true
    }

    fun getLog(tunnelName: String): String {
        return instances[tunnelName]?.log?.toString() ?: ""
    }

    fun clearLog(tunnelName: String) {
        instances[tunnelName]?.log?.apply {
            setLength(0)
        }
    }

    fun appendLogLine(tunnelName: String, line: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val builder = instance.log
        if (builder.isNotEmpty()) {
            builder.append('\n')
        }
        builder.append(line)
        if (builder.length > MAX_LOG_CHARS) {
            val overflow = builder.length - MAX_LOG_CHARS
            try {
                builder.delete(0, overflow)
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to trim TURN log for $tunnelName", e)
            }
        }
    }

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
    }
}

