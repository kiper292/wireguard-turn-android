/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log
import com.wireguard.android.backend.TurnBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.collectLatest
import java.net.Inet4Address

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * Uses PhysicalNetworkMonitor to track stable internet connections and 
 * triggers restarts when the underlying network or IP changes.
 */
class TurnProxyManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)

    sealed interface TurnStartResult {
        data object Success : TurnStartResult
        data class Failure(val code: Int, val message: String) : TurnStartResult
    }
    
    // State
    private var activeTunnelName: String? = null
    private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false
    
    // Network tracking
    private val networkMonitor = PhysicalNetworkMonitor(context)
    @Volatile private var lastKnownNetwork: Network? = null
    
    init {
        networkMonitor.start()
        
        scope.launch {
            networkMonitor.bestNetwork.collectLatest { network ->
                if (network != null) {
                    handleNetworkChange(network)
                }
            }
        }
    }

    /**
     * Central handler for network changes from PhysicalNetworkMonitor.
     * The monitor already provides debounced stable networks.
     */
    private suspend fun handleNetworkChange(network: Network) {
        if (userInitiatedStop || activeTunnelName == null) return

        // 1. Initial baseline setting
        if (lastKnownNetwork == null) {
            Log.d(TAG, "Setting initial network baseline: $network")
            lastKnownNetwork = network
            return
        }

        // 2. Stability check
        if (lastKnownNetwork == network) {
            Log.d(TAG, "Network state stable for $network")
            return
        }

        // 3. Real change confirmed
        Log.d(TAG, "Network change confirmed: $network. Restarting TURN.")
        lastKnownNetwork = network
        performRestartSequence()
    }

    private suspend fun performRestartSequence() {
        if (userInitiatedStop || activeTunnelName == null) return

        Log.d(TAG, "Stopping TURN proxy for restart...")
        TurnBackend.wgTurnProxyStop()
        
        // Critical: Notify Go backend to clear internal socket states/DNS cache
        Log.d(TAG, "Notifying Go layer of network change...")
        TurnBackend.wgNotifyNetworkChange()
        
        delay(500) // Give Go minimal time to react

        val name = activeTunnelName ?: return
        val settings = activeSettings ?: return

        var attempts = 0
        while (currentCoroutineContext().isActive && !userInitiatedStop) {
            attempts++
            Log.d(TAG, "Starting TURN for $name (Attempt $attempts)")
            
            when (val result = startForTunnelInternal(name, settings)) {
                TurnStartResult.Success -> {
                    Log.d(TAG, "TURN restarted successfully on attempt $attempts")
                    return // Exit loop on success
                }
                is TurnStartResult.Failure -> {
                    Log.w(TAG, "TURN restart attempt $attempts failed: ${result.message}")
                }
            }

            // Exponential backoff logic
            val delayMs = when {
                attempts <= 2 -> 2000L
                attempts <= 5 -> 5000L
                else -> 15000L
            }
            Log.w(TAG, "Restart failed, retrying in ${delayMs}ms...")
            delay(delayMs)
        }
    }

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()
    // Mutex to serialize start/stop operations and prevent race conditions between
    // onTunnelEstablished and handleNetworkChange
    private val operationMutex = kotlinx.coroutines.sync.Mutex()

    /**
     * Called once VpnService is ready and TURN should gate WireGuard startup.
     */
    suspend fun onTunnelEstablished(tunnelName: String, turnSettings: TurnSettings?): TurnStartResult {
        Log.d(TAG, "onTunnelEstablished called for tunnel: $tunnelName")

        // Reset state for new session
        activeTunnelName = tunnelName
        activeSettings = turnSettings
        userInitiatedStop = false
        
        // Initialize network baseline for the new session
        lastKnownNetwork = networkMonitor.currentNetwork
        Log.d(TAG, "Initial network for tunnel session: $lastKnownNetwork")

        if (turnSettings == null || !turnSettings.enabled) {
            Log.d(TAG, "TURN not enabled, skipping")
            return TurnStartResult.Success
        }

        val result = startForTunnelInternal(tunnelName, turnSettings)

        if (result == TurnStartResult.Success) {
            // After initial start, allow network changes to trigger restarts.
            // We delay slightly to ensure we don't catch the immediate network fluctuation caused by VPN itself.
            scope.launch {
                delay(2000)
                Log.d(TAG, "Initialization phase complete, network monitoring active")
            }
        }

        return result
    }

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): TurnStartResult {
        return startForTunnelInternal(tunnelName, settings)
    }
    
    private suspend fun startForTunnelInternal(tunnelName: String, settings: TurnSettings): TurnStartResult =
        withContext(Dispatchers.IO) {
            operationMutex.lock()
            try {
                if (!currentCoroutineContext().isActive) {
                    Log.d(TAG, "startForTunnelInternal cancelled before execution")
                    return@withContext TurnStartResult.Failure(ERROR_START_CANCELLED, "TURN startup cancelled")
                }

                val instance = instances.getOrPut(tunnelName) { Instance() }
                instance.running = false

                Log.d(TAG, "Stopping any existing TURN proxy...")
                TurnBackend.wgTurnProxyStop()
                // Give Go runtime a moment to fully clean up goroutines
                delay(200)

                // Wait for JNI to be registered
                val jniReady = TurnBackend.waitForVpnServiceRegistered(2000)
                if (!jniReady) {
                    Log.e(TAG, "TIMEOUT waiting for JNI registration!")
                    return@withContext TurnStartResult.Failure(
                        ERROR_VPN_SERVICE_NOT_READY,
                        "TURN startup failed: VpnService was not registered in time"
                    )
                }

                // If network is still null, try one quick re-poll from monitor
                if (lastKnownNetwork == null) {
                    lastKnownNetwork = networkMonitor.currentNetwork
                    if (lastKnownNetwork == null) {
                        Log.w(TAG, "Network still null, waiting 500ms for PhysicalNetworkMonitor...")
                        delay(500)
                        lastKnownNetwork = networkMonitor.currentNetwork
                    }
                }

                val networkHandle = lastKnownNetwork?.getNetworkHandle() ?: 0L
                val networkType = getNetworkTypeString(lastKnownNetwork)
                Log.d(TAG, "Starting TURN proxy for $tunnelName with network: $lastKnownNetwork (type=$networkType, handle=$networkHandle)")

                val ret = TurnBackend.wgTurnProxyStart(
                    settings.peer, settings.vkLink, settings.mode, settings.streams,
                    if (settings.useUdp) 1 else 0,
                    "127.0.0.1:${settings.localPort}",
                    settings.turnIp,
                    settings.turnPort,
                    settings.peerType,
                    settings.streamsPerCred,
                    settings.watchdogTimeout,
                    networkHandle
                )

                val listenAddr = "127.0.0.1:${settings.localPort}"
                if (ret == TurnBackend.WG_TURN_PROXY_SUCCESS) {
                    instance.running = true
                    val msg = "TURN started for tunnel \"$tunnelName\" listening on $listenAddr"
                    Log.d(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    TurnStartResult.Success
                } else {
                    val msg = when (ret) {
                        TurnBackend.WG_TURN_PROXY_ERROR_VK_LINK_EXPIRED ->
                            "TURN startup failed: VK call link expired"
                        else -> "Failed to start TURN proxy (error $ret)"
                    }
                    Log.e(TAG, msg)
                    appendLogLine(tunnelName, msg)
                    TurnStartResult.Failure(ret, msg)
                }
            } finally {
                operationMutex.unlock()
            }
        }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            userInitiatedStop = true
            activeTunnelName = null
            activeSettings = null
            lastKnownNetwork = null

            // Stop TURN proxy BEFORE acquiring mutex to avoid deadlock with startup wait
            TurnBackend.wgTurnProxyStop()

            operationMutex.lock()
            try {
                val instance = instances[tunnelName] ?: return@withContext
                instance.running = false
                val msg = "TURN stopped for tunnel \"$tunnelName\""
                Log.d(TAG, msg)
                appendLogLine(tunnelName, msg)
            } finally {
                operationMutex.unlock()
            }
        }

    fun isRunning(tunnelName: String): Boolean {
        return instances[tunnelName]?.running == true
    }

    fun getLog(tunnelName: String): String {
        return instances[tunnelName]?.log?.toString() ?: ""
    }

    fun clearLog(tunnelName: String) {
        instances[tunnelName]?.log?.setLength(0)
    }

    fun appendLogLine(tunnelName: String, line: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val builder = instance.log
        synchronized(builder) {
            if (builder.isNotEmpty()) {
                builder.append('\n')
            }
            builder.append(line)
            if (builder.length > MAX_LOG_CHARS) builder.delete(0, builder.length - MAX_LOG_CHARS)
        }
    }

    /**
     * Returns a string representation of the network type (wifi, cellular, lan, unknown).
     */
    private fun getNetworkTypeString(network: Network?): String {
        if (network == null) return "unknown"

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(network)

        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "lan"
            else -> "unknown"
        }
    }

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
        private const val ERROR_VPN_SERVICE_NOT_READY = -1001
        private const val ERROR_START_CANCELLED = -1002
    }
}
