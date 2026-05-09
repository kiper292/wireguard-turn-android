/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import java.util.Locale

/**
 * Per-tunnel TURN proxy configuration.
 */
data class TurnSettings(
    val enabled: Boolean = false,
    val peer: String = "",
    val vkLink: String = "",
    val mode: String = "vk_link",
    val streams: Int = 4,
    val useUdp: Boolean = false,
    val localPort: Int = 9000,
    val turnIp: String = "",
    val turnPort: Int = 0,
    val peerType: String = "proxy_v2",  // "turncoat_v3", "proxy_v2", "proxy_v1", "wireguard"
    val streamsPerCred: Int = 4,
    val watchdogTimeout: Int = 0,
    val wrapKey: String = "",
) {
    fun toComments(): List<String> {
        val lines = mutableListOf(
            "",
            "# [Peer] TURN extensions",
            "#@wgt:EnableTURN = $enabled",
            "#@wgt:UseUDP = $useUdp",
            "#@wgt:IPPort = $peer",
            "#@wgt:VKLink = $vkLink",
            "#@wgt:Mode = $mode",
            "#@wgt:StreamNum = $streams",
            "#@wgt:LocalPort = $localPort",
            "#@wgt:PeerType = $peerType",
            "#@wgt:StreamsPerCred = $streamsPerCred"
        )
        if (turnIp.isNotBlank()) lines.add("#@wgt:TurnIP = $turnIp")
        if (turnPort > 0) lines.add("#@wgt:TurnPort = $turnPort")
        if (watchdogTimeout > 0) lines.add("#@wgt:WatchdogTimeout = $watchdogTimeout")
        if (wrapKey.isNotBlank()) lines.add("#@wgt:WrapKey = $wrapKey")
        return lines
    }

    companion object {
        fun fromComments(comments: List<String>): TurnSettings? {
            var enabled = false
            var peer = ""
            var vkLink = ""
            var mode = "vk_link"
            var streams = 4
            var useUdp = false
            var localPort = 9000
            var turnIp = ""
            var turnPort = 0
            var peerType: String? = null  // null means not set, will be determined from noDtls
            var streamsPerCred = 4
            var watchdogTimeout = 0
            var wrapKey = ""
            var noDtlsLegacy = false
            var foundAny = false

            for (line in comments) {
                if (!line.startsWith("#@wgt:")) continue
                foundAny = true
                val parts = line.substring(6).split("=", limit = 2)
                if (parts.size != 2) continue
                val key = parts[0].trim().lowercase(Locale.ENGLISH)
                val value = parts[1].trim()

                when (key) {
                    "enableturn" -> enabled = value.toBoolean()
                    "useudp" -> useUdp = value.toBoolean()
                    "ipport" -> peer = value
                    "vklink" -> vkLink = value
                    "mode" -> mode = value
                    "streamnum" -> streams = value.toIntOrNull() ?: 4
                    "localport" -> localPort = value.toIntOrNull() ?: 9000
                    "turnip" -> turnIp = value
                    "turnport" -> turnPort = value.toIntOrNull() ?: 0
                    "watchdogtimeout" -> watchdogTimeout = value.toIntOrNull() ?: 0
                    "nodtls" -> noDtlsLegacy = value.toBoolean()  // legacy, for backward compatibility
                    "peertype" -> peerType = value
                    "streamspercred" -> streamsPerCred = value.toIntOrNull() ?: 4
                    "wrapkey" -> wrapKey = value
                }
            }

            // Backward compatibility: if peerType is not set, derive from legacy noDtls
            if (peerType == null) {
                peerType = if (noDtlsLegacy) "wireguard" else "proxy_v2"
            }

            return if (foundAny) TurnSettings(enabled, peer, vkLink, mode, streams, useUdp, localPort, turnIp, turnPort, peerType, streamsPerCred, watchdogTimeout, wrapKey) else null
        }

        fun validate(settings: TurnSettings): TurnSettings {
            if (!settings.enabled) return settings

            require(settings.peer.isNotBlank()) { "TURN peer is empty" }
            if (settings.mode != "wb") {
                require(settings.vkLink.isNotBlank()) { "VK link is empty" }
            }
            require(settings.streams >= 1) { "Streams must be at least 1" }
            require(settings.localPort in 1..65535) { "Local port must be between 1 and 65535" }
            require(settings.peerType in listOf("turncoat_v3", "proxy_v2", "proxy_v1", "wireguard")) { "Invalid peer type: ${settings.peerType}" }
            require(settings.streamsPerCred >= 1) { "Streams per credentials must be at least 1" }

            if (settings.turnPort != 0) {
                require(settings.turnPort in 1..65535) { "TURN port must be between 1 and 65535" }
            }

            if (settings.watchdogTimeout > 0) {
                require(settings.watchdogTimeout >= 5) { "Watchdog timeout must be at least 5 seconds or 0 to disable" }
            }

            if (settings.wrapKey.isNotBlank()) {
                require(settings.wrapKey.matches(Regex("^[0-9a-fA-F]{64}$"))) { "WRAP key must be 64 hex characters" }
            }

            // Very small sanity check for host:port format; full validation is done later when applying.
            require(':' in settings.peer) { "TURN peer must be in host:port format" }

            return settings
        }
    }
}
