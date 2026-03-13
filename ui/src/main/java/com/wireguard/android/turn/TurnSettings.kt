/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

/**
 * Per-tunnel TURN proxy configuration.
 */
data class TurnSettings(
    val enabled: Boolean = false,
    val peer: String = "",
    val vkLink: String = "",
    val streams: Int = 4,
    val useUdp: Boolean = true,
    val localPort: Int = 9000,
) {
    companion object {
        fun validate(settings: TurnSettings): TurnSettings {
            if (!settings.enabled) return settings

            require(settings.peer.isNotBlank()) { "TURN peer is empty" }
            require(settings.vkLink.isNotBlank()) { "VK link is empty" }
            require(settings.streams in 1..16) { "Streams must be between 1 and 16" }
            require(settings.localPort in 1..65535) { "Local port must be between 1 and 65535" }

            // Very small sanity check for host:port format; full validation is done later when applying.
            require(':' in settings.peer) { "TURN peer must be in host:port format" }

            return settings
        }
    }
}

