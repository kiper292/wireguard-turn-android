/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.viewmodel

import android.os.Parcel
import android.os.Parcelable
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.BR
import com.wireguard.android.turn.TurnSettings
import com.wireguard.config.BadConfigException

class TurnSettingsProxy : BaseObservable, Parcelable {
    @get:Bindable
    var enabled: Boolean = false
        set(value) {
            field = value
            notifyPropertyChanged(BR.enabled)
        }

    @get:Bindable
    var peer: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.peer)
        }

    @get:Bindable
    var vkLink: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.vkLink)
        }

    @get:Bindable
    var mode: String = "vk_link"
        set(value) {
            field = value
            notifyPropertyChanged(BR.mode)
        }

    @get:Bindable
    var streams: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.streams)
        }

    @get:Bindable
    var useUdp: Boolean = false
        set(value) {
            field = value
            notifyPropertyChanged(BR.useUdp)
        }

    @get:Bindable
    var localPort: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.localPort)
        }

    @get:Bindable
    var turnIp: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.turnIp)
        }

    @get:Bindable
    var turnPort: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.turnPort)
        }

    @get:Bindable
    var watchdogTimeout: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.watchdogTimeout)
        }

    @get:Bindable
    var peerType: String = "proxy_v2"
        set(value) {
            field = value
            notifyPropertyChanged(BR.peerType)
        }

    @get:Bindable
    var streamsPerCred: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.streamsPerCred)
        }

    @get:Bindable
    var advancedExpanded: Boolean = false
        set(value) {
            field = value
            notifyPropertyChanged(BR.advancedExpanded)
        }

    private constructor(parcel: Parcel) {
        enabled = parcel.readInt() != 0
        peer = parcel.readString() ?: ""
        vkLink = parcel.readString() ?: ""
        mode = parcel.readString() ?: "vk_link"
        streams = parcel.readString() ?: ""
        useUdp = parcel.readInt() != 0
        localPort = parcel.readString() ?: ""
        turnIp = parcel.readString() ?: ""
        turnPort = parcel.readString() ?: ""
        watchdogTimeout = parcel.readString() ?: ""
        peerType = parcel.readString() ?: "proxy_v2"
        streamsPerCred = parcel.readString() ?: ""
        advancedExpanded = parcel.readInt() != 0
    }

    constructor()

    constructor(other: TurnSettings?) {
        if (other != null) {
            enabled = other.enabled
            peer = other.peer
            vkLink = other.vkLink
            mode = other.mode
            streams = other.streams.toString()
            useUdp = other.useUdp
            localPort = other.localPort.toString()
            turnIp = other.turnIp
            turnPort = if (other.turnPort > 0) other.turnPort.toString() else ""
            watchdogTimeout = if (other.watchdogTimeout > 0) other.watchdogTimeout.toString() else ""
            peerType = other.peerType
            streamsPerCred = other.streamsPerCred.toString()
        }
    }

    override fun describeContents() = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(if (enabled) 1 else 0)
        dest.writeString(peer)
        dest.writeString(vkLink)
        dest.writeString(mode)
        dest.writeString(streams)
        dest.writeInt(if (useUdp) 1 else 0)
        dest.writeString(localPort)
        dest.writeString(turnIp)
        dest.writeString(turnPort)
        dest.writeString(watchdogTimeout)
        dest.writeString(peerType)
        dest.writeString(streamsPerCred)
        dest.writeInt(if (advancedExpanded) 1 else 0)
    }

    @Throws(BadConfigException::class)
    fun resolve(): TurnSettings {
        val parsedStreams = streams.toIntOrNull() ?: 4
        val parsedPort = localPort.toIntOrNull() ?: 9000
        val parsedTurnPort = turnPort.toIntOrNull() ?: 0
        val parsedWatchdogTimeout = watchdogTimeout.toIntOrNull() ?: 0
        val parsedStreamsPerCred = streamsPerCred.toIntOrNull() ?: 4

        if (enabled) {
            if (parsedStreams < 1) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.TOP_LEVEL, BadConfigException.Reason.INVALID_VALUE, streams)
            }

            if (parsedPort !in 1..65535) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.LISTEN_PORT, BadConfigException.Reason.INVALID_VALUE, localPort)
            }

            if (turnPort.isNotEmpty() && parsedTurnPort !in 1..65535) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.TOP_LEVEL, BadConfigException.Reason.INVALID_VALUE, turnPort)
            }

            if (watchdogTimeout.isNotEmpty() && parsedWatchdogTimeout > 0 && parsedWatchdogTimeout < 5) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.TOP_LEVEL, BadConfigException.Reason.INVALID_VALUE, watchdogTimeout)
            }

            if (parsedStreamsPerCred < 1) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.TOP_LEVEL, BadConfigException.Reason.INVALID_VALUE, streamsPerCred)
            }

            if (peer.isBlank()) {
                throw BadConfigException(BadConfigException.Section.PEER, BadConfigException.Location.ENDPOINT, BadConfigException.Reason.MISSING_ATTRIBUTE, peer)
            }
            if (!peer.contains(':')) {
                throw BadConfigException(BadConfigException.Section.PEER, BadConfigException.Location.ENDPOINT, BadConfigException.Reason.INVALID_VALUE, peer)
            }
            if (mode != "wb" && vkLink.isBlank()) {
                throw BadConfigException(BadConfigException.Section.INTERFACE, BadConfigException.Location.TOP_LEVEL, BadConfigException.Reason.MISSING_ATTRIBUTE, vkLink)
            }
        }

        val settings = TurnSettings(
            enabled = enabled,
            peer = peer.trim(),
            vkLink = vkLink.trim(),
            mode = mode,
            streams = parsedStreams,
            useUdp = useUdp,
            localPort = parsedPort,
            turnIp = turnIp.trim(),
            turnPort = parsedTurnPort,
            peerType = peerType,
            streamsPerCred = parsedStreamsPerCred,
            watchdogTimeout = parsedWatchdogTimeout,
        )
        if (enabled) {
            TurnSettings.validate(settings)
        }
        return settings
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<TurnSettingsProxy> =
            object : Parcelable.Creator<TurnSettingsProxy> {
                override fun createFromParcel(parcel: Parcel) = TurnSettingsProxy(parcel)
                override fun newArray(size: Int): Array<TurnSettingsProxy?> = arrayOfNulls(size)
            }
    }
}
