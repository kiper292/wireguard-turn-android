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
    var streams: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.streams)
        }

    @get:Bindable
    var useUdp: Boolean = true
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

    private constructor(parcel: Parcel) {
        enabled = parcel.readInt() != 0
        peer = parcel.readString() ?: ""
        vkLink = parcel.readString() ?: ""
        streams = parcel.readString() ?: ""
        useUdp = parcel.readInt() != 0
        localPort = parcel.readString() ?: ""
    }

    constructor()

    constructor(other: TurnSettings?) {
        if (other != null) {
            enabled = other.enabled
            peer = other.peer
            vkLink = other.vkLink
            streams = other.streams.toString()
            useUdp = other.useUdp
            localPort = other.localPort.toString()
        }
    }

    override fun describeContents() = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(if (enabled) 1 else 0)
        dest.writeString(peer)
        dest.writeString(vkLink)
        dest.writeString(streams)
        dest.writeInt(if (useUdp) 1 else 0)
        dest.writeString(localPort)
    }

    @Throws(BadConfigException::class)
    fun resolve(): TurnSettings? {
        if (!enabled) {
            return null
        }

        val parsedStreams = streams.toIntOrNull()
            ?: throw BadConfigException("streams", streams, "Invalid number of streams")
        if (parsedStreams !in 1..16) {
            throw BadConfigException("streams", streams, "Streams must be between 1 and 16")
        }

        val parsedPort = localPort.toIntOrNull() ?: 9000
        if (parsedPort !in 1..65535) {
            throw BadConfigException("local_port", localPort, "Local port must be between 1 and 65535")
        }

        if (peer.isBlank()) {
            throw BadConfigException("peer", peer, "TURN peer must be specified")
        }
        if (!peer.contains(':')) {
            throw BadConfigException("peer", peer, "TURN peer must be in host:port format")
        }
        if (vkLink.isBlank()) {
            throw BadConfigException("vk_link", vkLink, "VK Calls link must be specified")
        }

        val settings = TurnSettings(
            enabled = enabled,
            peer = peer.trim(),
            vkLink = vkLink.trim(),
            streams = parsedStreams,
            useUdp = useUdp,
            localPort = parsedPort,
        )
        TurnSettings.validate(settings)
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

