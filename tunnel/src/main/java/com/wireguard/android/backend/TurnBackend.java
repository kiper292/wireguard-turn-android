/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.net.VpnService;
import androidx.annotation.Nullable;
import android.util.Log;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private static final AtomicReference<CompletableFuture<VpnService>> vpnServiceFutureRef = new AtomicReference<>(new CompletableFuture<>());

    private TurnBackend() {
    }

    /**
     * Registers the VpnService instance and notifies the native layer.
     * @param service The VpnService instance.
     */
    public static void onVpnServiceCreated(@Nullable VpnService service) {
        Log.d("WireGuard/TurnBackend", "onVpnServiceCreated called with service=" + (service != null ? "non-null" : "null"));

        if (service != null) {
            // First, set the service in JNI so sockets can be protected
            wgSetVpnService(service);

            // Atomically get old future and create new one
            CompletableFuture<VpnService> currentFuture = vpnServiceFutureRef.getAndSet(new CompletableFuture<>());
            if (!currentFuture.isDone()) {
                currentFuture.complete(service);
                Log.d("WireGuard/TurnBackend", "VpnService future completed");
            } else {
                // Old future already completed — complete the new one
                CompletableFuture<VpnService> newFuture = vpnServiceFutureRef.get();
                if (!newFuture.isDone()) {
                    newFuture.complete(service);
                    Log.d("WireGuard/TurnBackend", "VpnService future completed (replacement)");
                }
            }
        } else {
            // Service destroyed - reset the future for next cycle
            Log.d("WireGuard/TurnBackend", "VpnService destroyed, resetting future");
            wgSetVpnService(null);
            vpnServiceFutureRef.set(new CompletableFuture<>());
        }
    }

    /**
     * Returns a future that completes when the VpnService is created.
     */
    public static CompletableFuture<VpnService> getVpnServiceFuture() {
        return vpnServiceFutureRef.get();
    }

    public static native void wgSetVpnService(@Nullable VpnService service);

    public static native int wgTurnProxyStart(String peerAddr, String vklink, int n, int useUdp, String listenAddr);
    public static native void wgTurnProxyStop();
    public static native void wgNotifyNetworkChange();
}
