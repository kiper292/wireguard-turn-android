/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.databinding.TurnLogFragmentBinding
import kotlinx.coroutines.launch

class TurnLogFragment : BaseFragment() {
    private var binding: TurnLogFragmentBinding? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        binding = TurnLogFragmentBinding.inflate(inflater, container, false)
        binding?.executePendingBindings()
        return binding?.root
    }

    override fun onDestroyView() {
        binding = null
        super.onDestroyView()
    }

    override fun onViewStateRestored(savedInstanceState: Bundle?) {
        binding ?: return
        binding!!.fragment = this
        binding!!.tunnel = selectedTunnel
        updateLog()
        super.onViewStateRestored(savedInstanceState)
    }

    override fun onSelectedTunnelChanged(oldTunnel: com.wireguard.android.model.ObservableTunnel?, newTunnel: com.wireguard.android.model.ObservableTunnel?) {
        binding?.tunnel = newTunnel
        updateLog()
    }

    fun onClearLogClicked(@Suppress("UNUSED_PARAMETER") view: View) {
        val tunnelName = binding?.tunnel?.name ?: return
        Application.getTurnProxyManager().clearLog(tunnelName)
        updateLog()
    }

    private fun updateLog() {
        val tunnelName = binding?.tunnel?.name ?: return
        val binding = binding ?: return
        lifecycleScope.launch {
            val log = Application.getTurnProxyManager().getLog(tunnelName)
            binding.logText.text = log
        }
    }
}

