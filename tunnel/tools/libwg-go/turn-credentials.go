/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

var (
	credsCache      TurnCredentials
	credsMutex      sync.Mutex
	cacheErrorCount atomic.Int32
	lastErrorTime   atomic.Int64
)

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

// isAuthError checks if the error is an authentication error
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

// handleAuthError handles authentication errors and invalidates cache if needed.
// Returns true if cache was invalidated, false otherwise.
func handleAuthError(streamID int) bool {
	now := time.Now().Unix()

	// Reset counter if enough time has passed
	if now - lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cacheErrorCount.Store(0)
	}

	count := cacheErrorCount.Add(1)
	lastErrorTime.Store(now)

	turnLog("[STREAM %d] Auth error (count=%d/%d)", streamID, count, maxCacheErrors)

	// Invalidate cache only after N errors within the time window
	if count >= maxCacheErrors {
		turnLog("[VK Auth] Multiple auth errors detected (%d), invalidating cache...", count)
		invalidateCredentialsCache()
		return true
	}

	return false
}

// invalidateCredentialsCache invalidates the credentials cache
func invalidateCredentialsCache() {
	credsMutex.Lock()
	credsCache = TurnCredentials{}
	credsMutex.Unlock()

	// Reset auth error counter
	cacheErrorCount.Store(0)
	lastErrorTime.Store(0)

	turnLog("[VK Auth] Credentials cache invalidated")
}

// getVkCreds fetches TURN credentials from VK/OK API with caching
func getVkCreds(ctx context.Context, link string) (string, string, string, error) {
	credsMutex.Lock()
	defer credsMutex.Unlock()

	// Check cache
	if credsCache.Link == link && time.Now().Before(credsCache.ExpiresAt) {
		turnLog("[VK Auth] Using cached credentials (expires in %v)", time.Until(credsCache.ExpiresAt))
		return credsCache.Username, credsCache.Password, credsCache.ServerAddr, nil
	}

	turnLog("[VK Auth] Cache miss, starting credential fetch...")

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	doRequest := func(data string, requestURL string) (resp map[string]interface{}, err error) {
		// Resolve host via DNS cache with cascading fallback
		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}

		// Resolve domain name
		domain := parsedURL.Hostname()
		resolvedIP, err := hostCache.Resolve(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", domain, err)
		}

		// Replace host with IP in URL
		port := parsedURL.Port()
		if port == "" {
			port = "443"
		}
		ipURL := "https://" + resolvedIP + ":" + port + parsedURL.Path
		if parsedURL.RawQuery != "" {
			ipURL += "?" + parsedURL.RawQuery
		}

		// Create request with IP instead of domain
		req, err := http.NewRequestWithContext(ctx, "POST", ipURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		// Set original host for HTTP Host header
		req.Host = domain
		req.Header.Add("User-Agent", "Mozilla/5.0 (Android 12; Mobile; rv:144.0)")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// Create HTTP client with custom TLS config for certificate verification
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					Control:   protectControl,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					ServerName: domain,  // Use domain for certificate verification
				},
			},
		}

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		if errMsg, ok := resp["error"].(map[string]interface{}); ok {
			return resp, fmt.Errorf("VK error: %v", errMsg)
		}
		return resp, nil
	}

	data := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil { return "", "", "", err }
	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	data = fmt.Sprintf("access_token=%s", token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487")
	if err != nil { return "", "", "", err }
	token2 := resp["response"].(map[string]interface{})["payload"].(string)

	data = fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", url.QueryEscape(token2))
	resp, err = doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil { return "", "", "", err }
	token3 := resp["data"].(map[string]interface{})["access_token"].(string)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", url.QueryEscape(link), token3)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil { return "", "", "", err }
	token4 := resp["response"].(map[string]interface{})["token"].(string)

	data = fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New())
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil { return "", "", "", err }
	token5 := resp["session_key"].(string)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token4, token5)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil { return "", "", "", err }

	ts := resp["turn_server"].(map[string]interface{})
	urls := ts["urls"].([]interface{})
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urls[0].(string), "?")[0], "turn:"), "turns:")

	// Resolve TURN server address via cascading DNS (if it's a domain)
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		// Check if host is IP address
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[TURN DNS] Warning: failed to resolve TURN server %s: %v", host, err)
				// Don't fail, use original address
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[TURN DNS] Resolved TURN server %s -> %s", host, resolvedIP)
			}
		}
	}

	// Save to cache
	credsCache = TurnCredentials{
		Username:   ts["username"].(string),
		Password:   ts["credential"].(string),
		ServerAddr: address,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}

	turnLog("[VK Auth] Success! Credentials cached until %v", credsCache.ExpiresAt)
	return ts["username"].(string), ts["credential"].(string), address, nil
}
