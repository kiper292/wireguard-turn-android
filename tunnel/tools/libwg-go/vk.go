/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

// VKCredentials stores VK API client credentials
type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

// Predefined list of VK credentials (tried in order until success)
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
}

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

// vkDelayRandom sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string) (string, string, string, error) {
	customDialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl,
	}

	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithDialer(customDialer),
	)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create tlsclient: %w", err)
	}
	defer client.CloseIdleConnections()

	var lastErr error
	for _, creds := range vkCredentialsList {
		user, pass, addr, err := getTokenChain(ctx, link, creds, client)
		if err == nil {
			return user, pass, addr, nil
		}
		lastErr = err
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "Rate limit") {
			turnLog("[VK Auth] Rate limit detected, trying next credentials...")
		}
	}
	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// getTokenChain performs the VK/OK API token chain with given credentials
func getTokenChain(ctx context.Context, link string, creds VKCredentials, client tlsclient.HttpClient) (string, string, string, error) {

	doRequest := func(data string, requestURL string) (resp map[string]interface{}, err error) {
		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}

		domain := parsedURL.Hostname()
		resolvedIP, err := hostCache.Resolve(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", domain, err)
		}

		port := parsedURL.Port()
		if port == "" {
			port = "443"
		}
		ipURL := "https://" + resolvedIP + ":" + port + parsedURL.Path
		if parsedURL.RawQuery != "" {
			ipURL += "?" + parsedURL.RawQuery
		}

		req, err := fhttp.NewRequestWithContext(ctx, "POST", ipURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		profile := getRandomProfile()
		req.Host = domain
		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
		req.Header.Set("sec-ch-ua", profile.SecChUa)
		req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		req.Header.Set("Priority", "u=1, i")

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

	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		turnLog("[VK Auth] Token 1 request failed: %v", err)
		return "", "", "", err
	}
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		turnLog("[VK Auth] Token 1 VK API error: %v", errMsg)
		return "", "", "", fmt.Errorf("VK API error (token1): %v", errMsg)
	}
	dataRaw, ok := resp["data"]
	if !ok {
		return "", "", "", fmt.Errorf("invalid response structure for token1: 'data' not found")
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok || dataMap == nil {
		return "", "", "", fmt.Errorf("invalid response structure for token1: %v", resp)
	}
	token1Raw, ok := dataMap["access_token"]
	if !ok {
		return "", "", "", fmt.Errorf("token1 not found in response: %v", resp)
	}
	token1, ok := token1Raw.(string)
	if !ok {
		return "", "", "", fmt.Errorf("token1 is not a string: %v", token1Raw)
	}
	turnLog("[VK Auth] Token 1 (anonym_token) received")

	vkDelayRandom(100, 200)

	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", url.QueryEscape(link), token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		turnLog("[VK Auth] getCallPreview request failed: %v", err)
	} else {
		turnLog("[VK Auth] getCallPreview completed (optional)")
	}

	vkDelayRandom(500, 1000)

	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&access_token=%s", url.QueryEscape(link), url.QueryEscape(generateName()), token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)
	resp, err = doRequest(data, urlAddr)
	var successToken string
	var solveErr error

	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		captchaErr := ParseVkCaptchaError(errMsg)
		if captchaErr != nil && captchaErr.IsCaptchaError() {
			turnLog("[VK Auth] Token 2: Captcha detected, solving...")

			// Try tlsclient-based captcha solving first
			solver, err := NewCaptchaTlsClientSolver(client)
			if err == nil {
				defer solver.Close()
				successToken, solveErr = solver.Solve(ctx, captchaErr)
				if solveErr == nil {
					turnLog("[VK Auth] Captcha solved via TLSClient")
				} else {
					turnLog("[VK Auth] TLSClient captcha failed: %v, trying automatic...", solveErr)
				}
			} else {
				turnLog("[VK Auth] Failed to create TLSClient solver: %v", err)
			}

			// Try automatic solution if TLSClient failed
			if successToken == "" {
				successToken, solveErr = solveVkCaptcha(ctx, captchaErr)
				if solveErr != nil {
					return "", "", "", fmt.Errorf("captcha solving failed: %w", solveErr)
				}
			}

			turnLog("[VK Auth] Token 2: Retrying with captcha solution...")
			data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=123"+
				"&captcha_key="+
				"&captcha_sid=%s"+
				"&is_sound_captcha=0"+
				"&success_token=%s"+
				"&captcha_ts=%s"+
				"&captcha_attempt=%s"+
				"&access_token=%s",
				url.QueryEscape(link),
				captchaErr.CaptchaSid,
				successToken,
				captchaErr.CaptchaTs,
				captchaErr.CaptchaAttempt,
				token1)
			resp, err = doRequest(data, urlAddr)
			if err != nil {
				return "", "", "", err
			}
			if errMsg2, ok := resp["error"].(map[string]interface{}); ok {
				return "", "", "", fmt.Errorf("VK API error (token2 retry): %v", errMsg2)
			}
		} else {
			return "", "", "", fmt.Errorf("VK API error (token2): %v", errMsg)
		}
	} else if err != nil {
		return "", "", "", err
	}
	responseRaw, ok := resp["response"]
	if !ok {
		return "", "", "", fmt.Errorf("invalid response structure for token2: 'response' not found")
	}
	responseMap, ok := responseRaw.(map[string]interface{})
	if !ok || responseMap == nil {
		return "", "", "", fmt.Errorf("invalid response structure for token2: %v", resp)
	}
	token2Raw, ok := responseMap["token"]
	if !ok {
		return "", "", "", fmt.Errorf("token2 not found in response: %v", resp)
	}
	token2, ok := token2Raw.(string)
	if !ok {
		return "", "", "", fmt.Errorf("token2 is not a string: %v", token2Raw)
	}
	turnLog("[VK Auth] Token 2 (messages token) received")

	vkDelayRandom(100, 200)

	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", url.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", fmt.Errorf("Token 3 API error: %s", errMsg)
	}
	token3Raw, ok := resp["session_key"]
	if !ok {
		return "", "", "", fmt.Errorf("token3 not found in response: %v", resp)
	}
	token3, ok := token3Raw.(string)
	if !ok {
		return "", "", "", fmt.Errorf("token3 is not a string: %v", token3Raw)
	}
	turnLog("[VK Auth] Token 3 (session_key) received")

	vkDelayRandom(100, 200)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", fmt.Errorf("Token 4 API error: %s", errMsg)
	}
	turnLog("[VK Auth] TURN credentials received")

	tsRaw, ok := resp["turn_server"]
	if !ok {
		return "", "", "", fmt.Errorf("turn_server not found in response: %v", resp)
	}
	ts, ok := tsRaw.(map[string]interface{})
	if !ok || ts == nil {
		return "", "", "", fmt.Errorf("invalid turn_server type: %v", tsRaw)
	}
	urlsRaw, ok := ts["urls"]
	if !ok {
		return "", "", "", fmt.Errorf("urls not found in turn_server: %v", ts)
	}
	urls, ok := urlsRaw.([]interface{})
	if !ok || len(urls) == 0 {
		return "", "", "", fmt.Errorf("invalid urls in turn_server: %v", ts)
	}
	urlStr, ok := urls[0].(string)
	if !ok {
		return "", "", "", fmt.Errorf("invalid url type in turn_server: %v", ts)
	}
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urlStr, "?")[0], "turn:"), "turns:")

	host, port, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip == nil {
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[TURN DNS] Warning: failed to resolve TURN server %s: %v", host, err)
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[TURN DNS] Resolved TURN server %s -> %s", host, resolvedIP)
			}
		}
	}

	usernameRaw, ok := ts["username"]
	if !ok {
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	username, ok := usernameRaw.(string)
	if !ok || username == "" {
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	credentialRaw, ok := ts["credential"]
	if !ok {
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}
	credential, ok := credentialRaw.(string)
	if !ok || credential == "" {
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}

	vkDelayRandom(5000, 5000)

	return username, credential, address, nil
}
