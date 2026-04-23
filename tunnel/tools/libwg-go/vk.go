/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern const char* requestCaptcha(const char* redirect_uri);
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
	"github.com/kiper292/tls-client/profiles"
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

type captchaSolveMode int

const (
	captchaSolveModeAuto captchaSolveMode = iota
	captchaSolveModeSliderPOC
	captchaSolveModeManual
)

func captchaSolveModeForAttempt(attempt int, manualCaptcha bool, enableSliderPOC bool) (captchaSolveMode, bool) {
	switch attempt {
	case 0:
		return captchaSolveModeAuto, true
	case 1:
		if enableSliderPOC {
			return captchaSolveModeSliderPOC, true
		}
	case 2:
		if manualCaptcha {
			return captchaSolveModeManual, true
		}
	}

	return 0, false
}

func captchaSolveModeLabel(mode captchaSolveMode) string {
	switch mode {
	case captchaSolveModeAuto:
		return "auto captcha"
	case captchaSolveModeSliderPOC:
		return "auto captcha slider POC"
	case captchaSolveModeManual:
		return "manual captcha"
	default:
		return "captcha"
	}
}

// vkDelayRandom sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func getCustomNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl,
	}
}

// Custom dial context that resolves domains via DNS cache
func getCustomDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	resolvedIP, err := hostCache.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	dialer := getCustomNetDialer()
	return dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string) (string, string, string, error) {

	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithDialer(getCustomNetDialer()),
		tlsclient.WithDialContext(getCustomDialContext),
	)
	
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create tlsclient: %w", err)
	}
	defer client.CloseIdleConnections()

	profile := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	var lastErr error
	for _, creds := range vkCredentialsList {
		user, pass, addr, err := getTokenChain(ctx, link, creds, client, profile)
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
func getTokenChain(ctx context.Context, link string, creds VKCredentials, client tlsclient.HttpClient, profile Profile) (string, string, string, error) {

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				turnLog("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	// Token 1
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

	// Token 1 -> getCallPreview
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", neturl.QueryEscape(link), token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		turnLog("[VK Auth] getCallPreview request failed: %v", err)
	} else {
		turnLog("[VK Auth] getCallPreview completed (optional)")
	}

	vkDelayRandom(500, 1000)

	// Token 2
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	manualCaptcha := true
	autoCaptchaSliderPOC := true
	streamID := 0
	
	var token2 string
	for attempt := 0; ; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", "", err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				solveMode, hasSolveMode := captchaSolveModeForAttempt(attempt, manualCaptcha, autoCaptchaSliderPOC)
				if !hasSolveMode {
					turnLog("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)

					// Engage global lockout to protect API
					//globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())

					//if connectedStreams.Load() == 0 {
					//	turnLog("[STREAM %d] [FATAL] 0 connected streams and captcha solve modes exhausted.", streamID)
					//	return "", "", "", fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
					//}

					return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				var successToken string
				var captchaKey string
				var solveErr error

				switch solveMode {
				case captchaSolveModeAuto:
					turnLog("[Captcha] Attempt 1. Try auto solving...")
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, false)
						if solveErr != nil {
							turnLog("[STREAM %d] [Captcha] Auto captcha failed: %v", streamID, solveErr)
						}
					} else {
						solveErr = fmt.Errorf("missing fields for auto solve")
					}
				case captchaSolveModeSliderPOC:
					turnLog("[Captcha] Attempt 2. Try slider solving...")
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, true)
						if solveErr != nil {
							turnLog("[STREAM %d] [Captcha] Auto captcha slider POC failed: %v", streamID, solveErr)
						}
					} else {
						solveErr = fmt.Errorf("missing fields for slider POC auto solve")
					}
				case captchaSolveModeManual:
					turnLog("[STREAM %d] [Captcha] Triggering manual captcha fallback...", streamID)
				
					// Step 2: Fall back to WebView
					turnLog("[Captcha] Attempt 3. Web view solving...")
					turnLog("[Captcha] Opening WebView for manual solving...")
					redirectURICStr := C.CString(captchaErr.RedirectURI)
					defer C.free(unsafe.Pointer(redirectURICStr))
				
					cToken := C.requestCaptcha(redirectURICStr)
					if cToken == nil {
						solveErr = fmt.Errorf("WebView captcha solving failed: returned nil token")
					}
					defer C.free(unsafe.Pointer(cToken))
				
					successToken = C.GoString(cToken)
					if successToken == "" {
						solveErr = fmt.Errorf("WebView captcha solving failed: returned empty token")
					} else {
						solveErr = nil;
						turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
					}
				}

				// If solving failed (auto or manual) or timed out
				if solveErr != nil {
					turnLog("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, captchaSolveModeLabel(solveMode), attempt+1, solveErr)

					nextSolveMode, hasNextSolveMode := captchaSolveModeForAttempt(attempt+1, manualCaptcha, autoCaptchaSliderPOC)
					if hasNextSolveMode {
						turnLog("[STREAM %d] [Captcha] Falling back to %s...", streamID, captchaSolveModeLabel(nextSolveMode))
						continue
					}

					// Engage global lockout to protect API
					//globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())

					// If we have 0 streams alive, this is fatal
					//if connectedStreams.Load() == 0 {
					//	turnLog("[STREAM %d] [FATAL] 0 connected streams and manual captcha failed/timed out.", streamID)
					//	return "", "", "", fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS")
					//}

					return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
					captchaErr.CaptchaAttempt = "1"
				}

				if captchaKey != "" {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=%s&captcha_sid=%s&access_token=%s",
						link, escapedName, neturl.QueryEscape(captchaKey), captchaErr.CaptchaSid, token1)
				} else {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				}
				continue
			}
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}
		
		responseRaw, okLoop := resp["response"]
		if !okLoop {
			return "", "", "", fmt.Errorf("invalid response structure for token2: 'response' not found, response: %v", resp)
		}
		
		respMap, okLoop := responseRaw.(map[string]interface{})
		if !okLoop {
			return "", "", "", fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}

		token2Raw, okToken2 := respMap["token"]
		if !okToken2 {
			return "", "", "", fmt.Errorf("token2 not found in response: %v", resp)
		}
		
		token2, okLoop = token2Raw.(string)
		if !okLoop {
			return "", "", "", fmt.Errorf("token2 is not a string: %v", token2Raw)
		}
		
		break
	} // end of for

	turnLog("[VK Auth] Token 2 (messages token) received")
	
	vkDelayRandom(100, 200)

	// Token 3
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
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

	// Token 4 -> TURN Creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", neturl.QueryEscape(link), token2, token3)
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
