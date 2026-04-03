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
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const captchaServerAddr = "127.0.0.1:8765"
const maxCaptchaAttempts = 3

// captchaSolution holds the result submitted by the user via the local HTTP captcha server
type captchaSolution struct {
	key string
	err error
}

// solveCaptcha starts a local HTTP server showing the captcha image and waits for the user's solution.
// On desktop platforms (Windows/macOS/Linux) it auto-opens the default browser.
// On Android the APK is expected to handle the CAPTCHA_REQUIRED: stdout signal.
func solveCaptcha(ctx context.Context, captchaImg string, captchaSid string) (string, error) {
	resultCh := make(chan captchaSolution, 1)

	mux := http.NewServeMux()
	var srv *http.Server

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Captcha</title>
<style>
  body { font-family: sans-serif; display: flex; flex-direction: column;
         align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .box { background: white; padding: 32px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.15); text-align: center; }
  img { max-width: 300px; margin: 16px 0; border-radius: 6px; }
  input { font-size: 18px; padding: 8px 14px; border: 2px solid #ccc; border-radius: 6px; width: 220px; }
  button { margin-top: 14px; padding: 10px 28px; font-size: 16px; background: #2787F5; color: white;
           border: none; border-radius: 6px; cursor: pointer; }
  button:hover { background: #1a6ed8; }
</style>
</head>
<body>
  <div class="box">
    <h2>VK Captcha Required</h2>
    <img src="%s" alt="captcha">
    <br>
    <form method="POST" action="/submit">
      <input type="text" name="captcha_key" placeholder="Enter captcha text" autofocus autocomplete="off">
      <br>
      <button type="submit">Submit</button>
    </form>
  </div>
</body>
</html>`, captchaImg)
	})

	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		key := strings.TrimSpace(r.FormValue("captcha_key"))
		if key == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding-top:80px">
<h2>✅ Captcha submitted! You can close this tab.</h2></body></html>`)
		resultCh <- captchaSolution{key: key}
		// Shutdown server gracefully in background after response is sent
		go func() {
			time.Sleep(300 * time.Millisecond)
			srv.Shutdown(context.Background())
		}()
	})

	srv = &http.Server{Addr: captchaServerAddr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			resultCh <- captchaSolution{err: fmt.Errorf("captcha server error: %w", err)}
		}
	}()
	// Give server a moment to start
	time.Sleep(150 * time.Millisecond)

	captchaURL := "http://" + captchaServerAddr
	// Signal to APK / external integrations
	fmt.Printf("CAPTCHA_REQUIRED:%s\n", captchaURL)
	turnLog("[VK Auth] Captcha required. Open %s to solve it (sid=%s)", captchaURL, captchaSid)

	// Auto-open browser on desktop platforms
	switch runtime.GOOS {
	case "windows":
		exec.Command("cmd", "/c", "start", captchaURL).Start()
	case "darwin":
		exec.Command("open", captchaURL).Start()
	case "linux":
		exec.Command("xdg-open", captchaURL).Start()
	}

	select {
	case sol := <-resultCh:
		srv.Shutdown(context.Background())
		if sol.err != nil {
			return "", sol.err
		}
		turnLog("[VK Auth] Captcha solution received")
		return sol.key, nil
	case <-ctx.Done():
		srv.Shutdown(context.Background())
		return "", fmt.Errorf("captcha wait cancelled: %w", ctx.Err())
	}
}

// VKCredentials stores VK API client credentials
type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

// Predefined list of VK credentials (tried in order until success)
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	//{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"}, // VK_MVK_APP_ID
	//{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	//{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	//{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
}

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials cache for a single stream
type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
	minRequestInterval = 1 * time.Second // Minimum interval between VK API requests
)

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

// credentialsStore manages per-stream credentials caches
var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// getStreamCache returns or creates a cache for the given stream ID
func getStreamCache(streamID int) *StreamCredentialsCache {
	// Try read lock first for fast path
	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[streamID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	// Need to create new cache
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = credentialsStore.caches[streamID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[streamID] = cache
	return cache
}

// isAuthError checks if the error is an authentication error
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

// handleAuthError handles authentication errors for a specific stream.
// Returns true if cache was invalidated, false otherwise.
func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)

	now := time.Now().Unix()

	// Reset counter if enough time has passed
	if now - cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	turnLog("[STREAM %d] Auth error (count=%d/%d)", streamID, count, maxCacheErrors)

	// Invalidate cache only after N errors within the time window
	if count >= maxCacheErrors {
		turnLog("[VK Auth] Multiple auth errors detected (%d), invalidating cache for stream %d...", count, streamID)
		cache.invalidate(streamID)
		return true
	}

	return false
}

// invalidate invalidates the credentials cache for this stream
func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	// Reset auth error counter
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	turnLog("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

// invalidateAllCaches invalidates all per-stream caches (called on network change)
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	for streamID, cache := range credentialsStore.caches {
		cache.invalidate(streamID)
	}

	// Clear the map to free memory
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[VK Auth] All per-stream caches cleared")
}

// getVkCreds fetches TURN credentials from VK/OK API with per-stream caching
func getVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	cache := getStreamCache(streamID)

	// Check cache with read lock first (fast path)
	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		cache.mutex.RUnlock()
		turnLog("[STREAM %d] [VK Auth] Using cached credentials (expires in %v)", streamID, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}
	cache.mutex.RUnlock()

	turnLog("[STREAM %d] [VK Auth] Cache miss, starting credential fetch...", streamID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with rate limiting
	user, pass, addr, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		return "", "", "", err
	}

	// Store in cache
	cache.mutex.Lock()
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}
	cache.mutex.Unlock()

	turnLog("[STREAM %d] [VK Auth] Success! Credentials cached until %v", streamID, cache.creds.ExpiresAt)
	return user, pass, addr, nil
}

// fetchVkCredsSerialized wraps fetchVkCreds with rate limiting to avoid VK flood control
func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (string, string, string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	user, pass, addr, err := fetchVkCreds(ctx, link, streamID)
	//time.Sleep(minRequestInterval)
	return user, pass, addr, err
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	var lastErr error

	// Try each credentials pair until success
	for _, creds := range vkCredentialsList {
		turnLog("[STREAM %d] [VK Auth] Trying credentials: client_id=%s", streamID, creds.ClientID)

		user, pass, addr, err := getTokenChain(ctx, link, streamID, creds)
		time.Sleep(minRequestInterval)

		if err == nil {
			turnLog("[STREAM %d] [VK Auth] Success with client_id=%s", streamID, creds.ClientID)
			return user, pass, addr, nil
		}

		lastErr = err
		turnLog("[STREAM %d] [VK Auth] Failed with client_id=%s: %v", streamID, creds.ClientID, err)

		// Check if it's a rate limit error - wait and try next credentials
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "Rate limit") {
			turnLog("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}
	}

	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// getTokenChain performs the VK/OK API token chain with given credentials
func getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials) (string, string, string, error) {
	//var token1, token2, token3, token4, token5 string

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
		// Set headers like real VK Web Chrome browser (matching HAR capture)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("sec-ch-ua-platform", "\"Linux\"")
		req.Header.Set("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"")
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("DNT", "1")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-GPC", "1")

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
					ServerName: domain, // Use domain for certificate verification
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


/*
    // token 1
	data := fmt.Sprintf("client_secret=%s&client_id=%s&scopes=audio_anonymous%%2Cvideo_anonymous%%2Cphotos_anonymous%%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=5.247&app_id=%s", creds.ClientSecret, creds.ClientID, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 1 request failed: %v, response: %v", streamID, err, resp)
		return "", "", "", err
	}
	turnLog("[STREAM %d] [VK Auth] Token 1 response: %v", streamID, resp)
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok || dataMap == nil {
		turnLog("[STREAM %d] [VK Auth] Invalid data structure in response", streamID)
		return "", "", "", fmt.Errorf("invalid response structure for token1: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] access_token not found in data: %v", streamID, dataMap)
		return "", "", "", fmt.Errorf("token1 not found in response: %v", resp)
	}
	turnLog("[STREAM %d] [VK Auth] Token 1 (anonym_token) received", streamID)

    // token 2
	data = fmt.Sprintf("access_token=%s", token1)
	resp, err = doRequest(data, fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=%s", creds.ClientID))
	if err != nil { return "", "", "", err }
	responseMap := resp["response"].(map[string]interface{})
	if responseMap == nil { return "", "", "", fmt.Errorf("invalid response structure for token2: %v", resp) }
	token2, ok := responseMap["payload"].(string)
	if !ok { return "", "", "", fmt.Errorf("token2 not found in response: %v", resp) }
	turnLog("[STREAM %d] [VK Auth] Token 2 (payload) received", streamID)
*/
    // token 3
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 3 request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for VK API error in response
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		turnLog("[STREAM %d] [VK Auth] Token 3 VK API error: %v", streamID, errMsg)
		return "", "", "", fmt.Errorf("VK API error (token3): %v", errMsg)
	}
	dataRaw, ok := resp["data"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 3: 'data' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("invalid response structure for token3: 'data' not found")
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok || dataMap == nil {
		turnLog("[STREAM %d] [VK Auth] Token 3: invalid data type: %T", streamID, dataRaw)
		return "", "", "", fmt.Errorf("invalid response structure for token3: %v", resp)
	}
	token3Raw, ok := dataMap["access_token"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 3: 'access_token' field not found in data: %v", streamID, dataMap)
		return "", "", "", fmt.Errorf("token3 not found in response: %v", resp)
	}
	token3, ok := token3Raw.(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 3: 'access_token' is not a string: %T", streamID, token3Raw)
		return "", "", "", fmt.Errorf("token3 is not a string: %v", token3Raw)
	}
	turnLog("[STREAM %d] [VK Auth] Token 3 (anonym_token) received", streamID)

    // getCallPreview - emulate browser behavior (HAR entry 129)
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", url.QueryEscape(link), token3)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.274&client_id="+creds.ClientID)
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] getCallPreview request failed: %v", streamID, err)
	} else {
	    turnLog("[STREAM %d] [VK Auth] getCallPreview completed (optional)", streamID)
    }

    // token 4 — with captcha retry support (error_code 14)
	var token4 string
	{
		var captchaSid, captchaKey string
		for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
			t4Data := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=123&access_token=%s", url.QueryEscape(link), token3)
			if captchaSid != "" && captchaKey != "" {
				t4Data += fmt.Sprintf("&captcha_sid=%s&captcha_key=%s", url.QueryEscape(captchaSid), url.QueryEscape(captchaKey))
				turnLog("[STREAM %d] [VK Auth] Token 4 retry with captcha (attempt %d/%d)", streamID, attempt, maxCaptchaAttempts)
			}
			urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=%s", creds.ClientID)
			resp, err = doRequest(t4Data, urlAddr)
			if err != nil {
				turnLog("[STREAM %d] [VK Auth] Token 4 request failed: %v", streamID, err)
				return "", "", "", err
			}

			// Detect captcha challenge (error_code 14)
			if errMap, ok := resp["error"].(map[string]interface{}); ok {
				errCode, _ := errMap["error_code"].(float64)
				if errCode == 14 {
					if attempt >= maxCaptchaAttempts {
						return "", "", "", fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
					}
					sid, _ := errMap["captcha_sid"].(string)
					img, _ := errMap["captcha_img"].(string)
					if sid == "" || img == "" {
						return "", "", "", fmt.Errorf("captcha response missing sid/img: %v", errMap)
					}
					turnLog("[STREAM %d] [VK Auth] Captcha required (sid=%s), attempt %d/%d", streamID, sid, attempt+1, maxCaptchaAttempts)
					key, solveErr := solveCaptcha(ctx, img, sid)
					if solveErr != nil {
						return "", "", "", fmt.Errorf("captcha solve error: %w", solveErr)
					}
					captchaSid = sid
					captchaKey = key
					continue
				}
				turnLog("[STREAM %d] [VK Auth] Token 4 VK API error: %v", streamID, errMap)
				return "", "", "", fmt.Errorf("VK API error (token4): %v", errMap)
			}

			responseRaw, ok := resp["response"]
			if !ok {
				turnLog("[STREAM %d] [VK Auth] Token 4: 'response' field not found in response: %v", streamID, resp)
				return "", "", "", fmt.Errorf("invalid response structure for token4: 'response' not found")
			}
			responseMap, ok := responseRaw.(map[string]interface{})
			if !ok || responseMap == nil {
				turnLog("[STREAM %d] [VK Auth] Token 4: invalid response type: %T", streamID, responseRaw)
				return "", "", "", fmt.Errorf("invalid response structure for token4: %v", resp)
			}
			token4Raw, ok := responseMap["token"]
			if !ok {
				turnLog("[STREAM %d] [VK Auth] Token 4: 'token' field not found in response: %v", streamID, responseMap)
				return "", "", "", fmt.Errorf("token4 not found in response: %v", resp)
			}
			t4, ok := token4Raw.(string)
			if !ok {
				turnLog("[STREAM %d] [VK Auth] Token 4: 'token' is not a string: %T", streamID, token4Raw)
				return "", "", "", fmt.Errorf("token4 is not a string: %v", token4Raw)
			}
			token4 = t4
			break
		}
	}
	turnLog("[STREAM %d] [VK Auth] Token 4 (messages token) received", streamID)

    // token 5 (auth.anonymLogin - independent request, doesn't need token4)
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", url.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Token 5 request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for error in response
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		turnLog("[STREAM %d] [VK Auth] Token 5 API error: %s", streamID, errMsg)
		return "", "", "", fmt.Errorf("Token 5 API error: %s", errMsg)
	}
	token5Raw, ok := resp["session_key"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 5: 'session_key' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("token5 not found in response: %v", resp)
	}
	token5, ok := token5Raw.(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] Token 5: 'session_key' is not a string: %T", streamID, token5Raw)
		return "", "", "", fmt.Errorf("token5 is not a string: %v", token5Raw)
	}
	turnLog("[STREAM %d] [VK Auth] Token 5 (session_key) received", streamID)

    // final 6
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token4, token5)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		turnLog("[STREAM %d] [VK Auth] Final request failed: %v", streamID, err)
		return "", "", "", err
	}
	// Check for error in response
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		turnLog("[STREAM %d] [VK Auth] Final API error: %s", streamID, errMsg)
		return "", "", "", fmt.Errorf("Final API error: %s", errMsg)
	}
	turnLog("[STREAM %d] [VK Auth] TURN credentials received", streamID)

	tsRaw, ok := resp["turn_server"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'turn_server' field not found in response: %v", streamID, resp)
		return "", "", "", fmt.Errorf("turn_server not found in response: %v", resp)
	}
	ts, ok := tsRaw.(map[string]interface{})
	if !ok || ts == nil {
		turnLog("[STREAM %d] [VK Auth] 'turn_server' is not a map: %T", streamID, tsRaw)
		return "", "", "", fmt.Errorf("invalid turn_server type: %v", tsRaw)
	}
	urlsRaw, ok := ts["urls"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'urls' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("urls not found in turn_server: %v", ts)
	}
	urls, ok := urlsRaw.([]interface{})
	if !ok || len(urls) == 0 {
		turnLog("[STREAM %d] [VK Auth] 'urls' is not a valid array: %T", streamID, urlsRaw)
		return "", "", "", fmt.Errorf("invalid urls in turn_server: %v", ts)
	}
	urlStr, ok := urls[0].(string)
	if !ok {
		turnLog("[STREAM %d] [VK Auth] first url is not a string: %T", streamID, urls[0])
		return "", "", "", fmt.Errorf("invalid url type in turn_server: %v", ts)
	}
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urlStr, "?")[0], "turn:"), "turns:")

	// Resolve TURN server address via cascading DNS (if it's a domain)
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		// Check if host is IP address
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[STREAM %d] [TURN DNS] Warning: failed to resolve TURN server %s: %v", streamID, host, err)
				// Don't fail, use original address
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[STREAM %d] [TURN DNS] Resolved TURN server %s -> %s", streamID, host, resolvedIP)
			}
		}
	}

	usernameRaw, ok := ts["username"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'username' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	username, ok := usernameRaw.(string)
	if !ok || username == "" {
		turnLog("[STREAM %d] [VK Auth] 'username' is not a valid string: %T", streamID, usernameRaw)
		return "", "", "", fmt.Errorf("username not found in turn_server: %v", ts)
	}
	credentialRaw, ok := ts["credential"]
	if !ok {
		turnLog("[STREAM %d] [VK Auth] 'credential' field not found in turn_server: %v", streamID, ts)
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}
	credential, ok := credentialRaw.(string)
	if !ok || credential == "" {
		turnLog("[STREAM %d] [VK Auth] 'credential' is not a valid string: %T", streamID, credentialRaw)
		return "", "", "", fmt.Errorf("credential not found in turn_server: %v", ts)
	}
	return username, credential, address, nil
}
