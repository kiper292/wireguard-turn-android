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
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

// VkCaptchaError represents a VK captcha error
type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectUri             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string // captcha_ts from error
	CaptchaAttempt          string // captcha_attempt from error
}

// ParseVkCaptchaError parses a VK error response into VkCaptchaError
func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	code := int(codeFloat)

	redirectUri, _ := errData["redirect_uri"].(string)
	captchaSid, _ := errData["captcha_sid"].(string)
	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	// Extract session_token from redirect_uri
	var sessionToken string
	if redirectUri != "" {
		if parsed, err := url.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	isSound, _ := errData["is_sound_captcha_available"].(bool)

	// captcha_ts can be float64 (scientific notation) or string
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// captcha_attempt is usually a float64
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectUri:             redirectUri,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

// IsCaptchaError checks if the error data is a Not Robot Captcha error
func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectUri != "" && e.SessionToken != ""
}

// captchaMutex serializes captcha solving to avoid multiple concurrent attempts
var captchaMutex sync.Mutex

// solveVkCaptcha solves the VK Not Robot Captcha and returns success_token
// First tries automatic solution, falls back to WebView if it fails
func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError) (string, error) {
	// Serialize captcha solving to avoid multiple concurrent attempts
	captchaMutex.Lock()
	defer captchaMutex.Unlock()

	turnLog("[Captcha] Solving Not Robot Captcha...")

	// Step 1: Try automatic solution
	turnLog("[Captcha] Attempting automatic solution...")
	successToken, err := solveVkCaptchaAutomatic(ctx, captchaErr)
	if err == nil && successToken != "" {
		turnLog("[Captcha] Automatic solution SUCCESS!")
		return successToken, nil
	}

	turnLog("[Captcha] Automatic solution FAILED: %v", err)
	turnLog("[Captcha] Falling back to WebView...")

	// Step 2: Fall back to WebView
	turnLog("[Captcha] Opening WebView for manual solving...")
	redirectURICStr := C.CString(captchaErr.RedirectUri)
	defer C.free(unsafe.Pointer(redirectURICStr))

	cToken := C.requestCaptcha(redirectURICStr)
	if cToken == nil {
		return "", fmt.Errorf("WebView captcha solving failed: returned nil token")
	}
	defer C.free(unsafe.Pointer(cToken))

	successToken = C.GoString(cToken)
	if successToken == "" {
		return "", fmt.Errorf("WebView captcha solving failed: returned empty token")
	}

	turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
	return successToken, nil
}

// solveVkCaptchaAutomatic performs the automatic captcha solving without UI
func solveVkCaptchaAutomatic(ctx context.Context, captchaErr *VkCaptchaError) (string, error) {
	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput
	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectUri)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[Captcha] PoW input: %s, difficulty: %d", bootstrap.PowInput, bootstrap.Difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	turnLog("[Captcha] PoW solved: hash=%s", hash)

	// Step 3: Call captchaNotRobot API with slider POC support
	successToken, err := callCaptchaNotRobotWithSliderPOC(ctx, sessionToken, hash, 0, nil, Profile{}, bootstrap.Settings)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	turnLog("[Captcha] Success! Got success_token")
	return successToken, nil
}

// fetchCaptchaBootstrap fetches the captcha HTML page and extracts PoW input, difficulty, and settings
func fetchCaptchaBootstrap(ctx context.Context, redirectUri string) (*captchaBootstrap, error) {
	parsedURL, err := url.Parse(redirectUri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect_uri: %w", err)
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

	req, err := http.NewRequestWithContext(ctx, "GET", ipURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = domain
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   protectControl,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				ServerName: domain,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)
	bootstrap, err := parseCaptchaBootstrapHTML(html)
	if err != nil {
		return nil, err
	}

	return bootstrap, nil
}

// solvePoW finds nonce where SHA-256(powInput + nonce) starts with '0' * difficulty
func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)

	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])

		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}

	// Fallback: should not happen with difficulty <= 3
	return ""
}

func generateBrowserFp(profile Profile) string {
	data := profile.UserAgent + profile.SecChUa + "1920x1080x24" + fmt.Sprintf("%d", time.Now().UnixNano())
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

// CaptchaTlsClientSolver provides captcha solving using tlsclient library
type CaptchaTlsClientSolver struct {
	client  tlsclient.HttpClient
	profile Profile
}

// NewCaptchaTlsClientSolver creates a new captcha solver with provided tlsclient
func NewCaptchaTlsClientSolver(client tlsclient.HttpClient, profile Profile) (*CaptchaTlsClientSolver, error) {
	if client == nil {
		return nil, fmt.Errorf("tlsclient cannot be nil")
	}
	return &CaptchaTlsClientSolver{
		client:  client,
		profile: profile,
	}, nil
}

// Solve solves the VK captcha using tlsclient
func (s *CaptchaTlsClientSolver) Solve(ctx context.Context, captchaErr *VkCaptchaError) (string, error) {
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectUri == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	bootstrap, err := s.fetchCaptchaBootstrap(ctx, captchaErr.RedirectUri)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[Captcha] PoW input: %s, difficulty: %d", bootstrap.PowInput, bootstrap.Difficulty)

	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	turnLog("[Captcha] PoW solved: hash=%s", hash)

	successToken, err := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		0,
		s.client,
		s.profile,
		bootstrap.Settings,
	)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	turnLog("[Captcha] Success! Got success_token")
	return successToken, nil
}

func (s *CaptchaTlsClientSolver) fetchCaptchaBootstrap(ctx context.Context, redirectUri string) (*captchaBootstrap, error) {
	parsedURL, err := url.Parse(redirectUri)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectUri, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	req.Header.Set("User-Agent", s.profile.UserAgent)
	req.Header.Set("sec-ch-ua", s.profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", s.profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", s.profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

// Close closes the tlsclient
func (s *CaptchaTlsClientSolver) Close() {
	s.client.CloseIdleConnections()
}
