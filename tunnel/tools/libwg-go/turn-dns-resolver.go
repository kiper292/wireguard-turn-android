/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// extern int wgProtectSocket(int fd);
import "C"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DnsCache stores cached IP addresses
type DnsCache struct {
	mu   sync.RWMutex
	ips  map[string]cachedIP
}

type cachedIP struct {
	ip      string
	expires time.Time
}

const (
	cacheTTL        = 5 * time.Minute
	dnsTimeout      = 2 * time.Second
	dohTimeout      = 5 * time.Second
	dotTimeout      = 5 * time.Second
	yandexDNSServer = "77.88.8.8"
	yandexDoHIP     = "77.88.8.8:443"
	yandexDoHURL    = "https://common.dot.dns.yandex.net/dns-query"
	yandexDoTIP     = "77.88.8.8:853"
	yandexServerName = "common.dot.dns.yandex.net"
)

var (
	hostCache = &DnsCache{
		ips: make(map[string]cachedIP),
	}
)

// Resolve resolves DNS name using cache and cascading fallback
func (c *DnsCache) Resolve(ctx context.Context, domain string) (string, error) {
	// 1. Check cache
	c.mu.RLock()
	if cached, ok := c.ips[domain]; ok && time.Now().Before(cached.expires) {
		c.mu.RUnlock()
		return cached.ip, nil
	}
	c.mu.RUnlock()

	// 2. Resolve with fallback
	ip, err := resolveWithFallback(ctx, domain)
	if err != nil {
		return "", err
	}

	// 3. Save to cache
	c.mu.Lock()
	c.ips[domain] = cachedIP{
		ip:      ip,
		expires: time.Now().Add(cacheTTL),
	}
	c.mu.Unlock()

	return ip, nil
}

// resolveWithFallback resolves DNS with cascading fallback: UDP → DoH → DoT
func resolveWithFallback(ctx context.Context, domain string) (string, error) {
	var lastErr error

	// 1. Standard DNS (UDP 53) - fastest and most reliable
	turnLog("[DNS] Trying UDP for %s", domain)
	if ip, err := resolveUDP(ctx, domain); err == nil {
		turnLog("[DNS] UDP success: %s -> %s", domain, ip)
		return ip, nil
	} else {
		turnLog("[DNS] UDP failed: %v", err)
		lastErr = err
	}

	// 2. DoH (HTTPS 443) - fallback if UDP is blocked
	turnLog("[DNS] Trying DoH for %s", domain)
	if ip, err := resolveDoH(ctx, domain); err == nil {
		turnLog("[DNS] DoH success: %s -> %s", domain, ip)
		return ip, nil
	} else {
		turnLog("[DNS] DoH failed: %v", err)
	}

	// 3. DoT (TLS 853) - final fallback
	turnLog("[DNS] Trying DoT for %s", domain)
	if ip, err := resolveDoT(ctx, domain); err == nil {
		turnLog("[DNS] DoT success: %s -> %s", domain, ip)
		return ip, nil
	} else {
		turnLog("[DNS] DoT failed: %v", err)
	}

	return "", fmt.Errorf("all DNS methods failed for %s: %w", domain, lastErr)
}

// resolveUDP resolves DNS via standard UDP query
func resolveUDP(ctx context.Context, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	// Build DNS query (A record)
	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	// Use DialContext with protectControl (same as old protectedResolver)
	addr := yandexDNSServer + ":53"
	dialer := &net.Dialer{
		Timeout: dnsTimeout,
		Control: protectControl,
	}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	// Send query
	conn.SetDeadline(time.Now().Add(dnsTimeout))
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("failed to send DNS query: %w", err)
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read DNS response: %w", err)
	}

	// Parse response
	ip, err := parseDNSResponse(response[:n], domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// resolveDoH resolves DNS via DNS-over-HTTPS
func resolveDoH(ctx context.Context, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	// Build HTTP request with IP directly (no DNS resolution needed)
	ipURL := "https://" + yandexDoHIP + "/dns-query"
	req, err := http.NewRequestWithContext(ctx, "POST", ipURL, bytes.NewReader(query))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Host = yandexServerName

	// DoH requires HTTP/2 per RFC 8484
	client := &http.Client{
		Timeout: dohTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return protectAndDial(ctx, network, yandexDoHIP)
			},
			TLSClientConfig: &tls.Config{
				ServerName: yandexServerName,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip, err := parseDNSResponse(body, domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// resolveDoT resolves DNS via DNS-over-TLS
func resolveDoT(ctx context.Context, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dotTimeout)
	defer cancel()

	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	tlsConfig := &tls.Config{
		ServerName: yandexServerName,
		MinVersion: tls.VersionTLS12,
	}

	tcpConn, err := protectAndDial(ctx, "tcp", yandexDoTIP)
	if err != nil {
		return "", fmt.Errorf("failed to connect to DoT server: %w", err)
	}
	defer tcpConn.Close()

	tlsConn := tls.Client(tcpConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(dotTimeout))

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return "", fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Send DNS query with 2-byte length prefix (DoT protocol)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(query)))

	_, err = tlsConn.Write(append(lengthPrefix, query...))
	if err != nil {
		return "", fmt.Errorf("failed to send DoT query: %w", err)
	}

	// Read response length
	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(tlsConn, lengthBuf)
	if err != nil {
		return "", fmt.Errorf("failed to read DoT response length: %w", err)
	}

	responseLen := binary.BigEndian.Uint16(lengthBuf)
	response := make([]byte, responseLen)
	_, err = io.ReadFull(tlsConn, response)
	if err != nil {
		return "", fmt.Errorf("failed to read DoT response: %w", err)
	}

	ip, err := parseDNSResponse(response, domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// buildDNSQuery builds DNS query for A record
func buildDNSQuery(domain string) ([]byte, error) {
	query := make([]byte, 12)

	// Random ID
	binary.BigEndian.PutUint16(query[0:2], uint16(time.Now().UnixNano()&0xFFFF))

	// Flags: standard recursive query
	binary.BigEndian.PutUint16(query[2:4], 0x0100)

	// QDCOUNT = 1
	binary.BigEndian.PutUint16(query[4:6], 1)

	// Encode domain name
	var nameBuf bytes.Buffer
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, part := range parts {
		nameBuf.WriteByte(byte(len(part)))
		nameBuf.WriteString(part)
	}
	nameBuf.WriteByte(0) // End of domain

	// QTYPE = A (1), QCLASS = IN (1)
	nameBuf.WriteByte(0)
	nameBuf.WriteByte(1)
	nameBuf.WriteByte(0)
	nameBuf.WriteByte(1)

	return append(query, nameBuf.Bytes()...), nil
}

// parseDNSResponse parses DNS response and extracts A record
func parseDNSResponse(response []byte, domain string) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("DNS response too short")
	}

	// Check response flag
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 {
		return "", fmt.Errorf("not a DNS response")
	}

	// Check response code
	rcode := flags & 0x000F
	if rcode != 0 {
		return "", fmt.Errorf("DNS error: rcode=%d", rcode)
	}

	// Get answer count
	ansCount := binary.BigEndian.Uint16(response[6:8])
	if ansCount == 0 {
		return "", fmt.Errorf("no answers in DNS response")
	}

	// Skip question section
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		labelLen := int(response[offset])
		if labelLen == 0 || labelLen > 63 {
			break
		}
		offset += labelLen + 1
	}
	offset += 5 // Null byte + QTYPE (2) + QCLASS (2)

	// Read answers
	for i := 0; i < int(ansCount) && offset < len(response); i++ {
		// Skip name (may have compression)
		for offset < len(response) && response[offset] != 0 {
			labelLen := int(response[offset])
			if labelLen > 63 {
				offset += 2 // Compression pointer
				break
			}
			offset += labelLen + 1
		}
		if offset >= len(response)-10 {
			break
		}

		qtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2      // TYPE
		offset += 2      // CLASS
		offset += 4      // TTL
		rdLength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		// Check if this is A record (TYPE=1, length=4)
		if qtype == 1 && rdLength == 4 && offset+4 <= len(response) {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				response[offset],
				response[offset+1],
				response[offset+2],
				response[offset+3])
			return ip, nil
		}

		offset += int(rdLength)
	}

	return "", fmt.Errorf("no A record found in DNS response")
}

// protectAndDial creates TCP connection and protects it via Control callback
func protectAndDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl, // Protects socket before connect()
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// ClearCache clears DNS cache
func ClearCache() {
	hostCache.mu.Lock()
	defer hostCache.mu.Unlock()
	hostCache.ips = make(map[string]cachedIP)
	turnLog("[DNS] Cache cleared")
}
