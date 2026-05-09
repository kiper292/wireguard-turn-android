/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
#include <android/log.h>
extern int wgProtectSocket(int fd);
extern const char* getNetworkDnsServers(long long network_handle);
*/
import "C"

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

var turnClientTag = C.CString("WireGuard/TurnClient")

func turnLog(format string, args ...interface{}) {
	l := AndroidLogger{level: C.ANDROID_LOG_INFO, tag: turnClientTag}
	l.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		C.wgProtectSocket(C.int(fd))
	})
}

func init() {
	os.Setenv("GODEBUG", "netdns=go")
}

//export wgNotifyNetworkChange
func wgNotifyNetworkChange() {
	// Clear DNS cache
	ClearCache()

	turnHTTPClient.CloseIdleConnections()
	turnLog("[NETWORK] Network change notified: HTTP connections cleared, DNS cache cleared")
}

var turnHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: protectControl,
		}).DialContext,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	},
}

type stream struct {
	ctx             context.Context
	id              int
	in              chan []byte
	out             net.PacketConn
	peer            atomic.Pointer[net.Addr] // Last seen addr from WireGuard
	ready           atomic.Bool
	sessionID       []byte
	cert            *tls.Certificate
	watchdogTimeout int
	wrapKey         []byte
}

const iPacketBuffMaxSize = 2048

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, iPacketBuffMaxSize)
	},
}

// Metrics for diagnostics
var (
	dtlsTxDropCount    atomic.Uint64 // Drops in DTLS TX goroutine
	dtlsRxErrorCount   atomic.Uint64 // Errors in DTLS RX goroutine
	relayTxErrorCount  atomic.Uint64 // Errors in relay TX
	relayRxErrorCount  atomic.Uint64 // Errors in relay RX
	noDtlsTxDropCount  atomic.Uint64 // Drops in NoDTLS TX
	noDtlsRxErrorCount atomic.Uint64 // Errors in NoDTLS RX
)

func (s *stream) run(link string, peer *net.UDPAddr, udp bool, okchan chan<- struct{}, turnIp string, turnPort int, peerType string) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		err := func() error {
			s.ready.Store(false)
			sCtx, sCancel := context.WithCancel(s.ctx)
			defer sCancel()

			if globalGetCreds == nil {
				return fmt.Errorf("credentials function not initialized")
			}
			user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
			if err != nil {
				return fmt.Errorf("TURN creds failed: %w", err)
			}

			// Override TURN address if provided
			if turnIp != "" {
				_, origPort, _ := net.SplitHostPort(addr)
				if turnPort != 0 {
					addr = net.JoinHostPort(turnIp, fmt.Sprintf("%d", turnPort))
				} else if origPort != "" {
					addr = net.JoinHostPort(turnIp, origPort)
				} else {
					addr = turnIp
				}
				turnLog("[STREAM %d] Using custom TURN IP: %s", s.id, addr)
			} else if turnPort != 0 {
				origHost, _, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(origHost, fmt.Sprintf("%d", turnPort))
				turnLog("[STREAM %d] Using custom TURN port: %s", s.id, addr)
			}

			turnLog("[STREAM %d] Dialing TURN server %s...", s.id, addr)
			// addr is already resolved during credential fetch via cascading DNS, so use DialContext without Resolver
			dialer := &net.Dialer{
				Timeout: 30 * time.Second,
				Control: protectControl,
			}
			var turnConn net.PacketConn
			if udp {
				c, err := dialer.DialContext(sCtx, "udp", addr)
				if err != nil {
					return fmt.Errorf("TURN UDP dial failed: %w", err)
				}
				defer c.Close()
				turnConn = &connectedUDPConn{c.(*net.UDPConn)}
			} else {
				c, err := dialer.DialContext(sCtx, "tcp", addr)
				if err != nil {
					return fmt.Errorf("TURN TCP dial failed: %w", err)
				}
				defer c.Close()
				turnConn = turn.NewSTUNConn(c)
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr, TURNServerAddr: addr, Username: user, Password: pass,
				Conn: turnConn, LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			if err != nil {
				return fmt.Errorf("TURN client creation failed: %w", err)
			}
			defer client.Close()
			if err := client.Listen(); err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN listen failed: %w", err)
			}

			turnLog("[STREAM %d] Requesting TURN allocation...", s.id)
			relayConn, err := client.Allocate()
			if err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN allocation failed: %w", err)
			}
			defer relayConn.Close()

			turnLog("[STREAM %d] Allocated relay address: %s", s.id, relayConn.LocalAddr())

			// Delegate to mode-specific handler
			if peerType == "wireguard" {
				return s.runNoDTLS(sCtx, relayConn, peer, okchan)
			}
			return s.runDTLS(sCtx, relayConn, peer, okchan, peerType)
		}()

		if err != nil && s.ctx.Err() == nil {
			turnLog("[STREAM %d] Error: %v. Reconnecting in 1s...", s.id, err)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}

// runNoDTLS handles packet relay without DTLS obfuscation
func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	turnLog("[STREAM %d] No DTLS mode - direct relay", s.id)
	turnLog("[STREAM %d] Forwarding to WireGuard server: %s", s.id, peer.String())

	wg := sync.WaitGroup{}
	wg.Add(2)

	// WireGuard backend (s.in channel) -> TURN -> WireGuard server (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				_, err := relayConn.WriteTo(b, peer)
				packetPool.Put(b[:cap(b)])

				if err != nil {
					noDtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// WireGuard server -> TURN -> WireGuard backend (s.out socket) (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				turnLog("[STREAM %d] RX error: %v", s.id, err)
				return
			}
			if from.String() == peer.String() {
				addr := s.peer.Load()
				if addr == nil {
					addr = globalWgPeer.Load()
				}
				if addr == nil {
					turnLog("[STREAM %d] RX: no peer address yet", s.id)
					continue
				}
				if _, err := s.out.WriteTo(buf[:n], *addr); err != nil {
					noDtlsRxErrorCount.Add(1)
					turnLog("[STREAM %d] RX write error: %v", s.id, err)
					return
				}
			}
		}
	}()

	s.ready.Store(true)
	select {
	case okchan <- struct{}{}:
	default:
	}

	wg.Wait()
	return nil
}

// runDTLS handles packet relay with DTLS obfuscation
func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}, peerType string) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	relayWire := relayConn
	if len(s.wrapKey) > 0 {
		wrapped, err := newWrapPacketConn(relayWire, s.wrapKey)
		if err != nil {
			return fmt.Errorf("wrap setup failed: %w", err)
		}
		relayWire = wrapped
		turnLog("[STREAM %d] WRAP enabled for relay transport", s.id)
	} else if peerType == "turncoat_v3" {
		turnLog("[STREAM %d] WRAP key is empty for turncoat_v3", s.id)
	}

	var dtlsConn *dtls.Conn

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates: []tls.Certificate{*s.cert}, InsecureSkipVerify: true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		return fmt.Errorf("DTLS client creation failed: %w", err)
	}
	defer dtlsConn.Close()

	wg := sync.WaitGroup{}
	wg.Add(3)

	// Robust cleanup
	context.AfterFunc(sCtx, func() {
		relayConn.Close()
		c1.Close() // Breaks dtlsConn
	})

	// DTLS <-> Relay (via Pipe) - MUST start before handshake
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := relayWire.WriteTo(buf[:n], peer); err != nil {
				relayTxErrorCount.Add(1)
				turnLog("[STREAM %d] Relay TX error: %v", s.id, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayWire.ReadFrom(buf)
			if err != nil {
				relayRxErrorCount.Add(1)
				turnLog("[STREAM %d] Relay RX error: %v", s.id, err)
				return
			}
			if from.String() == peer.String() {
				if _, err := c2.WriteTo(buf[:n], peer); err != nil {
					relayTxErrorCount.Add(1)
					turnLog("[STREAM %d] Relay RX->Pipe error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// Deadline updater
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sCtx.Done():
				return
			case <-ticker.C:
				deadline := time.Now().Add(30 * time.Second)
				relayConn.SetDeadline(deadline)
				dtlsConn.SetDeadline(deadline)
				c2.SetDeadline(deadline)
			}
		}
	}()

	// Set explicit deadline for handshake
	turnLog("[STREAM %d] Starting DTLS handshake...", s.id)
	dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := dtlsConn.HandshakeContext(sCtx); err != nil {
		turnLog("[STREAM %d] DTLS handshake FAILED: %v", s.id, err)
		return fmt.Errorf("DTLS handshake timeout: %w", err)
	}

	// Clear deadline after successful handshake
	dtlsConn.SetDeadline(time.Time{})
	turnLog("[STREAM %d] DTLS handshake SUCCESS", s.id)

	switch peerType {
	case "turncoat_v3":
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		handshakeBuf := make([]byte, 19)
		handshakeBuf[0] = 0x54
		handshakeBuf[1] = 0x43
		handshakeBuf[2] = 2
		copy(handshakeBuf[3:], s.sessionID)

		if _, err := dtlsConn.Write(handshakeBuf); err != nil {
			return fmt.Errorf("turncoat v3 session handshake failed: %w", err)
		}
		dtlsConn.SetWriteDeadline(time.Time{})
	case "proxy_v2":
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		handshakeBuf := make([]byte, 17)
		copy(handshakeBuf[:16], s.sessionID)
		handshakeBuf[16] = byte(s.id)

		if _, err := dtlsConn.Write(handshakeBuf); err != nil {
			return fmt.Errorf("session ID handshake failed: %w", err)
		}
		dtlsConn.SetWriteDeadline(time.Time{})
	}

	s.ready.Store(true)
	select {
	case okchan <- struct{}{}:
	default:
	}

	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	wg.Add(2)

	// WireGuard -> DTLS (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:

				// Watchdog (only active if watchdogTimeout > 0)
				if s.watchdogTimeout > 0 && time.Since(time.Unix(lastRx.Load(), 0)) > time.Duration(s.watchdogTimeout)*time.Second {
					packetPool.Put(b[:cap(b)])
					dtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX watchdog timeout (%ds)", s.id, s.watchdogTimeout)
					return
				}

				_, err := dtlsConn.Write(b)
				packetPool.Put(b[:cap(b)])

				if err != nil {
					dtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// DTLS -> WireGuard (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				turnLog("[STREAM %d] RX error: %v", s.id, err)
				return
			}
			lastRx.Store(time.Now().Unix())
			last := s.peer.Load()
			if last == nil {
				last = globalWgPeer.Load()
			}
			if last != nil {
				if _, err := s.out.WriteTo(buf[:n], *last); err != nil {
					dtlsRxErrorCount.Add(1)
					turnLog("[STREAM %d] RX write error: %v", s.id, err)
					return
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

var currentTurnCancel context.CancelFunc
var turnMutex sync.Mutex

// Global credentials function for mode selection (set by wgTurnProxyStart)
var globalGetCreds getCredsFunc

// Most recently observed local WG endpoint. Server-side session aggregation
// (turncoat_v3) load-balances inbound bytes round-robin across streams, so a
// reply may arrive on a stream whose own .peer hasn't been populated yet —
// without a shared fallback, those packets get silently dropped.
var globalWgPeer atomic.Pointer[net.Addr]

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddrC *C.char, vklinkC *C.char, modeC *C.char, n C.int, udp C.int, listenAddrC *C.char, turnIpC *C.char, turnPortC C.int, peerTypeC *C.char, streamsPerCredC C.int, watchdogTimeoutC C.int, wrapKeyC *C.char, networkHandleC C.longlong) int32 {
	// Force initialization of resolver and HTTP client with current environment
	wgNotifyNetworkChange()

	// Initialize system DNS from the current network (fallback to predefined Yandex/Google)
	if networkHandleC != 0 {
		if dnsStr := C.getNetworkDnsServers(C.longlong(networkHandleC)); dnsStr != nil {
			dnsGo := C.GoString(dnsStr)
			C.free(unsafe.Pointer(dnsStr))
			servers := strings.Split(dnsGo, ",")
			InitSystemDns(servers)
		}
	}

	peerAddr := C.GoString(peerAddrC)
	vklink := C.GoString(vklinkC)
	mode := C.GoString(modeC)
	listenAddr := C.GoString(listenAddrC)
	turnIp := C.GoString(turnIpC)
	turnPort := int(turnPortC)
	peerType := C.GoString(peerTypeC)
	streamsPerCred = int(streamsPerCredC)
	watchdogTimeout := int(watchdogTimeoutC)
	wrapKeyHex := strings.TrimSpace(C.GoString(wrapKeyC))
	networkHandle := int64(networkHandleC)

	var wrapKey []byte
	if wrapKeyHex != "" {
		parsed, err := parseWrapKeyHex(wrapKeyHex)
		if err != nil {
			turnLog("[PROXY] Invalid WRAP key: %v", err)
			return -1
		}
		wrapKey = parsed
	}

	turnLog("[PROXY] Hub starting on %s (streams=%d, mode=%s, peerType=%s, streamsPerCred=%d, watchdogTimeout=%d, wrap=%t, networkHandle=%d)", listenAddr, int(n), mode, peerType, streamsPerCred, watchdogTimeout, len(wrapKey) > 0, networkHandle)
	turnMutex.Lock()
	if currentTurnCancel != nil {
		currentTurnCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()

	// Setup credentials function based on mode
	if mode == "wb" {
		turnLog("[PROXY] Using WB credential mode")
		globalGetCreds = func(ctx context.Context, link string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, link, streamID, wbFetch)
		}
	} else {
		turnLog("[PROXY] Using VK Link credential mode")
		parts := strings.Split(vklink, "join/")
		link := parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, lk, streamID, fetchVkCreds)
		}
	}

	// Resolve peerAddr via cascading DNS (if it's a domain)
	var peer *net.UDPAddr
	host, port, err := net.SplitHostPort(peerAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(context.Background(), host)
			if err != nil {
				turnLog("[DNS] Warning: failed to resolve peer: %v, using original", err)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil {
					return -1
				}
			} else {
				peerAddr = net.JoinHostPort(resolvedIP, port)
				//turnLog("[DNS] Resolved peer %s -> %s", host, resolvedIP)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil {
					return -1
				}
			}
		} else {
			peer, err = net.ResolveUDPAddr("udp", peerAddr)
			if err != nil {
				return -1
			}
		}
	} else {
		peer, err = net.ResolveUDPAddr("udp", peerAddr)
		if err != nil {
			return -1
		}
	}

	// Determine link for VK mode (for WB mode, link is just "wb")
	var link string
	if mode == "wb" {
		link = "wb"
	} else {
		parts := strings.Split(vklink, "join/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
	}

	lc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return -1
	}
	context.AfterFunc(ctx, func() { lc.Close() })

	// Generate fresh Session ID for every run to avoid server-side conflicts
	sessionID, _ := uuid.New().MarshalBinary()
	turnLog("[PROXY] Session ID generated: %x", sessionID)

	// Generate DTLS certificate once for all streams to save CPU
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		turnLog("[PROXY] Failed to generate DTLS certificate: %v", err)
		return -1
	}

	ok := make(chan struct{}, int(n))
	streams := make([]*stream, int(n))
	for i := 0; i < int(n); i++ {
		streams[i] = &stream{ctx: ctx, id: i, in: make(chan []byte, 512), out: lc, sessionID: sessionID, cert: &cert, watchdogTimeout: watchdogTimeout, wrapKey: wrapKey}
		go streams[i].run(link, peer, udp != 0, ok, turnIp, turnPort, peerType)
		time.Sleep(200 * time.Millisecond)
	}

	go func() {
		nStreams := int(len(streams))
		var lastUsed int = 0

		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}

			// Round-Robin selection
			lastUsed = (lastUsed + 1) % nStreams

			var s *stream
			for i := 0; i < nStreams; i++ {
				st := streams[(lastUsed+i)%nStreams]
				if st.ready.Load() {
					s = st
					break
				}
			}

			if s == nil {
				packetPool.Put(b[:cap(b)])
				continue
			}

			returnAddr := addr
			s.peer.Store(&returnAddr)
			globalWgPeer.Store(&returnAddr)

			select {
			case s.in <- b[:nRead]:
				// Packet queued successfully
			default:
				packetPool.Put(b[:cap(b)])
			}
		}
	}()

	select {
	case <-ok:
		turnLog("[PROXY] First stream is ready, tunnel can start")
		return 0
	case <-ctx.Done():
		turnLog("[PROXY] PROXY startup cancelled")
		return -1
	}
}

//export wgTurnProxyStop
func wgTurnProxyStop() {
	turnMutex.Lock()
	defer turnMutex.Unlock()
	if currentTurnCancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		currentTurnCancel()
		currentTurnCancel = nil
	}
}

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
