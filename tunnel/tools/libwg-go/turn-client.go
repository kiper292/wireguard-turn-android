/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <android/log.h>
extern int wgProtectSocket(int fd);
*/
import "C"

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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func turnLog(format string, args ...interface{}) {
	tag := cstring("WireGuard/TurnClient")
	l := AndroidLogger{level: C.ANDROID_LOG_INFO, tag: tag}
	l.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		C.wgProtectSocket(C.int(fd))
	})
}

var protectedResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second, Control: protectControl}
		if strings.HasPrefix(address, "127.0.0.1") || strings.HasPrefix(address, "[::1]") {
			return d.DialContext(ctx, "udp", "77.88.8.8:53")
		}
		conn, err := d.DialContext(ctx, network, address)
		if err == nil { return conn, nil }
		return d.DialContext(ctx, "udp", "77.88.8.8:53")
	},
}

var turnHTTPClient *http.Client

func init() {
	os.Setenv("GODEBUG", "netdns=go")
	turnHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 30 * time.Second, Control: protectControl, Resolver: protectedResolver}).DialContext,
			MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
		},
	}
}

func getVkCreds(ctx context.Context, link string) (string, string, string, error) {
	turnLog("[VK Auth] Starting credential fetch...")
	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil { return nil, err }
		req.Header.Add("User-Agent", "Mozilla/5.0 (Android 12; Mobile; rv:144.0)")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		httpResp, err := turnHTTPClient.Do(req)
		if err != nil { return nil, err }
		defer httpResp.Body.Close()
		body, err := io.ReadAll(httpResp.Body)
		if err != nil { return nil, err }
		if err = json.Unmarshal(body, &resp); err != nil { return nil, err }
		if errMsg, ok := resp["error"].(map[string]interface{}); ok { return resp, fmt.Errorf("VK error: %v", errMsg) }
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
	turnLog("[VK Auth] Success! TURN Server: %s", address)
	return ts["username"].(string), ts["credential"].(string), address, nil
}

type stream struct {
	ctx    context.Context
	id     int
	in     chan []byte
	out    net.PacketConn
	peer   atomic.Pointer[net.Addr] // Last seen addr from WireGuard
	ready  atomic.Bool
}

func (s *stream) run(link string, peer *net.UDPAddr, udp bool, okchan chan<- struct{}) {
	for {
		select {
		case <-s.ctx.Done(): return
		default:
		}

		err := func() error {
			s.ready.Store(false)
			sCtx, sCancel := context.WithCancel(s.ctx)
			defer sCancel()

			user, pass, addr, err := getVkCreds(sCtx, link)
			if err != nil { return fmt.Errorf("VK creds failed: %w", err) }

			turnLog("[STREAM %d] Dialing TURN server %s...", s.id, addr)
			dialer := &net.Dialer{Control: protectControl, Resolver: protectedResolver}
			var turnConn net.PacketConn
			if udp {
				c, err := dialer.DialContext(sCtx, "udp", addr)
				if err != nil { return fmt.Errorf("TURN UDP dial failed: %w", err) }
				defer c.Close()
				turnConn = &connectedUDPConn{c.(*net.UDPConn)}
			} else {
				c, err := dialer.DialContext(sCtx, "tcp", addr)
				if err != nil { return fmt.Errorf("TURN TCP dial failed: %w", err) }
				defer c.Close()
				turnConn = turn.NewSTUNConn(c)
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr, TURNServerAddr: addr, Username: user, Password: pass,
				Conn: turnConn, LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			if err != nil { return fmt.Errorf("TURN client creation failed: %w", err) }
			defer client.Close()
			if err := client.Listen(); err != nil { return fmt.Errorf("TURN listen failed: %w", err) }
			
			turnLog("[STREAM %d] Requesting TURN allocation...", s.id)
			relayConn, err := client.Allocate()
			if err != nil { return fmt.Errorf("TURN allocation failed: %w", err) }
			defer relayConn.Close()

			turnLog("[STREAM %d] Allocated relay address: %s", s.id, relayConn.LocalAddr())

			cert, err := selfsign.GenerateSelfSigned()
			if err != nil { return err }
			c1, c2 := connutil.AsyncPacketPipe()
			defer c1.Close()
			defer c2.Close()

			turnLog("[STREAM %d] Starting DTLS handshake...", s.id)
			dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
				Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
				ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
				CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
			})
			if err != nil { return fmt.Errorf("DTLS client failed: %w", err) }
			defer dtlsConn.Close()

			turnLog("[STREAM %d] Ready!", s.id)
			s.ready.Store(true)
			select { case okchan <- struct{}{}: default: }

			wg := sync.WaitGroup{}
			wg.Add(4)
			
			// Deadline updater
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-sCtx.Done(): return
					case <-ticker.C:
						deadline := time.Now().Add(25 * time.Second)
						relayConn.SetDeadline(deadline)
						dtlsConn.SetDeadline(deadline)
						c2.SetDeadline(deadline)
					}
				}
			}()

			// WireGuard -> DTLS
			go func() {
				defer wg.Done(); defer sCancel()
				for {
					select {
					case <-sCtx.Done(): return
					case b := <-s.in:
						// turnLog("[STREAM %d] -> DTLS (%d bytes)", s.id, len(b))
						if _, err := dtlsConn.Write(b); err != nil { return }
					}
				}
			}()
			// DTLS -> Relay (via Pipe)
			go func() {
				defer wg.Done(); defer sCancel()
				buf := make([]byte, 2048)
				for {
					n, _, err := c2.ReadFrom(buf)
					if err != nil { return }
					// turnLog("[STREAM %d] DTLS -> TURN (%d bytes)", s.id, n)
					if _, err := relayConn.WriteTo(buf[:n], peer); err != nil { return }
				}
			}()
			// Relay -> DTLS (via Pipe)
			go func() {
				defer wg.Done(); defer sCancel()
				buf := make([]byte, 2048)
				for {
					n, from, err := relayConn.ReadFrom(buf)
					if err != nil { return }
					if from.String() == peer.String() {
						// turnLog("[STREAM %d] TURN -> DTLS (%d bytes)", s.id, n)
						if _, err := c2.WriteTo(buf[:n], peer); err != nil { return }
					}
				}
			}()
			// DTLS -> WireGuard
			go func() {
				defer wg.Done(); defer sCancel()
				buf := make([]byte, 2048)
				for {
					n, err := dtlsConn.Read(buf)
					if err != nil { return }
					if last := s.peer.Load(); last != nil {
						s.out.WriteTo(buf[:n], *last)
					}
				}
			}()

			wg.Wait()
			return nil
		}()

		if err != nil && s.ctx.Err() == nil {
			turnLog("[STREAM %d] Error: %v. Restarting in 1s...", s.id, err)
			time.Sleep(1 * time.Second)
		}
	}
}

var currentTurnCancel context.CancelFunc
var turnMutex sync.Mutex

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddrC *C.char, vklinkC *C.char, n int, udp int, listenAddrC *C.char) int32 {
	peerAddr := C.GoString(peerAddrC)
	vklink := C.GoString(vklinkC)
	listenAddr := C.GoString(listenAddrC)

	turnLog("[PROXY] Hub starting on %s (peer=%s, streams=%d)", listenAddr, peerAddr, n)
	turnMutex.Lock()
	if currentTurnCancel != nil { currentTurnCancel() }
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil { return -1 }
	parts := strings.Split(vklink, "join/")
	link := parts[len(parts)-1]
	if idx := strings.IndexAny(link, "/?#"); idx != -1 { link = link[:idx] }

	lc, err := net.ListenPacket("udp", listenAddr)
	if err != nil { return -1 }
	context.AfterFunc(ctx, func() { lc.Close() })

	ok := make(chan struct{}, n)
	streams := make([]*stream, n)
	for i := 0; i < n; i++ {
		streams[i] = &stream{ctx: ctx, id: i, in: make(chan []byte, 1000), out: lc}
		go streams[i].run(link, peer, udp != 0, ok)
	}

	go func() {
		var activeStream atomic.Pointer[stream]
		buf := make([]byte, 2048)
		for {
			nRead, addr, err := lc.ReadFrom(buf)
			if err != nil { return }
			
			s := activeStream.Load()
			// Only switch if current is nil or not ready
			if s == nil || !s.ready.Load() {
				s = nil
				for _, st := range streams {
					if st.ready.Load() {
						s = st
						activeStream.Store(s)
						turnLog("[PROXY] Sticky stream selected: [STREAM %d]", s.id)
						break
					}
				}
			}

			if s == nil { continue }

			returnAddr := addr
			s.peer.Store(&returnAddr)

			b := make([]byte, nRead)
			copy(b, buf[:nRead])
			select { case s.in <- b: default: }
		}
	}()

	select {
	case <-ok: 
		turnLog("[PROXY] First stream is ready, tunnel can start")
		return 0
	case <-time.After(30 * time.Second):
		turnLog("[PROXY] TIMEOUT waiting for any stream to be ready")
		cancel()
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

type connectedUDPConn struct { *net.UDPConn }
func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
