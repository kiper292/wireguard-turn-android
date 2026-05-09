/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026.
 */

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

func parseWrapKeyHex(value string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}

func newWrapPacketConn(inner net.PacketConn, key []byte) (net.PacketConn, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	keyCopy := append([]byte(nil), key...)
	return &wrapPacketConn{inner: inner, key: keyCopy}, nil
}

type wrapPacketConn struct {
	inner net.PacketConn
	key   []byte
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+wrapNonceLen)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < wrapNonceLen {
		return 0, addr, errors.New("wrap: short packet")
	}

	nonce := buf[:wrapNonceLen]
	ciphertext := buf[wrapNonceLen:n]
	if len(ciphertext) > len(p) {
		return 0, addr, errors.New("wrap: read buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, nonce)
	if err != nil {
		return 0, addr, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(p[:len(ciphertext)], ciphertext)
	return len(ciphertext), addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, wrapNonceLen+len(p))
	if _, err := rand.Read(out[:wrapNonceLen]); err != nil {
		return 0, fmt.Errorf("wrap: nonce gen: %w", err)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, out[:wrapNonceLen])
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(out[wrapNonceLen:], p)
	if _, err := c.inner.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
