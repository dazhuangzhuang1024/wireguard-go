//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"syscall"
)

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	t.connectMu.Lock()
	defer t.connectMu.Unlock()
	t.mu.Lock()
	t.fwmark = mark
	t.mu.Unlock()
	return nil
}

func setRawConnMark(conn syscall.RawConn, mark uint32) error {
	return nil
}

func setTCPConnMark(conn *net.TCPConn, mark uint32) error {
	return nil
}

func setTCPListenerMark(listener *net.TCPListener, mark uint32) error {
	return nil
}
