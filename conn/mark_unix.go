//go:build linux || openbsd || freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func setRawConnMark(conn syscall.RawConn, mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	var setMarkErr error
	if err := conn.Control(func(fd uintptr) {
		setMarkErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	}); err != nil {
		return err
	}
	return setMarkErr
}

func setTCPConnMark(conn *net.TCPConn, mark uint32) error {
	fd, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setRawConnMark(fd, mark)
}

func setTCPListenerMark(listener *net.TCPListener, mark uint32) error {
	fd, err := listener.SyscallConn()
	if err != nil {
		return err
	}
	return setRawConnMark(fd, mark)
}

func (s *StdNetBind) SetMark(mark uint32) error {
	var operr error
	if fwmarkIoctl == 0 {
		return nil
	}
	if s.ipv4 != nil {
		fd, err := s.ipv4.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	if s.ipv6 != nil {
		fd, err := s.ipv6.SyscallConn()
		if err != nil {
			return err
		}
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TcpBind) SetMark(mark uint32) error {
	t.connectMu.Lock()
	defer t.connectMu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fwmark = mark
	if fwmarkIoctl == 0 {
		return nil
	}

	if t.listener != nil {
		if err := setTCPListenerMark(t.listener, mark); err != nil {
			return err
		}
	}
	for _, conn := range t.tcpConnMap {
		if err := setTCPConnMark(conn.conn, mark); err != nil {
			return err
		}
	}
	return nil
}
