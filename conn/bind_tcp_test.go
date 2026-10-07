package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const tcpTestTimeout = 3 * time.Second

// openTCPBind opens a client bind, which listens for nothing.
func openTCPBind(t *testing.T) (*TcpBind, []ReceiveFunc, uint16) {
	t.Helper()
	return openTCPBindOn(t, 0)
}

// openTCPServerBind opens a bind that listens on a free port.
func openTCPServerBind(t *testing.T) (*TcpBind, []ReceiveFunc, uint16) {
	t.Helper()
	return openTCPBindOn(t, freeTCPPort(t))
}

func openTCPBindOn(t *testing.T, port uint16) (*TcpBind, []ReceiveFunc, uint16) {
	t.Helper()
	bind := NewTCPBind().(*TcpBind)
	receive, actualPort, err := bind.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	if actualPort != port {
		t.Fatalf("Open(%d) returned port %d", port, actualPort)
	}
	t.Cleanup(func() {
		if err := bind.Close(); err != nil {
			t.Errorf("close TCP bind: %v", err)
		}
	})
	return bind, receive, actualPort
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func listenTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close TCP listener: %v", err)
		}
	})
	return listener
}

func acceptTCP(t *testing.T, listener *net.TCPListener) *net.TCPConn {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func readTCPFrame(t *testing.T, conn *net.TCPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	var l reqLen
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		t.Fatal(err)
	}
	size := l.Len()
	if size < 0 || size > MaxSegmentSize {
		t.Fatalf("invalid TCP frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	return data
}

func waitForTCPCondition(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(tcpTestTimeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func tcpConnectionCount(bind *TcpBind) int {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	return len(bind.tcpConnMap)
}

func TestReqLen(t *testing.T) {
	var l reqLen
	for _, size := range []int{0, 123456789, 65535} {
		l.FromLen(size)
		if got := l.Len(); got != size {
			t.Errorf("Len() = %d, want %d", got, size)
		}
	}
	if strconv.IntSize == 64 {
		maxUint32 := uint64(^uint32(0))
		size := int(maxUint32)
		l.FromLen(size)
		if got := l.Len(); got != size {
			t.Errorf("Len() = %d, want %d", got, size)
		}
	}
}

func TestTCPBindSendReceive(t *testing.T) {
	_, receive, port := openTCPServerBind(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}

	packets := []string{
		"hello world",
		"packet 2",
		strings.Repeat("X", 4096),
		strings.Repeat("Y", MaxSegmentSize),
	}
	bufs := [][]byte{make([]byte, MaxSegmentSize)}
	sizes := make([]int, 1)
	endpoints := make([]Endpoint, 1)

	for i, want := range packets {
		if err := client.Send([][]byte{[]byte(want)}, endpoint); err != nil {
			t.Fatalf("send packet %d: %v", i, err)
		}
		n, err := receive[0](bufs, sizes, endpoints)
		if err != nil {
			t.Fatalf("receive packet %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("received %d packets, want 1", n)
		}
		if got := string(bufs[0][:sizes[0]]); got != want {
			t.Fatalf("packet %d = %q, want %q", i, got, want)
		}
	}
}

func TestTCPBindReceiveOversizedFrame(t *testing.T) {
	listener, _, port := openTCPServerBind(t)
	conn, err := net.DialTCP(
		"tcp",
		nil,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var l reqLen
	l.FromLen(MaxSegmentSize + 1)
	if _, err := conn.Write(l[:]); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("oversized frame did not close the connection")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for oversized frame connection to close")
	}
	waitForTCPCondition(t, func() bool {
		return tcpConnectionCount(listener) == 0
	}, "oversized connection eviction")
}

func TestTCPBindRejectsOversizedOutboundFrame(t *testing.T) {
	client, _, port := openTCPServerBind(t)
	endpoint, err := client.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([][]byte{make([]byte, MaxSegmentSize+1)}, endpoint); err == nil {
		t.Fatal("oversized outbound frame was accepted")
	}
	if got := tcpConnectionCount(client); got != 0 {
		t.Fatalf("oversized outbound frame opened %d connections", got)
	}
}

func TestTCPBindReconnectsAfterRemoteClose(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := endpoint.DstToString()

	if err := client.Send([][]byte{[]byte("first")}, endpoint); err != nil {
		t.Fatal(err)
	}
	firstConn := acceptTCP(t, server)
	if got := string(readTCPFrame(t, firstConn)); got != "first" {
		t.Fatalf("first frame = %q, want %q", got, "first")
	}
	if err := firstConn.Close(); err != nil {
		t.Fatal(err)
	}

	waitForTCPCondition(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.tcpConnMap[endpointKey] == nil
	}, "closed connection eviction")

	if err := client.Send([][]byte{[]byte("second")}, endpoint); err != nil {
		t.Fatal(err)
	}
	secondConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = secondConn.Close() })
	if got := string(readTCPFrame(t, secondConn)); got != "second" {
		t.Fatalf("second frame = %q, want %q", got, "second")
	}
}

func TestTCPBindWriteFailureEvictsStaleConnection(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := endpoint.DstToString()

	if err := client.Send([][]byte{[]byte("warmup")}, endpoint); err != nil {
		t.Fatal(err)
	}
	serverConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = serverConn.Close() })
	if got := string(readTCPFrame(t, serverConn)); got != "warmup" {
		t.Fatalf("warmup frame = %q, want %q", got, "warmup")
	}

	client.mu.Lock()
	staleConn := client.tcpConnMap[endpointKey]
	client.mu.Unlock()
	if staleConn == nil {
		t.Fatal("connection was not cached")
	}
	if err := staleConn.Close(); err != nil {
		t.Fatal(err)
	}
	waitForTCPCondition(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.tcpConnMap[endpointKey] == nil
	}, "reader cleanup before injecting stale connection")

	client.mu.Lock()
	client.tcpConnMap[endpointKey] = staleConn
	client.mu.Unlock()
	if err := client.Send([][]byte{[]byte("must succeed")}, endpoint); err != nil {
		t.Fatalf("send did not recover from a closed cached connection: %v", err)
	}
	newServerConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = newServerConn.Close() })
	if got := string(readTCPFrame(t, newServerConn)); got != "must succeed" {
		t.Fatalf("recovered frame = %q, want %q", got, "must succeed")
	}
	client.mu.Lock()
	cachedConn := client.tcpConnMap[endpointKey]
	client.mu.Unlock()
	if cachedConn == nil {
		t.Fatal("recovered connection was not cached")
	}
}

func TestTCPBindResetEndpointForcesReconnect(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := endpoint.DstToString()

	if err := client.Send([][]byte{[]byte("before reset")}, endpoint); err != nil {
		t.Fatal(err)
	}
	firstConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = firstConn.Close() })
	if got := string(readTCPFrame(t, firstConn)); got != "before reset" {
		t.Fatalf("first frame = %q, want %q", got, "before reset")
	}

	if reset, err := client.ResetEndpoint(endpoint); err != nil {
		t.Fatal(err)
	} else if !reset {
		t.Fatal("reset did not report closing the cached connection")
	}
	if reset, err := client.ResetEndpoint(endpoint); err != nil {
		t.Fatal(err)
	} else if reset {
		t.Fatal("second reset reported closing a connection that was no longer cached")
	}
	waitForTCPCondition(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.tcpConnMap[endpointKey] == nil
	}, "endpoint reset")

	if err := firstConn.SetReadDeadline(time.Now().Add(tcpTestTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := firstConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("reset did not close the first connection")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for reset to close the first connection")
	}

	if err := client.Send([][]byte{[]byte("after reset")}, endpoint); err != nil {
		t.Fatal(err)
	}
	secondConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = secondConn.Close() })
	if got := string(readTCPFrame(t, secondConn)); got != "after reset" {
		t.Fatalf("second frame = %q, want %q", got, "after reset")
	}
}

func TestTCPBindResetEndpointIsScoped(t *testing.T) {
	serverA := listenTCP(t)
	serverB := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpointA, err := client.ParseEndpoint(serverA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpointB, err := client.ParseEndpoint(serverB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Send([][]byte{[]byte("a1")}, endpointA); err != nil {
		t.Fatal(err)
	}
	connA := acceptTCP(t, serverA)
	t.Cleanup(func() { _ = connA.Close() })
	if got := string(readTCPFrame(t, connA)); got != "a1" {
		t.Fatalf("first endpoint A frame = %q, want %q", got, "a1")
	}

	if err := client.Send([][]byte{[]byte("b1")}, endpointB); err != nil {
		t.Fatal(err)
	}
	connB := acceptTCP(t, serverB)
	t.Cleanup(func() { _ = connB.Close() })
	if got := string(readTCPFrame(t, connB)); got != "b1" {
		t.Fatalf("first endpoint B frame = %q, want %q", got, "b1")
	}

	client.mu.Lock()
	cachedB := client.tcpConnMap[endpointB.DstToString()]
	client.mu.Unlock()
	if cachedB == nil {
		t.Fatal("endpoint B connection was not cached")
	}

	if reset, err := client.ResetEndpoint(endpointA); err != nil {
		t.Fatal(err)
	} else if !reset {
		t.Fatal("reset did not report closing endpoint A")
	}
	client.mu.Lock()
	gotA := client.tcpConnMap[endpointA.DstToString()]
	gotB := client.tcpConnMap[endpointB.DstToString()]
	client.mu.Unlock()
	if gotA != nil {
		t.Fatal("endpoint A remained cached after reset")
	}
	if gotB != cachedB {
		t.Fatal("resetting endpoint A replaced or removed endpoint B")
	}

	if err := client.Send([][]byte{[]byte("b2")}, endpointB); err != nil {
		t.Fatal(err)
	}
	if got := string(readTCPFrame(t, connB)); got != "b2" {
		t.Fatalf("second endpoint B frame = %q, want %q", got, "b2")
	}

	if err := client.Send([][]byte{[]byte("a2")}, endpointA); err != nil {
		t.Fatal(err)
	}
	reconnectedA := acceptTCP(t, serverA)
	t.Cleanup(func() { _ = reconnectedA.Close() })
	if got := string(readTCPFrame(t, reconnectedA)); got != "a2" {
		t.Fatalf("reconnected endpoint A frame = %q, want %q", got, "a2")
	}
}

func TestTCPBindEndpointLocksAreScoped(t *testing.T) {
	bind := NewTCPBind().(*TcpBind)
	_, _, unlockA := bind.lockEndpoint("endpoint-a")

	acquiredB := make(chan struct{})
	go func() {
		_, _, unlockB := bind.lockEndpoint("endpoint-b")
		close(acquiredB)
		unlockB()
	}()
	select {
	case <-acquiredB:
	case <-time.After(tcpTestTimeout):
		t.Fatal("endpoint B was blocked by endpoint A")
	}

	acquiredA := make(chan struct{})
	go func() {
		_, _, unlockSecondA := bind.lockEndpoint("endpoint-a")
		close(acquiredA)
		unlockSecondA()
	}()
	select {
	case <-acquiredA:
		t.Fatal("second endpoint A lock acquired before the first was released")
	case <-time.After(20 * time.Millisecond):
	}

	unlockA()
	select {
	case <-acquiredA:
	case <-time.After(tcpTestTimeout):
		t.Fatal("endpoint A remained blocked after release")
	}
}

func TestTCPBindOldConnectionCannotEvictReplacement(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := endpoint.DstToString()

	if err := client.Send([][]byte{[]byte("old")}, endpoint); err != nil {
		t.Fatal(err)
	}
	oldServerConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = oldServerConn.Close() })
	if got := string(readTCPFrame(t, oldServerConn)); got != "old" {
		t.Fatalf("old frame = %q, want %q", got, "old")
	}
	client.mu.Lock()
	oldConn := client.tcpConnMap[endpointKey]
	client.mu.Unlock()
	if oldConn == nil {
		t.Fatal("old connection was not cached")
	}

	replacementRaw, err := net.DialTCP("tcp", nil, server.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	replacement := &tcpConn{conn: replacementRaw}
	replacementServerConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = replacementServerConn.Close() })
	client.mu.Lock()
	client.tcpConnMap[endpointKey] = replacement
	client.mu.Unlock()

	client.invalidateConn(endpointKey, oldConn)
	client.mu.Lock()
	cachedConn := client.tcpConnMap[endpointKey]
	client.mu.Unlock()
	if cachedConn != replacement {
		t.Fatal("old connection cleanup evicted its replacement")
	}
}

func TestTCPBindSerializesConcurrentFrames(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Send([][]byte{[]byte("warmup")}, endpoint); err != nil {
		t.Fatal(err)
	}
	serverConn := acceptTCP(t, server)
	t.Cleanup(func() { _ = serverConn.Close() })
	if got := string(readTCPFrame(t, serverConn)); got != "warmup" {
		t.Fatalf("warmup frame = %q, want %q", got, "warmup")
	}

	const packetCount = 32
	wanted := make(map[string]bool, packetCount)
	var wg sync.WaitGroup
	errs := make(chan error, packetCount)
	for i := 0; i < packetCount; i++ {
		packet := fmt.Sprintf("packet-%02d-%s", i, strings.Repeat("x", 1024))
		wanted[packet] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- client.Send([][]byte{[]byte(packet)}, endpoint)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < packetCount; i++ {
		packet := string(readTCPFrame(t, serverConn))
		if !wanted[packet] {
			t.Fatalf("received malformed or duplicate frame %q", packet)
		}
		delete(wanted, packet)
	}
	if len(wanted) != 0 {
		t.Fatalf("did not receive %d frames", len(wanted))
	}
}

func TestTCPBindCloseIsIdempotentAndReopenable(t *testing.T) {
	bind := NewTCPBind().(*TcpBind)
	t.Cleanup(func() { _ = bind.Close() })
	receive, firstPort, err := bind.Open(freeTCPPort(t))
	if err != nil {
		t.Fatal(err)
	}
	if firstPort == 0 {
		t.Fatal("first Open returned port 0")
	}
	if _, _, err := bind.Open(0); !errors.Is(err, ErrBindAlreadyOpen) {
		t.Fatalf("second Open() error = %v, want %v", err, ErrBindAlreadyOpen)
	}
	bind.mu.Lock()
	bind.fwmark = 123
	bind.mu.Unlock()
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	bind.mu.Lock()
	markAfterClose := bind.fwmark
	bind.mu.Unlock()
	if markAfterClose != 0 {
		t.Fatalf("fwmark after Close() = %d, want 0", markAfterClose)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}

	newReceive, secondPort, err := bind.Open(freeTCPPort(t))
	if err != nil {
		t.Fatal(err)
	}
	if secondPort == 0 {
		t.Fatal("second Open returned port 0")
	}

	bufs := [][]byte{make([]byte, MaxSegmentSize)}
	sizes := make([]int, 1)
	endpoints := make([]Endpoint, 1)
	if _, err := receive[0](bufs, sizes, endpoints); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old receive function error = %v, want %v", err, net.ErrClosed)
	}

	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", secondPort))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send([][]byte{[]byte("reopened")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if n, err := newReceive[0](bufs, sizes, endpoints); err != nil {
		t.Fatal(err)
	} else if n != 1 || string(bufs[0][:sizes[0]]) != "reopened" {
		t.Fatalf("reopened bind received %d unexpected packets", n)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
}

// blockingDial makes every dial of bind wait until release is closed, then
// connect to target. started receives one value per dial.
func blockingDial(bind *TcpBind, target string) (started <-chan struct{}, release chan struct{}, dials *atomic.Int32) {
	startedChan := make(chan struct{}, 16)
	release = make(chan struct{})
	dials = new(atomic.Int32)
	bind.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		startedChan <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if target == "" {
			return nil, errors.New("dial refused")
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, target)
	}
	return startedChan, release, dials
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(tcpTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestTCPBindResetEndpointDoesNotWaitForADial(t *testing.T) {
	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	started, release, _ := blockingDial(client, server.Addr().String())

	sent := make(chan error, 1)
	go func() { sent <- client.Send([][]byte{[]byte("fresh")}, endpoint) }()
	waitForSignal(t, started, "the dial to start")

	resetDone := make(chan struct{})
	go func() {
		if reset, err := client.ResetEndpoint(endpoint); err != nil || reset {
			t.Errorf("reset during a dial = %v, %v; want false, nil", reset, err)
		}
		close(resetDone)
	}()
	waitForSignal(t, resetDone, "the reset, which must not wait for the dial")

	close(release)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	conn := acceptTCP(t, server)
	t.Cleanup(func() { _ = conn.Close() })
	if got := string(readTCPFrame(t, conn)); got != "fresh" {
		t.Fatalf("frame = %q, want %q", got, "fresh")
	}
	if tcpConnectionCount(client) != 1 {
		t.Fatal("the connection dialed during the reset was not kept")
	}
}

func TestTCPBindWaitersShareAFailedDial(t *testing.T) {
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	started, release, dials := blockingDial(client, "")

	results := make(chan error, 2)
	go func() { results <- client.Send([][]byte{[]byte("a")}, endpoint) }()
	waitForSignal(t, started, "the first dial to start")
	go func() { results <- client.Send([][]byte{[]byte("b")}, endpoint) }()
	waitForTCPCondition(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		entry := client.endpointMu[endpoint.DstToString()]
		return entry != nil && entry.refs == 2
	}, "the second send to wait for the dial")

	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			t.Fatal("send over a failed dial succeeded")
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 shared by both sends", got)
	}
}

func TestTCPBindCloseAbortsADial(t *testing.T) {
	client := NewTCPBind().(*TcpBind)
	if _, _, err := client.Open(0); err != nil {
		t.Fatal(err)
	}
	endpoint, err := client.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	started, _, _ := blockingDial(client, "")

	sent := make(chan error, 1)
	go func() { sent <- client.Send([][]byte{[]byte("a")}, endpoint) }()
	waitForSignal(t, started, "the dial to start")
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("send succeeded although the bind was closed")
		}
	case <-time.After(tcpDialTimeout / 2):
		t.Fatal("close did not abort the dial")
	}
}

func TestTCPBindWriteFailsOnAStalledPeer(t *testing.T) {
	saved := tcpWriteTimeout
	tcpWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tcpWriteTimeout = saved })

	server := listenTCP(t)
	client, _, _ := openTCPBind(t)
	endpoint, err := client.ParseEndpoint(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.getConn(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	// accepted, never read
	stalled := acceptTCP(t, server)
	t.Cleanup(func() { _ = stalled.Close() })

	// a typical packet, so the size allowance on top of the timeout is small
	frame := make([]byte, 1400)
	deadline := time.Now().Add(tcpTestTimeout * 3)
	for {
		err := conn.Write([][]byte{frame})
		if err != nil {
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("write to a stalled peer failed with %v, want a timeout", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writes to a stalled peer never timed out")
		}
	}
	if err := conn.Write([][]byte{[]byte("after")}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after a failed one = %v, want net.ErrClosed", err)
	}
}

func TestTCPBindDoesNotListenWithoutAPort(t *testing.T) {
	// what the device does on Down and Up: reopen with the port it got back
	client := NewTCPBind().(*TcpBind)
	port := uint16(0)
	for i := 0; i < 2; i++ {
		_, actualPort, err := client.Open(port)
		if err != nil {
			t.Fatal(err)
		}
		client.mu.Lock()
		listener := client.listener
		client.mu.Unlock()
		if actualPort != 0 || listener != nil {
			t.Fatalf("Open(%d) listens on port %d", port, actualPort)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		port = actualPort
	}
}

func TestTCPBindCapsInboundConnections(t *testing.T) {
	_, _, port := openTCPServerBind(t)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	conns := make([]net.Conn, 0, maxInboundTCPConns+1)
	t.Cleanup(func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	for i := 0; i <= maxInboundTCPConns; i++ {
		conn, err := net.DialTimeout("tcp", address, tcpTestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}

	// exactly the one over the limit gets closed
	var closed atomic.Int32
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := conn.Read(make([]byte, 1)); err != nil {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					closed.Add(1)
				}
			}
		}(conn)
	}
	wg.Wait()
	if closed := closed.Load(); closed != 1 {
		t.Fatalf("%d inbound connections were closed, want 1", closed)
	}
}
