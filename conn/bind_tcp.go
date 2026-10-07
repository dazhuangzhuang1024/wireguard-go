package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	_ Bind             = (*TcpBind)(nil)
	_ EndpointResetter = (*TcpBind)(nil)
)

// MaxSegmentSize ref: device.MaxSegmentSize, we choose the max
const MaxSegmentSize = 65535

// Keep failed network operations from blocking WireGuard recovery until the
// kernel's much longer TCP timeout expires.
const tcpDialTimeout = 5 * time.Second

// A write gets tcpWriteTimeout plus the time to drain the batch at
// tcpMinWriteRate, so a slow link that still makes progress is not mistaken
// for a stalled one. A variable so tests can shorten it.
var tcpWriteTimeout = 5 * time.Second

const tcpMinWriteRate = 16 << 10 // bytes per second

// Peers reach a client over the connections it dials, so inbound connections
// exist only with a configured listen port, and even then are limited.
const maxInboundTCPConns = 64

func NewTCPBind() Bind {
	return &TcpBind{
		tcpConnMap: make(map[string]*tcpConn),
		endpointMu: make(map[string]*endpointMutex),
		dataPool: sync.Pool{
			New: func() any {
				data := &recvData{
					buff: make([]byte, MaxSegmentSize),
				}
				return data
			},
		},
	}
}

type endpointMutex struct {
	mu   sync.Mutex
	refs int
	// dials counts the dials made under mu, and dialErr holds the error of
	// the last one, so callers that waited on mu can share its failure
	dials   atomic.Uint64
	dialErr error
}

type tcpConn struct {
	conn      *net.TCPConn
	inbound   bool
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
}

func validateTCPBuffers(bufs [][]byte) error {
	for _, buf := range bufs {
		if len(buf) > MaxSegmentSize {
			return fmt.Errorf("TCP packet size %d exceeds maximum %d", len(buf), MaxSegmentSize)
		}
	}
	return nil
}

func (c *tcpConn) Close() error {
	c.closeOnce.Do(func() {
		// Closing the socket interrupts a writer blocked in WriteTo; the flag
		// makes writers still queued on writeMu fail fast.
		c.closed.Store(true)
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

func (c *tcpConn) Write(bufs [][]byte) error {
	if err := validateTCPBuffers(bufs); err != nil {
		return err
	}

	// the whole batch in one vectored write
	headers := make([]reqLen, len(bufs))
	frames := make(net.Buffers, 0, 2*len(bufs))
	size := 0
	for i, buf := range bufs {
		headers[i].FromLen(len(buf))
		frames = append(frames, headers[i][:], buf)
		size += len(headers[i]) + len(buf)
	}
	timeout := tcpWriteTimeout + time.Duration(size)*time.Second/tcpMinWriteRate

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		_ = c.Close()
		return err
	}
	if _, err := frames.WriteTo(c.conn); err != nil {
		// a frame may have been cut short, so nothing may follow it
		_ = c.Close()
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Time{})
	return nil
}

type TcpBind struct {
	mu         sync.Mutex
	connectMu  sync.RWMutex
	tcpConnMap map[string]*tcpConn
	endpointMu map[string]*endpointMutex
	listener   *net.TCPListener
	fwmark     uint32
	inbound    atomic.Int32

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}

	// dial replaces the system dialer in tests
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// lockEndpoint also returns the endpoint's dial count from before waiting.
func (t *TcpBind) lockEndpoint(endpoint string) (*endpointMutex, uint64, func()) {
	t.mu.Lock()
	if t.endpointMu == nil {
		t.endpointMu = make(map[string]*endpointMutex)
	}
	entry := t.endpointMu[endpoint]
	if entry == nil {
		entry = new(endpointMutex)
		t.endpointMu[endpoint] = entry
	}
	entry.refs++
	t.mu.Unlock()

	dials := entry.dials.Load()
	entry.mu.Lock()
	return entry, dials, func() {
		entry.mu.Unlock()
		t.mu.Lock()
		entry.refs--
		if entry.refs == 0 && t.endpointMu[endpoint] == entry {
			delete(t.endpointMu, endpoint)
		}
		t.mu.Unlock()
	}
}

type reqLen [4]byte

func (l *reqLen) Len() int {
	return int(l[0]) + int(l[1])<<8 + int(l[2])<<16 + int(l[3])<<24
}

func (l *reqLen) FromLen(len int) {
	l[0] = byte(len & 0xff)
	l[1] = byte(len >> 8 & 0xff)
	l[2] = byte(len >> 16 & 0xff)
	l[3] = byte(len >> 24 & 0xff)
}

type recvData struct {
	buff     []byte
	size     int
	endpoint Endpoint
}

func (t *TcpBind) makeReceive(recvChan <-chan *recvData, closeChan <-chan struct{}) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		select {
		case <-closeChan:
			return 0, net.ErrClosed
		case data := <-recvChan:
			if data == nil {
				return 0, nil
			}
			select {
			case <-closeChan:
				t.dataPool.Put(data)
				return 0, net.ErrClosed
			default:
			}
			sizes[0] = data.size
			copy(bufs[0], data.buff[:sizes[0]])
			eps[0] = data.endpoint
			t.dataPool.Put(data)
			return 1, nil
		}
	}
}

func (t *TcpBind) invalidateConn(endpoint string, conn *tcpConn) {
	t.mu.Lock()
	if t.tcpConnMap[endpoint] == conn {
		delete(t.tcpConnMap, endpoint)
	}
	t.mu.Unlock()
	_ = conn.Close()
}

func (t *TcpBind) handleConn(
	conn *tcpConn,
	endpoint Endpoint,
	recvChan chan<- *recvData,
	closeChan <-chan struct{},
) {
	endpointKey := endpoint.DstToString()
	go func() {
		defer func() {
			t.invalidateConn(endpointKey, conn)
			if conn.inbound {
				t.inbound.Add(-1)
			}
		}()
		for {
			// read uint32 size header, before taking a buffer, so an idle
			// connection does not hold one
			var l reqLen
			if _, err := io.ReadFull(conn.conn, l[:]); err != nil {
				return
			}
			size := l.Len()
			if size < 0 || size > MaxSegmentSize {
				return
			}
			data := t.dataPool.Get().(*recvData)
			// read real data
			_, err := io.ReadFull(conn.conn, data.buff[:size])
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			data.size = size
			data.endpoint = endpoint
			select {
			case <-closeChan:
				t.dataPool.Put(data)
				return
			case recvChan <- data:
			}
		}
	}()
}

func (t *TcpBind) accept(
	listener *net.TCPListener,
	recvChan chan<- *recvData,
	closeChan <-chan struct{},
) {
	var backoff time.Duration
	for {
		rawConn, err := listener.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-closeChan:
				return
			default:
			}
			// e.g. out of file descriptors: retry rather than stop accepting
			// until the next bind update
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if t.inbound.Add(1) > maxInboundTCPConns {
			t.inbound.Add(-1)
			_ = rawConn.Close()
			continue
		}
		addrPort := rawConn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &StdNetEndpoint{AddrPort: addrPort}
		endpointKey := endpoint.DstToString()
		conn := &tcpConn{conn: rawConn, inbound: true}

		t.mu.Lock()
		if t.closeChan != closeChan {
			t.mu.Unlock()
			t.inbound.Add(-1)
			_ = conn.Close()
			return
		}
		// A zero mark means policy routing is disabled. On Linux, even
		// setting SO_MARK to zero requires CAP_NET_ADMIN, so leave the
		// default socket option untouched in that case.
		if t.fwmark != 0 {
			if err := setTCPConnMark(rawConn, t.fwmark); err != nil {
				t.mu.Unlock()
				t.inbound.Add(-1)
				_ = conn.Close()
				continue
			}
		}
		oldConn := t.tcpConnMap[endpointKey]
		t.tcpConnMap[endpointKey] = conn
		t.handleConn(conn, endpoint, recvChan, closeChan)
		t.mu.Unlock()

		if oldConn != nil {
			_ = oldConn.Close()
		}
	}
}

func (t *TcpBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil || t.closeChan != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// A client gets its replies over the connections it dials, so it listens
	// only on a configured port. Port 0 is reported back for none, so the
	// device asks for none again when it reopens the bind.
	var listener *net.TCPListener
	if port != 0 {
		listener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
		if err != nil {
			return nil, 0, err
		}
		if t.fwmark != 0 {
			if err := setTCPListenerMark(listener, t.fwmark); err != nil {
				_ = listener.Close()
				return nil, 0, err
			}
		}
	}
	recvChan := make(chan *recvData)
	closeChan := make(chan struct{})
	t.listener = listener
	t.recvChan = recvChan
	t.closeChan = closeChan
	if t.tcpConnMap == nil {
		t.tcpConnMap = make(map[string]*tcpConn)
	}

	if listener != nil {
		go t.accept(listener, recvChan, closeChan)
		actualPort = uint16(listener.Addr().(*net.TCPAddr).Port)
	}
	fn := t.makeReceive(recvChan, closeChan)
	return []ReceiveFunc{fn}, actualPort, nil
}

func (t *TcpBind) Close() error {
	t.mu.Lock()
	// BindUpdate reapplies a nonzero device mark after Open. Clearing the
	// cached value here also handles a mark changed to zero while the device
	// was down, when Device.BindSetMark cannot call into the closed bind.
	t.fwmark = 0
	if t.listener == nil && t.closeChan == nil {
		t.mu.Unlock()
		return nil
	}

	listener := t.listener
	closeChan := t.closeChan
	connections := make([]*tcpConn, 0, len(t.tcpConnMap))
	for _, conn := range t.tcpConnMap {
		connections = append(connections, conn)
	}
	t.tcpConnMap = make(map[string]*tcpConn)
	t.listener = nil
	t.recvChan = nil
	t.closeChan = nil
	if closeChan != nil {
		close(closeChan)
	}
	t.mu.Unlock()

	var firstErr error
	if listener != nil {
		if err := listener.Close(); err != nil {
			firstErr = err
		}
	}
	for _, conn := range connections {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *TcpBind) ResetEndpoint(endpoint Endpoint) (bool, error) {
	if _, ok := endpoint.(*StdNetEndpoint); !ok {
		return false, ErrWrongEndpointType
	}
	endpointKey := endpoint.DstToString()

	// Never waits for a dial in progress: the caller holds the peer's handshake
	// lock, and a connection dialed meanwhile is a fresh one anyway, which is
	// all a reset is after.
	t.mu.Lock()
	conn := t.tcpConnMap[endpointKey]
	if conn != nil {
		delete(t.tcpConnMap, endpointKey)
	}
	t.mu.Unlock()

	if conn == nil {
		return false, nil
	}
	return true, conn.Close()
}

func (t *TcpBind) getConn(endpoint Endpoint, rejected *tcpConn) (*tcpConn, error) {
	stdEndpoint, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return nil, ErrWrongEndpointType
	}
	endpointKey := stdEndpoint.DstToString()

	t.mu.Lock()
	if t.closeChan == nil {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if conn := t.tcpConnMap[endpointKey]; conn != nil && conn != rejected {
		t.mu.Unlock()
		return conn, nil
	}
	t.mu.Unlock()

	// Serialize cache misses for this endpoint while allowing unrelated peers
	// to connect and recover independently.
	t.connectMu.RLock()
	defer t.connectMu.RUnlock()
	entry, dialsBefore, unlockEndpoint := t.lockEndpoint(endpointKey)
	defer unlockEndpoint()

	t.mu.Lock()
	if t.closeChan == nil {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if conn := t.tcpConnMap[endpointKey]; conn != nil && conn != rejected {
		t.mu.Unlock()
		return conn, nil
	}
	recvChan := t.recvChan
	closeChan := t.closeChan
	fwmark := t.fwmark
	t.mu.Unlock()

	// A dial that ended while this caller waited already answered for it:
	// failing right away beats another timeout under the device locks the
	// caller holds.
	if entry.dials.Load() != dialsBefore && entry.dialErr != nil {
		return nil, entry.dialErr
	}
	raw, err := t.dialEndpoint(stdEndpoint, fwmark, closeChan)
	entry.dialErr = err
	entry.dials.Add(1)
	if err != nil {
		return nil, err
	}
	rawConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("TCP dial returned %T, want *net.TCPConn", raw)
	}
	conn := &tcpConn{conn: rawConn}

	t.mu.Lock()
	if t.closeChan != closeChan {
		t.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if current := t.tcpConnMap[endpointKey]; current != nil && current != rejected {
		t.mu.Unlock()
		_ = conn.Close()
		return current, nil
	}
	// The mark was applied while dialing, and connectMu keeps it from
	// changing until this connection is installed.
	t.tcpConnMap[endpointKey] = conn
	t.handleConn(conn, stdEndpoint, recvChan, closeChan)
	t.mu.Unlock()
	return conn, nil
}

func (t *TcpBind) dialEndpoint(endpoint *StdNetEndpoint, fwmark uint32, closeChan <-chan struct{}) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	defer cancel()
	// Close aborts a dial in progress instead of waiting out its timeout.
	go func() {
		select {
		case <-closeChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	dial := t.dial
	if dial == nil {
		var dialer net.Dialer
		if fwmark != 0 {
			dialer.Control = func(_, _ string, rawConn syscall.RawConn) error {
				return setRawConnMark(rawConn, fwmark)
			}
		}
		dial = dialer.DialContext
	}
	return dial(ctx, "tcp", net.TCPAddrFromAddrPort(endpoint.AddrPort).String())
}

func (t *TcpBind) Send(bufs [][]byte, endpoint Endpoint) error {
	if err := validateTCPBuffers(bufs); err != nil {
		return err
	}

	var rejected *tcpConn
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := t.getConn(endpoint, rejected)
		if err != nil {
			return err
		}
		if err := conn.Write(bufs); err != nil {
			rejected = conn
			t.invalidateConn(endpoint.DstToString(), conn)
			if attempt == 0 {
				continue
			}
			return err
		}
		return nil
	}
	return net.ErrClosed
}

func (t *TcpBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
