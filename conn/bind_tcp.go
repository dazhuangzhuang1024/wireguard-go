package conn

import (
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

const (
	// Keep failed network operations from blocking WireGuard recovery until
	// the kernel's much longer TCP timeout expires.
	tcpDialTimeout  = 5 * time.Second
	tcpWriteTimeout = 5 * time.Second
)

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
}

type tcpConn struct {
	conn      *net.TCPConn
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
		// Mark the connection before closing the socket so writers that are
		// already blocked in WriteTo are interrupted by the close rather than
		// delaying bind shutdown while holding writeMu.
		c.closed.Store(true)
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

func (c *tcpConn) Write(bufs [][]byte) error {
	if err := validateTCPBuffers(bufs); err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout)); err != nil {
		return err
	}

	for _, buf := range bufs {
		var l reqLen
		l.FromLen(len(buf))
		frame := net.Buffers{l[:], buf}
		if _, err := frame.WriteTo(c.conn); err != nil {
			return err
		}
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

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}
}

func (t *TcpBind) lockEndpoint(endpoint string) func() {
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

	entry.mu.Lock()
	return func() {
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
	len      [4]byte
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
		defer t.invalidateConn(endpointKey, conn)
		for {
			data := t.dataPool.Get().(*recvData)
			// read uint32 size header
			_, err := io.ReadFull(conn.conn, data.len[:])
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			l := reqLen(data.len)
			size := l.Len()
			if size < 0 || size > MaxSegmentSize {
				t.dataPool.Put(data)
				return
			}
			// read real data
			_, err = io.ReadFull(conn.conn, data.buff[:size])
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
	for {
		rawConn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		addrPort := rawConn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &StdNetEndpoint{AddrPort: addrPort}
		endpointKey := endpoint.DstToString()
		conn := &tcpConn{conn: rawConn}

		t.mu.Lock()
		if t.closeChan != closeChan {
			t.mu.Unlock()
			_ = conn.Close()
			return
		}
		// A zero mark means policy routing is disabled. On Linux, even
		// setting SO_MARK to zero requires CAP_NET_ADMIN, so leave the
		// default socket option untouched in that case.
		if t.fwmark != 0 {
			if err := setTCPConnMark(rawConn, t.fwmark); err != nil {
				t.mu.Unlock()
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

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	if t.fwmark != 0 {
		if err := setTCPListenerMark(listener, t.fwmark); err != nil {
			_ = listener.Close()
			return nil, 0, err
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

	go t.accept(listener, recvChan, closeChan)
	fn := t.makeReceive(recvChan, closeChan)
	actualPort = uint16(listener.Addr().(*net.TCPAddr).Port)
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

	// Synchronize with getConn so a dial already in progress cannot install a
	// connection immediately after this reset.
	t.connectMu.RLock()
	defer t.connectMu.RUnlock()
	unlockEndpoint := t.lockEndpoint(endpointKey)
	defer unlockEndpoint()

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
	unlockEndpoint := t.lockEndpoint(endpointKey)
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

	dialer := net.Dialer{Timeout: tcpDialTimeout}
	if fwmark != 0 {
		dialer.Control = func(_, _ string, rawConn syscall.RawConn) error {
			return setRawConnMark(rawConn, fwmark)
		}
	}
	raw, err := dialer.Dial("tcp", net.TCPAddrFromAddrPort(stdEndpoint.AddrPort).String())
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
	// If the mark changed while dialing, also clear an old nonzero mark.
	// A socket created with Dialer.Control may still carry the previous mark
	// when SetMark(0) races with the dial.
	if fwmark != t.fwmark || t.fwmark != 0 {
		if err := setTCPConnMark(rawConn, t.fwmark); err != nil {
			t.mu.Unlock()
			_ = conn.Close()
			return nil, err
		}
	}
	t.tcpConnMap[endpointKey] = conn
	t.handleConn(conn, stdEndpoint, recvChan, closeChan)
	t.mu.Unlock()
	return conn, nil
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
