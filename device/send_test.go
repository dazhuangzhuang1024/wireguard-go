package device

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type recordingResetBind struct {
	mu     sync.Mutex
	events []string
}

func (b *recordingResetBind) record(event string) {
	b.mu.Lock()
	b.events = append(b.events, event)
	b.mu.Unlock()
}

func (b *recordingResetBind) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.events...)
}

func (b *recordingResetBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, 0, nil
}

func (b *recordingResetBind) Close() error { return nil }

func (b *recordingResetBind) SetMark(uint32) error { return nil }

func (b *recordingResetBind) Send([][]byte, conn.Endpoint) error {
	b.record("send")
	return nil
}

func (b *recordingResetBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}, nil
}

func (b *recordingResetBind) BatchSize() int { return 1 }

func (b *recordingResetBind) ResetEndpoint(conn.Endpoint) (bool, error) {
	b.record("reset")
	return true, nil
}

func newHandshakeRetryPeer(t *testing.T) (*Peer, *recordingResetBind) {
	t.Helper()
	bind := new(recordingResetBind)
	tun := tuntest.NewChannelTUN()
	tunDevice := tun.TUN()
	<-tunDevice.Events()
	device := NewDevice(tunDevice, bind, NewLogger(LogLevelSilent, ""))
	t.Cleanup(device.Close)

	localKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := device.SetPrivateKey(localKey); err != nil {
		t.Fatal(err)
	}
	peer, err := device.NewPeer(remoteKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer.Lock()
	peer.endpoint = &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}
	peer.Unlock()
	if _, err := device.CreateMessageInitiation(peer); err != nil {
		t.Fatal(err)
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-RekeyTimeout - time.Second)
	peer.handshake.mutex.Unlock()
	return peer, bind
}

func TestHandshakeRetryResetsEndpointBeforeSend(t *testing.T) {
	peer, bind := newHandshakeRetryPeer(t)
	if err := peer.sendHandshakeInitiation(true, true); err != nil {
		t.Fatal(err)
	}
	events := bind.snapshot()
	if len(events) != 2 || events[0] != "reset" || events[1] != "send" {
		t.Fatalf("retry events = %v, want [reset send]", events)
	}
}

func TestCompletedHandshakeRetryDoesNotResetEndpoint(t *testing.T) {
	peer, bind := newHandshakeRetryPeer(t)
	peer.timers.handshakeAttempts.Store(4)
	peer.handshake.mutex.Lock()
	peer.handshake.state = handshakeZeroed
	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{created: time.Now()}
	peer.keypairs.Unlock()
	peer.handshake.mutex.Unlock()

	if err := peer.sendHandshakeInitiation(true, true); err != nil {
		t.Fatal(err)
	}
	if events := bind.snapshot(); len(events) != 0 {
		t.Fatalf("completed handshake produced events %v, want none", events)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != 4 {
		t.Fatalf("stale retry changed handshake attempts to %d, want 4", got)
	}
	peer.timers.endpointReset.Lock()
	lastReset := peer.timers.endpointReset.last
	peer.timers.endpointReset.Unlock()
	if !lastReset.IsZero() {
		t.Fatalf("stale retry consumed endpoint reset throttle at %v", lastReset)
	}
}

func TestSimultaneousInitiationUnconfirmedResponderStillRetries(t *testing.T) {
	localBind := new(recordingResetBind)
	localTUN := tuntest.NewChannelTUN()
	localTUNDevice := localTUN.TUN()
	<-localTUNDevice.Events()
	localDevice := NewDevice(localTUNDevice, localBind, NewLogger(LogLevelSilent, ""))
	t.Cleanup(localDevice.Close)

	remoteTUN := tuntest.NewChannelTUN()
	remoteTUNDevice := remoteTUN.TUN()
	<-remoteTUNDevice.Events()
	remoteDevice := NewDevice(remoteTUNDevice, new(recordingResetBind), NewLogger(LogLevelSilent, ""))
	t.Cleanup(remoteDevice.Close)

	localKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := localDevice.SetPrivateKey(localKey); err != nil {
		t.Fatal(err)
	}
	if err := remoteDevice.SetPrivateKey(remoteKey); err != nil {
		t.Fatal(err)
	}
	localPeer, err := localDevice.NewPeer(remoteKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	remotePeer, err := remoteDevice.NewPeer(localKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	localPeer.Lock()
	localPeer.endpoint = &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}
	localPeer.Unlock()
	localPeer.Start()

	// Both peers initiate. The local peer then consumes the remote initiation
	// and becomes a responder, abandoning its initiator handshake state.
	if _, err := localDevice.CreateMessageInitiation(localPeer); err != nil {
		t.Fatal(err)
	}
	remoteInitiation, err := remoteDevice.CreateMessageInitiation(remotePeer)
	if err != nil {
		t.Fatal(err)
	}
	if peer := localDevice.ConsumeMessageInitiation(remoteInitiation); peer != localPeer {
		t.Fatal("local peer did not consume the simultaneous remote initiation")
	}
	if _, err := localDevice.CreateMessageResponse(localPeer); err != nil {
		t.Fatal(err)
	}
	if err := localPeer.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}

	localPeer.handshake.mutex.Lock()
	if localPeer.handshake.state != handshakeZeroed {
		localPeer.handshake.mutex.Unlock()
		t.Fatal("responder handshake state was not zeroed")
	}
	localPeer.handshake.lastSentHandshake = time.Now().Add(-RekeyTimeout - time.Second)
	localPeer.handshake.mutex.Unlock()
	if localPeer.keypairs.Current() != nil {
		t.Fatal("unconfirmed responder key unexpectedly became current")
	}
	if localPeer.keypairs.next.Load() == nil {
		t.Fatal("responder key was not staged for confirmation")
	}

	// Simulate loss of the response and confirmation packet. The retransmit
	// callback must start a fresh initiation instead of treating zeroed as done.
	expiredRetransmitHandshake(localPeer)
	if events := localBind.snapshot(); len(events) != 2 || events[0] != "reset" || events[1] != "send" {
		t.Fatalf("unconfirmed responder retry events = %v, want [reset send]", events)
	}
	if got := localPeer.timers.handshakeAttempts.Load(); got != 1 {
		t.Fatalf("unconfirmed responder retry attempts = %d, want 1", got)
	}
}

func TestRateLimitedHandshakeRetryIsRescheduled(t *testing.T) {
	peer, bind := newHandshakeRetryPeer(t)
	peer.device.state.state.Store(uint32(deviceStateUp))
	peer.Start()

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()
	if err := peer.sendHandshakeInitiation(true, true); err != nil {
		t.Fatal(err)
	}
	if events := bind.snapshot(); len(events) != 0 {
		t.Fatalf("rate-limited retry produced events %v, want none", events)
	}
	if !peer.timers.retransmitHandshake.IsPending() {
		t.Fatal("rate-limited retry was not rescheduled")
	}
}

func TestNewHandshakeClearsAttemptsOnlyAfterInitiationIsCreated(t *testing.T) {
	peer, bind := newHandshakeRetryPeer(t)
	peer.timers.handshakeAttempts.Store(3)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != 3 {
		t.Fatalf("skipped initiation cleared attempts: got %d, want 3", got)
	}
	if events := bind.snapshot(); len(events) != 0 {
		t.Fatalf("skipped initiation produced events %v, want none", events)
	}

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-RekeyTimeout - time.Second)
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != 0 {
		t.Fatalf("created initiation left attempts at %d, want 0", got)
	}
	if events := bind.snapshot(); len(events) != 1 || events[0] != "send" {
		t.Fatalf("created initiation events = %v, want [send]", events)
	}
}
