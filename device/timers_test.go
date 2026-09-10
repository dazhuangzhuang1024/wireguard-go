package device

import (
	"testing"
	"time"
)

func TestShouldResetEndpointOnHandshakeRetry(t *testing.T) {
	peer := new(Peer)
	started := time.Now()
	if !peer.shouldResetEndpointOnHandshakeRetry(started) {
		t.Fatal("first handshake retry should reset the endpoint")
	}
	if peer.shouldResetEndpointOnHandshakeRetry(started.Add(endpointResetRetryInterval - time.Nanosecond)) {
		t.Fatal("endpoint reset was not throttled within the retry interval")
	}
	if !peer.shouldResetEndpointOnHandshakeRetry(started.Add(endpointResetRetryInterval)) {
		t.Fatal("endpoint reset remained throttled after the retry interval")
	}

	peer.clearEndpointResetTime()
	if !peer.shouldResetEndpointOnHandshakeRetry(started.Add(endpointResetRetryInterval + time.Second)) {
		t.Fatal("clearing the endpoint reset time should allow an immediate reset")
	}
}
