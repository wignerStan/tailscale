package magicsock

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/tailscale/health"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/util/eventbus"
	"github.com/sagernet/tailscale/util/usermetric"
)

type recoveryListener struct {
	fail4, fail6   atomic.Bool
	calls4, calls6 atomic.Int32
}

func (l *recoveryListener) ListenPacket(ctx context.Context, network, _ string) (net.PacketConn, error) {
	address, fail, calls := "127.0.0.1:0", &l.fail4, &l.calls4
	if network == "udp6" {
		address, fail, calls = "[::1]:0", &l.fail6, &l.calls6
	}
	calls.Add(1)
	if fail.Load() {
		return nil, errors.New("physical interface temporarily unavailable")
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func recoveryConn(t *testing.T, listener *recoveryListener) *Conn {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	c, err := NewConn(Options{
		Logf: t.Logf, EventBus: bus, NetMon: netmon.NewStatic(),
		HealthTracker: health.NewTracker(bus), Metrics: new(usermetric.Registry),
		DisablePortMapper: true, TestOnlyPacketListener: listener,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.checkNetworkUpDuringTests = true
	t.Cleanup(func() { c.Close() })
	return c
}

func assertRecoveryDelivery(t *testing.T, c *Conn, network string) {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "udp6" {
		address = "[::1]:0"
	}
	sink, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	payload := []byte("native bind recovery")
	if n, err := c.sendUDPNetcheck(payload, sink.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil || n != len(payload) {
		t.Fatalf("send: %d, %v", n, err)
	}
	sink.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	if n, _, err := sink.ReadFrom(buffer); err != nil || string(buffer[:n]) != string(payload) {
		t.Fatalf("receive: %d, %v", n, err)
	}
}

func TestBindRecoverySameNetwork(t *testing.T) {
	listener := new(recoveryListener)
	c := recoveryConn(t, listener)
	listener.fail4.Store(true)
	listener.fail6.Store(true)
	if err := c.rebind(keepCurrentPort); err == nil {
		t.Fatal("expected the transient bind failure")
	}
	listener.fail4.Store(false)
	listener.fail6.Store(false)
	state := c.netMon.InterfaceState()
	delta, err := netmon.NewChangeDelta(state, state, 0, false)
	if err != nil || delta.RebindLikelyRequired {
		t.Fatalf("expected unchanged network state: %v, %v", delta, err)
	}
	// Allow the bounded first retry delay to expire. Like userspaceEngine's
	// minor link-change path, call only ReSTUN, never an explicit Rebind.
	time.Sleep(1100 * time.Millisecond)
	c.ReSTUN("link-change-minor")
	if c.LocalPort() == 0 {
		t.Fatal("same-network recovery left the UDP transport unbound")
	}
	assertRecoveryDelivery(t, c, "udp4")
	assertRecoveryDelivery(t, c, "udp6")
}

func retryDue(c *Conn) {
	for _, ruc := range []*RebindingUDPConn{&c.pconn4, &c.pconn6} {
		ruc.mu.Lock()
		ruc.bindRetryAfter = time.Time{}
		ruc.mu.Unlock()
	}
}

func TestBindRecoveryStartupFailure(t *testing.T) {
	listener := new(recoveryListener)
	listener.fail4.Store(true)
	listener.fail6.Store(true)
	c := recoveryConn(t, listener)
	if c.LocalPort() != 0 {
		t.Fatal("expected an initially unbound socket")
	}
	if n, err := c.sendUDPNetcheck([]byte("lost"), netip.MustParseAddrPort("127.0.0.1:9")); n != 0 || err == nil {
		t.Fatalf("failed bind must not report successful UDP writes: %d, %v", n, err)
	}
	listener.fail4.Store(false)
	listener.fail6.Store(false)
	retryDue(c)
	c.ReSTUN("periodic")
	assertRecoveryDelivery(t, c, "udp4")
	assertRecoveryDelivery(t, c, "udp6")
}

func TestBindRecoveryPreservesHealthyFamily(t *testing.T) {
	for _, late := range []string{"udp4", "udp6"} {
		t.Run(late, func(t *testing.T) {
			listener := new(recoveryListener)
			fail := &listener.fail4
			if late == "udp6" {
				fail = &listener.fail6
			}
			fail.Store(true)
			c := recoveryConn(t, listener)
			healthy := &c.pconn6
			if late == "udp6" {
				healthy = &c.pconn4
			}
			original := healthy.currentConn()
			port := healthy.Port()
			fail.Store(false)
			retryDue(c)
			c.ReSTUN("link-change-minor")
			if healthy.currentConn() != original || healthy.Port() != port {
				t.Fatal("recovering one family disturbed the healthy socket")
			}
			assertRecoveryDelivery(t, c, "udp4")
			assertRecoveryDelivery(t, c, "udp6")
		})
	}
}

func TestBindRecoveryBackoffAndNetworkDown(t *testing.T) {
	listener := new(recoveryListener)
	listener.fail4.Store(true)
	listener.fail6.Store(true)
	c := recoveryConn(t, listener)
	for _, want := range []time.Duration{2, 4, 8, 16, 30, 30} {
		retryDue(c)
		c.retryUnboundSockets()
		c.pconn4.mu.Lock()
		got := c.pconn4.bindRetryDelay
		c.pconn4.mu.Unlock()
		if got != want*time.Second {
			t.Fatalf("retry delay = %v; want %v", got, want*time.Second)
		}
		before := listener.calls4.Load() + listener.calls6.Load()
		for range 20 {
			c.retryUnboundSockets()
		}
		if after := listener.calls4.Load() + listener.calls6.Load(); after != before {
			t.Fatal("repeated discovery bypassed the retry deadline")
		}
	}
	c.SetNetworkUp(false)
	retryDue(c)
	before := listener.calls4.Load() + listener.calls6.Load()
	c.retryUnboundSockets()
	if after := listener.calls4.Load() + listener.calls6.Load(); after != before {
		t.Fatal("retried while the network was down")
	}
}

func TestBindRecoveryDoesNotReopenClosedBind(t *testing.T) {
	listener := new(recoveryListener)
	listener.fail4.Store(true)
	listener.fail6.Store(true)
	c := recoveryConn(t, listener)
	c.pconn4.Close()
	c.pconn6.Close()
	retryDue(c)
	listener.fail4.Store(false)
	listener.fail6.Store(false)
	before := listener.calls4.Load() + listener.calls6.Load()
	c.retryUnboundSockets()
	if after := listener.calls4.Load() + listener.calls6.Load(); after != before {
		t.Fatal("reopened explicitly closed sockets")
	}
}

func TestBindRecoveryConcurrentClose(t *testing.T) {
	listener := new(recoveryListener)
	listener.fail4.Store(true)
	listener.fail6.Store(true)
	c := recoveryConn(t, listener)
	listener.fail4.Store(false)
	listener.fail6.Store(false)
	retryDue(c)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				c.ReSTUN("link-change-minor")
			}
		})
	}
	c.Close()
	wg.Wait()
	before := listener.calls4.Load() + listener.calls6.Load()
	c.ReSTUN("after-close")
	if after := listener.calls4.Load() + listener.calls6.Load(); after != before {
		t.Fatal("opened sockets after connection close")
	}
	if c.pconn4.Port() != 0 || c.pconn6.Port() != 0 {
		t.Fatal("close left a recovered socket open")
	}
}

func TestBindRecoveryLeavesDisabledUDPAlone(t *testing.T) {
	listener := new(recoveryListener)
	c := recoveryConn(t, listener)
	for _, ruc := range []*RebindingUDPConn{&c.pconn4, &c.pconn6} {
		ruc.mu.Lock()
		ruc.closeLocked()
		ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize(), c.controlKnobs)
		ruc.mu.Unlock()
	}
	before := listener.calls4.Load() + listener.calls6.Load()
	c.retryUnboundSockets()
	if after := listener.calls4.Load() + listener.calls6.Load(); after != before {
		t.Fatal("retried an intentionally disabled socket")
	}
}
