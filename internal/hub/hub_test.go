package hub

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

// member is a real WireGuard peer whose "interface" is a loopTun we can
// inject packets into (Write side is unused; we read what arrives via in).
type member struct {
	ip  netip.Addr
	dev *device.Device
	tun *testTun
}

type testTun struct {
	*loopTun
	in chan []byte
}

// Write is called by WireGuard with packets that arrived through the tunnel.
func (t *testTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case t.in <- append([]byte(nil), b[offset:]...):
		default:
		}
	}
	return len(bufs), nil
}

func join(t *testing.T, h *Hub, network string, groups ...string) *member {
	t.Helper()
	_, tok, err := h.CreateCode(network, CodeOpts{Groups: groups, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	jt, err := proto.DecodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	priv := proto.NewPrivateKey()
	resp, err := h.Enroll(proto.EnrollRequest{Code: jt.Code, PublicKey: proto.KeyToB64(proto.PublicKey(priv)), Name: "m"})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := h.network(network)
	tt := &testTun{loopTun: newLoopTun(resp.MTU), in: make(chan []byte, 16)}
	dev := device.NewDevice(tt, conn.NewDefaultBind(), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf})
	privHex, _ := proto.KeyHex(proto.KeyToB64(priv))
	hubHex, _ := proto.KeyHex(resp.HubPublicKey)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s\n", privHex, hubHex, n.Port, n.CIDR)); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &member{ip: netip.MustParsePrefix(resp.Address).Addr(), dev: dev, tun: tt}
}

func ping(src, dst netip.Addr, seq uint16) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:], 28)
	s, d := src.As4(), dst.As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[10:], ^checksum(p[:20]))
	p[20] = 8
	binary.BigEndian.PutUint16(p[26:], seq)
	binary.BigEndian.PutUint16(p[22:], ^checksum(p[20:]))
	return p
}

// send injects a packet as if the member's OS had routed it into the tunnel.
func (m *member) send(p []byte) { m.tun.q <- p }

func (m *member) recv(d time.Duration) []byte {
	select {
	case p := <-m.tun.in:
		return p
	case <-time.After(d):
		return nil
	}
}

func newHub(t *testing.T) *Hub {
	t.Helper()
	dir := t.TempDir()
	if _, err := Init(dir, "127.0.0.1", "127.0.0.1:0", ""); err != nil {
		t.Fatal(err)
	}
	h, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func freePort(t *testing.T, base int) int { return base + int(time.Now().UnixNano()%2000) }

func TestRelay(t *testing.T) {
	h := newHub(t)
	p := freePort(t, 42000)
	if _, err := h.CreateNetwork(NetworkOpts{Name: "flat", Port: p}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateNetwork(NetworkOpts{Name: "locked", Mode: ModeRestricted, Port: p + 1}); err != nil {
		t.Fatal(err)
	}
	n1, _ := h.network("flat")
	n2, _ := h.network("locked")
	if n1.prefix().Overlaps(n2.prefix()) {
		t.Fatal("networks share a subnet")
	}

	a, b := join(t, h, "flat"), join(t, h, "flat")
	x, y, z := join(t, h, "locked", "alice"), join(t, h, "locked", "alice"), join(t, h, "locked", "bob")

	// The hub answers pings, proving the tunnel works end to end.
	a.send(ping(a.ip, n1.hubIP(), 1))
	if r := a.recv(5 * time.Second); r == nil || r[20] != 0 || checksum(r[20:]) != 0xffff {
		t.Fatalf("no valid echo reply from hub: %x", r)
	}
	// Bring every member's session up so the hub knows where to send to.
	for _, m := range []*member{b, x, y, z} {
		n := n2
		if m == b {
			n = n1
		}
		m.send(ping(m.ip, n.hubIP(), 1))
		if m.recv(5*time.Second) == nil {
			t.Fatal("member could not reach hub")
		}
	}

	t.Run("flat network relays between members", func(t *testing.T) {
		a.send(ping(a.ip, b.ip, 2))
		if r := b.recv(3 * time.Second); r == nil || netip.AddrFrom4([4]byte(r[12:16])) != a.ip {
			t.Fatalf("b did not receive a's packet: %x", r)
		}
	})
	t.Run("restricted network relays within a group only", func(t *testing.T) {
		x.send(ping(x.ip, y.ip, 3))
		if y.recv(3*time.Second) == nil {
			t.Fatal("same-group packet was not delivered")
		}
		x.send(ping(x.ip, z.ip, 4))
		if r := z.recv(700 * time.Millisecond); r != nil {
			t.Fatalf("packet crossed groups: %x", r)
		}
	})
	t.Run("regrouping takes effect immediately", func(t *testing.T) {
		zd := n2.Devices[2]
		g := []string{"alice", "bob"}
		if err := h.UpdateDevice("locked", zd.ID, nil, &g); err != nil {
			t.Fatal(err)
		}
		x.send(ping(x.ip, z.ip, 5))
		if z.recv(3*time.Second) == nil {
			t.Fatal("packet not delivered after sharing a group")
		}
	})
	t.Run("networks are isolated from each other", func(t *testing.T) {
		// a (flat) addresses x (locked): its own tunnel refuses the route, and
		// even a forged source cannot get through the other network's relay.
		a.send(ping(a.ip, x.ip, 6))
		x.send(ping(a.ip, y.ip, 7)) // spoofed source from the other network
		if r := x.recv(700 * time.Millisecond); r != nil {
			t.Fatalf("packet crossed networks: %x", r)
		}
		if r := y.recv(300 * time.Millisecond); r != nil {
			t.Fatalf("spoofed packet was relayed: %x", r)
		}
	})
	t.Run("removed device is cut off", func(t *testing.T) {
		if err := h.DeleteDevice("flat", n1.Devices[1].ID); err != nil {
			t.Fatal(err)
		}
		a.send(ping(a.ip, b.ip, 8))
		if r := b.recv(700 * time.Millisecond); r != nil {
			t.Fatalf("removed device still receives: %x", r)
		}
	})
}

func TestCodes(t *testing.T) {
	h := newHub(t)
	if _, err := h.CreateNetwork(NetworkOpts{Name: "n", Port: freePort(t, 45000)}); err != nil {
		t.Fatal(err)
	}
	c, tok, _ := h.CreateCode("n", CodeOpts{MaxUses: 1})
	if _, err := proto.DecodeToken(tok); err != nil {
		t.Fatal(err)
	}
	enroll := func(code string) error {
		_, err := h.Enroll(proto.EnrollRequest{Code: code, PublicKey: proto.KeyToB64(proto.PublicKey(proto.NewPrivateKey()))})
		return err
	}
	if err := enroll(c.Code); err != nil {
		t.Fatal(err)
	}
	if enroll(c.Code) == nil {
		t.Fatal("single-use code worked twice")
	}
	if enroll("") == nil || enroll("nope") == nil {
		t.Fatal("bogus code accepted")
	}
	// State survives a restart.
	h.Close()
	h2, err := Load(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if s := h2.Snapshot(); len(s.Networks) != 1 || len(s.Networks[0].Devices) != 1 || s.Networks[0].Devices[0].IP != "10.77.1.2" {
		t.Fatalf("unexpected state after reload: %+v", s)
	}
}
