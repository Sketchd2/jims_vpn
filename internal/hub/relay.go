package hub

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

// acl decides which member may talk to which. It is immutable once published.
type acl struct {
	restricted bool
	hubIP      [4]byte
	groups     map[[4]byte][]string // member IP -> groups (restricted mode only)
}

func (a *acl) allow(src, dst [4]byte) bool {
	if !a.restricted {
		return true
	}
	for _, g := range a.groups[src] {
		for _, h := range a.groups[dst] {
			if g == h {
				return true
			}
		}
	}
	return false
}

// loopTun is the hub's "network interface". It never touches the operating
// system: every packet WireGuard decrypts from one member is checked against
// the ACL and handed straight back to WireGuard, which encrypts it for the
// member that owns the destination address. Because each network has its own
// loopTun and its own WireGuard device, there is no path between networks and
// no path from a network to the hub's host.
type loopTun struct {
	mtu    int
	acl    atomic.Pointer[acl]
	q      chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newLoopTun(mtu int) *loopTun {
	t := &loopTun{mtu: mtu, q: make(chan []byte, 2048), events: make(chan tun.Event, 1), closed: make(chan struct{})}
	t.acl.Store(&acl{restricted: true})
	t.events <- tun.EventUp
	return t
}

func (t *loopTun) File() *os.File           { return nil }
func (t *loopTun) MTU() (int, error)        { return t.mtu, nil }
func (t *loopTun) Name() (string, error)    { return "jv-relay", nil }
func (t *loopTun) Events() <-chan tun.Event { return t.events }
func (t *loopTun) BatchSize() int           { return conn.IdealBatchSize }

func (t *loopTun) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

// Write receives packets decrypted from members. WireGuard has already
// verified that the source address belongs to the sending member.
func (t *loopTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	a := t.acl.Load()
	for _, b := range bufs {
		p := b[offset:]
		if len(p) < 20 || p[0]>>4 != 4 {
			continue // IPv4 only inside the tunnels
		}
		var src, dst [4]byte
		copy(src[:], p[12:16])
		copy(dst[:], p[16:20])
		var out []byte
		switch {
		case dst == a.hubIP:
			out = echoReply(p)
		case a.allow(src, dst):
			out = append([]byte(nil), p...)
		}
		if out == nil {
			continue
		}
		select {
		case t.q <- out:
		default: // queue full: drop, like any congested router
		}
	}
	return len(bufs), nil
}

// Read hands queued packets back to WireGuard for encryption.
func (t *loopTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case p := <-t.q:
		sizes[0] = copy(bufs[0][offset:], p)
	}
	n := 1
	for n < len(bufs) {
		select {
		case p := <-t.q:
			sizes[n] = copy(bufs[n][offset:], p)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

// echoReply answers a ping addressed to the hub so members can test their link.
func echoReply(p []byte) []byte {
	ihl := int(p[0]&0x0f) * 4
	if p[9] != 1 || ihl < 20 || len(p) < ihl+8 || p[ihl] != 8 {
		return nil
	}
	if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return nil // fragment
	}
	r := append([]byte(nil), p...)
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	icmp := r[ihl:]
	icmp[0], icmp[2], icmp[3] = 0, 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], ^checksum(icmp))
	return r
}

func checksum(b []byte) uint16 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// relay is one network's WireGuard endpoint on the hub.
type relay struct {
	dev *device.Device
	tun *loopTun
}

func newRelay(name, privB64 string, port, mtu int) (*relay, error) {
	privHex, err := proto.KeyHex(privB64)
	if err != nil {
		return nil, err
	}
	t := newLoopTun(mtu)
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("["+name+"] "+f, a...) },
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, port)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("cannot listen on UDP port %d: %w", port, err)
	}
	return &relay{dev: dev, tun: t}, nil
}

func (r *relay) setPeer(pubB64, ip string) error {
	h, err := proto.KeyHex(pubB64)
	if err != nil {
		return err
	}
	return r.dev.IpcSet(fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", h, ip))
}

func (r *relay) removePeer(pubB64 string) error {
	h, err := proto.KeyHex(pubB64)
	if err != nil {
		return err
	}
	return r.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", h))
}

func (r *relay) stats() map[string]*proto.PeerStat {
	s, err := r.dev.IpcGet()
	if err != nil {
		return map[string]*proto.PeerStat{}
	}
	return proto.ParseStats(s)
}

func (r *relay) close() { r.dev.Close() }

var errNotFound = errors.New("not found")
