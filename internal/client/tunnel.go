package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

func ifName(network string) string { return "jv-" + network }

type tunnel struct {
	dev         *device.Device
	hubKeyHex   string
	endpoint    string // host:port as configured
	resolved    string // ip:port currently programmed, "" if never resolved
	lastResolve time.Time
	backoff     time.Duration
}

// resolve turns host:port into ip:port, preferring IPv4.
func resolve(hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no address for %s", host)
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			pick = ip
			break
		}
	}
	return net.JoinHostPort(pick.Unmap().String(), port), nil
}

func startTunnel(c *NetConfig) (*tunnel, error) {
	privHex, err := proto.KeyHex(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	hubHex, err := proto.KeyHex(c.HubPublicKey)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return nil, err
	}
	tdev, err := tun.CreateTUN(ifName(c.Network), c.MTU)
	if err != nil {
		return nil, fmt.Errorf("cannot create interface %s: %w", ifName(c.Network), err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("["+c.Network+"] "+f, a...) },
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	t := &tunnel{dev: dev, hubKeyHex: hubHex, endpoint: c.Endpoint, backoff: 15 * time.Second}
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\npersistent_keepalive_interval=%d\n",
		privHex, hubHex, addr.Masked(), c.Keepalive)
	t.lastResolve = time.Now()
	if ep, err := resolve(c.Endpoint); err == nil {
		cfg += "endpoint=" + ep + "\n"
		t.resolved = ep
	} else {
		log.Printf("[%s] cannot resolve hub %s yet, will retry: %v", c.Network, c.Endpoint, err)
	}
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	if err := configureInterface(tdev, c, addr); err != nil {
		dev.Close()
		return nil, err
	}
	return t, nil
}

func (t *tunnel) stat() proto.PeerStat {
	s, err := t.dev.IpcGet()
	if err != nil {
		return proto.PeerStat{}
	}
	if p := proto.ParseStats(s)[t.hubKeyHex]; p != nil {
		return *p
	}
	return proto.PeerStat{}
}

func (t *tunnel) setKeepalive(sec int) error {
	return t.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", t.hubKeyHex, sec))
}

// staleAfter is how old a handshake may be before the link counts as lost.
func staleAfter(keepalive int) time.Duration {
	return time.Duration(190+keepalive) * time.Second
}

// watch re-resolves the hub's name when the link has gone quiet, so a hub
// that changes address (or a device that booted before DNS worked) recovers.
// It generates no traffic at all while the link is healthy.
func (t *tunnel) watch(c *NetConfig) {
	age := staleAfter(c.Keepalive) + 1
	if hs := t.stat().LastHandshake; hs > 0 {
		age = time.Since(time.Unix(hs, 0))
	}
	if t.resolved != "" && age < staleAfter(c.Keepalive) {
		t.backoff = 15 * time.Second
		return
	}
	if t.resolved != "" && c.Keepalive == 0 {
		return // an idle link without keepalive is expected to look stale
	}
	if time.Since(t.lastResolve) < t.backoff {
		return
	}
	t.lastResolve = time.Now()
	if t.backoff *= 2; t.backoff > 15*time.Minute {
		t.backoff = 15 * time.Minute
	}
	ep, err := resolve(t.endpoint)
	if err != nil || ep == t.resolved {
		return
	}
	if err := t.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", t.hubKeyHex, ep)); err == nil {
		log.Printf("[%s] hub endpoint is now %s", c.Network, ep)
		t.resolved = ep
	}
}

func (t *tunnel) close(c *NetConfig) {
	cleanupInterface(c)
	t.dev.Close()
}
