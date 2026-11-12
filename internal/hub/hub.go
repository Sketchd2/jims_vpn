// Package hub implements the jimsvpn hub: the control plane that enrols
// devices and the WireGuard relay that carries their traffic.
package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

const (
	ModeFlat       = "flat"       // every member reaches every member
	ModeRestricted = "restricted" // members reach only members sharing a group
)

type State struct {
	PublicHost   string `json:"public_host"`  // name or IP that devices use to reach this hub
	APIListen    string `json:"api_listen"`   // enrolment API (HTTPS), reachable from the internet
	AdminListen  string `json:"admin_listen"` // web admin; empty disables it
	AdminTLS     bool   `json:"admin_tls"`    // serve the web admin over HTTPS
	TLSCert      string `json:"tls_cert"`     // relative to the state dir unless absolute
	TLSKey       string `json:"tls_key"`
	TLSPublicCA  bool   `json:"tls_public_ca"` // certificate is from a public CA: tokens then carry no pin
	PasswordHash string `json:"password_hash"`

	Networks []*Network `json:"networks"`
}

type Network struct {
	Name       string    `json:"name"`
	CIDR       string    `json:"cidr"`
	Port       int       `json:"port"`
	Mode       string    `json:"mode"`
	MTU        int       `json:"mtu"`
	Keepalive  int       `json:"keepalive"`
	PrivateKey string    `json:"private_key"`
	Devices    []*Device `json:"devices"`
	Codes      []*Code   `json:"codes"`
}

type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OS        string    `json:"os"`
	PublicKey string    `json:"public_key"`
	IP        string    `json:"ip"`
	Groups    []string  `json:"groups"`
	TokenHash string    `json:"token_hash"`
	Created   time.Time `json:"created"`
}

type Code struct {
	Code    string    `json:"code"`
	Groups  []string  `json:"groups"`
	MaxUses int       `json:"max_uses"` // 0 = unlimited
	Uses    int       `json:"uses"`
	Expires time.Time `json:"expires"` // zero = never
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
}

func (c *Code) valid(now time.Time) bool {
	return (c.MaxUses == 0 || c.Uses < c.MaxUses) && (c.Expires.IsZero() || now.Before(c.Expires))
}

func (n *Network) prefix() netip.Prefix { return netip.MustParsePrefix(n.CIDR) }
func (n *Network) hubIP() netip.Addr    { return n.prefix().Addr().Next() }

type Hub struct {
	mu          sync.Mutex
	dir         string
	st          *State
	relays      map[string]*relay
	fingerprint string
	sessions    map[string]time.Time
	loginMu     sync.Mutex
}

func statePath(dir string) string { return filepath.Join(dir, "hub.json") }

// Init creates a new hub state directory and returns the generated admin password.
func Init(dir, publicHost, apiListen, adminListen string) (string, error) {
	if publicHost == "" {
		return "", errors.New("a public host name or IP is required")
	}
	if _, err := os.Stat(statePath(dir)); err == nil {
		return "", fmt.Errorf("%s already exists", statePath(dir))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	pw := proto.RandomToken(12)
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	st := &State{PublicHost: publicHost, APIListen: apiListen, AdminListen: adminListen,
		TLSCert: "tls.crt", TLSKey: "tls.key", PasswordHash: string(hash)}
	if err := writeSelfSigned(dir, publicHost); err != nil {
		return "", err
	}
	h := &Hub{dir: dir, st: st}
	return pw, h.save()
}

func writeSelfSigned(dir, host string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "jimsvpn hub " + host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
}

// Load reads the state and starts a relay for every network.
func Load(dir string) (*Hub, error) {
	b, err := os.ReadFile(statePath(dir))
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", statePath(dir), err)
	}
	h := &Hub{dir: dir, st: st, relays: map[string]*relay{}, sessions: map[string]time.Time{}}
	if !st.TLSPublicCA {
		pemBytes, err := os.ReadFile(h.path(st.TLSCert))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(pemBytes)
		if blk == nil {
			return nil, fmt.Errorf("%s: no certificate found", h.path(st.TLSCert))
		}
		sum := sha256.Sum256(blk.Bytes)
		h.fingerprint = hex.EncodeToString(sum[:])
	}
	for _, n := range st.Networks {
		if err := h.startRelay(n); err != nil {
			h.Close()
			return nil, fmt.Errorf("network %s: %w", n.Name, err)
		}
	}
	return h, nil
}

func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.relays {
		r.close()
	}
	h.relays = map[string]*relay{}
}

func (h *Hub) path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(h.dir, p)
}

func (h *Hub) save() error {
	b, _ := json.MarshalIndent(h.st, "", "  ")
	tmp := statePath(h.dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(h.dir))
}

func (h *Hub) startRelay(n *Network) error {
	r, err := newRelay(n.Name, n.PrivateKey, n.Port, n.MTU)
	if err != nil {
		return err
	}
	for _, d := range n.Devices {
		if err := r.setPeer(d.PublicKey, d.IP); err != nil {
			r.close()
			return err
		}
	}
	h.relays[n.Name] = r
	h.applyACL(n)
	return nil
}

func (h *Hub) applyACL(n *Network) {
	r := h.relays[n.Name]
	if r == nil {
		return
	}
	a := &acl{restricted: n.Mode == ModeRestricted, hubIP: n.hubIP().As4(), groups: map[[4]byte][]string{}}
	for _, d := range n.Devices {
		if ip, err := netip.ParseAddr(d.IP); err == nil && len(d.Groups) > 0 {
			a.groups[ip.As4()] = append([]string(nil), d.Groups...)
		}
	}
	r.tun.acl.Store(a)
}

func (h *Hub) network(name string) (*Network, error) {
	for _, n := range h.st.Networks {
		if n.Name == name {
			return n, nil
		}
	}
	return nil, fmt.Errorf("network %q: %w", name, errNotFound)
}

type NetworkOpts struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	CIDR      string `json:"cidr"`
	Port      int    `json:"port"`
	MTU       int    `json:"mtu"`
	Keepalive *int   `json:"keepalive"`
}

func (h *Hub) CreateNetwork(o NetworkOpts) (*Network, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !proto.NetworkNameRE.MatchString(o.Name) {
		return nil, errors.New("network name must be 1-12 characters: a-z, 0-9 and -")
	}
	if _, err := h.network(o.Name); err == nil {
		return nil, fmt.Errorf("network %q already exists", o.Name)
	}
	n := &Network{Name: o.Name, Mode: o.Mode, MTU: o.MTU, Port: o.Port, Keepalive: proto.DefaultKeepalive,
		PrivateKey: proto.KeyToB64(proto.NewPrivateKey()), Devices: []*Device{}, Codes: []*Code{}}
	if n.Mode == "" {
		n.Mode = ModeFlat
	}
	if n.Mode != ModeFlat && n.Mode != ModeRestricted {
		return nil, errors.New("mode must be flat or restricted")
	}
	if n.MTU == 0 {
		n.MTU = proto.DefaultMTU
	}
	if n.MTU < 576 || n.MTU > 1420 {
		return nil, errors.New("mtu must be between 576 and 1420")
	}
	if o.Keepalive != nil {
		if *o.Keepalive < 0 || *o.Keepalive > 3600 {
			return nil, errors.New("keepalive must be 0-3600 seconds")
		}
		n.Keepalive = *o.Keepalive
	}
	var used []netip.Prefix
	ports := map[int]bool{}
	for _, e := range h.st.Networks {
		used = append(used, e.prefix())
		ports[e.Port] = true
	}
	overlaps := func(p netip.Prefix) bool {
		for _, u := range used {
			if u.Overlaps(p) {
				return true
			}
		}
		return false
	}
	if o.CIDR == "" {
		for i := 1; i < 255 && n.CIDR == ""; i++ {
			if p := netip.MustParsePrefix(fmt.Sprintf("10.77.%d.0/24", i)); !overlaps(p) {
				n.CIDR = p.String()
			}
		}
		if n.CIDR == "" {
			return nil, errors.New("no free subnet left; specify one")
		}
	} else {
		p, err := netip.ParsePrefix(o.CIDR)
		if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 || !p.Addr().IsPrivate() {
			return nil, errors.New("subnet must be a private IPv4 range between /16 and /29, e.g. 10.20.30.0/24")
		}
		p = p.Masked()
		if overlaps(p) {
			return nil, errors.New("subnet overlaps another network on this hub")
		}
		n.CIDR = p.String()
	}
	if n.Port == 0 {
		for n.Port = 51820; ports[n.Port]; n.Port++ {
		}
	} else if n.Port < 1 || n.Port > 65535 || ports[n.Port] {
		return nil, errors.New("UDP port is invalid or already used by another network")
	}
	if err := h.startRelay(n); err != nil {
		return nil, err
	}
	h.st.Networks = append(h.st.Networks, n)
	return n, h.save()
}

func (h *Hub) UpdateNetwork(name string, mode *string, keepalive *int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.network(name)
	if err != nil {
		return err
	}
	if mode != nil {
		if *mode != ModeFlat && *mode != ModeRestricted {
			return errors.New("mode must be flat or restricted")
		}
		n.Mode = *mode
	}
	if keepalive != nil {
		if *keepalive < 0 || *keepalive > 3600 {
			return errors.New("keepalive must be 0-3600 seconds")
		}
		n.Keepalive = *keepalive
	}
	h.applyACL(n)
	return h.save()
}

func (h *Hub) DeleteNetwork(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, n := range h.st.Networks {
		if n.Name == name {
			if r := h.relays[name]; r != nil {
				r.close()
				delete(h.relays, name)
			}
			h.st.Networks = append(h.st.Networks[:i], h.st.Networks[i+1:]...)
			return h.save()
		}
	}
	return fmt.Errorf("network %q: %w", name, errNotFound)
}

type CodeOpts struct {
	Groups       []string `json:"groups"`
	MaxUses      int      `json:"max_uses"`
	ExpiresHours float64  `json:"expires_hours"` // 0 = never
	Note         string   `json:"note"`
}

func (h *Hub) CreateCode(network string, o CodeOpts) (*Code, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.network(network)
	if err != nil {
		return nil, "", err
	}
	if o.MaxUses < 0 || o.ExpiresHours < 0 {
		return nil, "", errors.New("uses and expiry cannot be negative")
	}
	c := &Code{Code: proto.RandomToken(18), Groups: cleanGroups(o.Groups), MaxUses: o.MaxUses, Note: trim(o.Note, 100), Created: time.Now().UTC()}
	if o.ExpiresHours > 0 {
		c.Expires = time.Now().Add(time.Duration(o.ExpiresHours * float64(time.Hour))).UTC()
	}
	n.Codes = append(n.Codes, c)
	return c, h.token(c), h.save()
}

func (h *Hub) token(c *Code) string {
	_, port, _ := net.SplitHostPort(h.st.APIListen)
	return proto.JoinToken{Hub: "https://" + net.JoinHostPort(h.st.PublicHost, port), Fingerprint: h.fingerprint, Code: c.Code}.Encode()
}

func (h *Hub) DeleteCode(network, code string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.network(network)
	if err != nil {
		return err
	}
	for i, c := range n.Codes {
		if c.Code == code {
			n.Codes = append(n.Codes[:i], n.Codes[i+1:]...)
			return h.save()
		}
	}
	return fmt.Errorf("code: %w", errNotFound)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (h *Hub) Enroll(req proto.EnrollRequest) (*proto.EnrollResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := proto.KeyHex(req.PublicKey); err != nil {
		return nil, err
	}
	var n *Network
	var code *Code
	for _, nn := range h.st.Networks {
		for _, c := range nn.Codes {
			if c.Code == req.Code && req.Code != "" {
				n, code = nn, c
			}
		}
	}
	if code == nil || !code.valid(time.Now()) {
		return nil, errors.New("join code is invalid, expired or used up")
	}
	usedIP := map[netip.Addr]bool{n.hubIP(): true}
	usedName := map[string]bool{}
	for _, d := range n.Devices {
		if d.PublicKey == req.PublicKey {
			return nil, errors.New("this key is already enrolled")
		}
		usedIP[netip.MustParseAddr(d.IP)] = true
		usedName[d.Name] = true
	}
	pfx := n.prefix()
	var ip netip.Addr
	for a := n.hubIP().Next(); pfx.Contains(a) && pfx.Contains(a.Next()); a = a.Next() { // skips broadcast
		if !usedIP[a] {
			ip = a
			break
		}
	}
	if !ip.IsValid() {
		return nil, errors.New("network is full")
	}
	name := cleanName(req.Name)
	for base, i := name, 2; usedName[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	tok := proto.RandomToken(24)
	d := &Device{ID: proto.RandomToken(4), Name: name, OS: trim(req.OS, 40), PublicKey: req.PublicKey, IP: ip.String(),
		Groups: append([]string{}, code.Groups...), TokenHash: hashToken(tok), Created: time.Now().UTC()}
	if err := h.relays[n.Name].setPeer(d.PublicKey, d.IP); err != nil {
		return nil, err
	}
	n.Devices = append(n.Devices, d)
	code.Uses++
	h.applyACL(n)
	if err := h.save(); err != nil {
		return nil, err
	}
	return &proto.EnrollResponse{
		Network: n.Name, Address: netip.PrefixFrom(ip, pfx.Bits()).String(), HubIP: n.hubIP().String(),
		Endpoint:     net.JoinHostPort(h.st.PublicHost, fmt.Sprint(n.Port)),
		HubPublicKey: proto.KeyToB64(proto.PublicKey(mustKey(n.PrivateKey))),
		MTU:          n.MTU, Keepalive: n.Keepalive, DeviceID: d.ID, DeviceToken: tok,
	}, nil
}

func (h *Hub) byToken(tok string) (*Network, *Device) {
	want := hashToken(tok)
	for _, n := range h.st.Networks {
		for _, d := range n.Devices {
			if d.TokenHash == want {
				return n, d
			}
		}
	}
	return nil, nil
}

// Peers lists the devices the caller is able to reach.
func (h *Hub) Peers(tok string) ([]proto.Peer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, me := h.byToken(tok)
	if me == nil {
		return nil, errors.New("this device is no longer a member of the network")
	}
	r := h.relays[n.Name]
	a := r.tun.acl.Load()
	stats := r.stats()
	meIP := netip.MustParseAddr(me.IP).As4()
	out := []proto.Peer{{Name: "hub", IP: n.hubIP().String()}}
	for _, d := range n.Devices {
		if d != me && !a.allow(meIP, netip.MustParseAddr(d.IP).As4()) {
			continue
		}
		p := proto.Peer{Name: d.Name, IP: d.IP, OS: d.OS, Self: d == me}
		if kh, err := proto.KeyHex(d.PublicKey); err == nil && stats[kh] != nil {
			p.LastSeen = stats[kh].LastHandshake
		}
		out = append(out, p)
	}
	return out, nil
}

func (h *Hub) Leave(tok string) error {
	h.mu.Lock()
	n, d := h.byToken(tok)
	h.mu.Unlock()
	if d == nil {
		return nil
	}
	return h.DeleteDevice(n.Name, d.ID)
}

func (h *Hub) device(network, id string) (*Network, *Device, int, error) {
	n, err := h.network(network)
	if err != nil {
		return nil, nil, 0, err
	}
	for i, d := range n.Devices {
		if d.ID == id {
			return n, d, i, nil
		}
	}
	return nil, nil, 0, fmt.Errorf("device: %w", errNotFound)
}

func (h *Hub) UpdateDevice(network, id string, name *string, groups *[]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, d, _, err := h.device(network, id)
	if err != nil {
		return err
	}
	if name != nil {
		d.Name = cleanName(*name)
	}
	if groups != nil {
		d.Groups = cleanGroups(*groups)
	}
	h.applyACL(n)
	return h.save()
}

func (h *Hub) DeleteDevice(network, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, d, i, err := h.device(network, id)
	if err != nil {
		return err
	}
	if r := h.relays[n.Name]; r != nil {
		r.removePeer(d.PublicKey)
	}
	n.Devices = append(n.Devices[:i], n.Devices[i+1:]...)
	h.applyACL(n)
	return h.save()
}

func (h *Hub) SetPassword(pw string) error {
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.PasswordHash = string(hash)
	h.sessions = map[string]time.Time{}
	return h.save()
}

// Views returned by the admin API (never include keys or token hashes).
type DeviceView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	OS       string   `json:"os"`
	IP       string   `json:"ip"`
	Groups   []string `json:"groups"`
	Created  int64    `json:"created"`
	LastSeen int64    `json:"last_seen"`
	Endpoint string   `json:"endpoint"`
	Rx       int64    `json:"rx"`
	Tx       int64    `json:"tx"`
}

type CodeView struct {
	Code    string   `json:"code"`
	Token   string   `json:"token"`
	Groups  []string `json:"groups"`
	MaxUses int      `json:"max_uses"`
	Uses    int      `json:"uses"`
	Expires int64    `json:"expires"`
	Note    string   `json:"note"`
	Valid   bool     `json:"valid"`
}

type NetworkView struct {
	Name      string       `json:"name"`
	CIDR      string       `json:"cidr"`
	HubIP     string       `json:"hub_ip"`
	Port      int          `json:"port"`
	Mode      string       `json:"mode"`
	MTU       int          `json:"mtu"`
	Keepalive int          `json:"keepalive"`
	Devices   []DeviceView `json:"devices"`
	Codes     []CodeView   `json:"codes"`
}

type Snapshot struct {
	Version    string        `json:"version"`
	PublicHost string        `json:"public_host"`
	Now        int64         `json:"now"`
	Networks   []NetworkView `json:"networks"`
}

func (h *Hub) Snapshot() Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	s := Snapshot{Version: proto.Version, PublicHost: h.st.PublicHost, Now: now.Unix(), Networks: []NetworkView{}}
	for _, n := range h.st.Networks {
		v := NetworkView{Name: n.Name, CIDR: n.CIDR, HubIP: n.hubIP().String(), Port: n.Port, Mode: n.Mode, MTU: n.MTU,
			Keepalive: n.Keepalive, Devices: []DeviceView{}, Codes: []CodeView{}}
		stats := map[string]*proto.PeerStat{}
		if r := h.relays[n.Name]; r != nil {
			stats = r.stats()
		}
		for _, d := range n.Devices {
			dv := DeviceView{ID: d.ID, Name: d.Name, OS: d.OS, IP: d.IP, Groups: append([]string{}, d.Groups...), Created: d.Created.Unix()}
			if kh, err := proto.KeyHex(d.PublicKey); err == nil && stats[kh] != nil {
				st := stats[kh]
				dv.LastSeen, dv.Endpoint, dv.Rx, dv.Tx = st.LastHandshake, st.Endpoint, st.Rx, st.Tx
			}
			v.Devices = append(v.Devices, dv)
		}
		for _, c := range n.Codes {
			cv := CodeView{Code: c.Code, Token: h.token(c), Groups: append([]string{}, c.Groups...), MaxUses: c.MaxUses, Uses: c.Uses, Note: c.Note, Valid: c.valid(now)}
			if !c.Expires.IsZero() {
				cv.Expires = c.Expires.Unix()
			}
			v.Codes = append(v.Codes, cv)
		}
		s.Networks = append(s.Networks, v)
	}
	return s
}

func mustKey(b64 string) []byte {
	h, _ := proto.KeyHex(b64)
	b, _ := hex.DecodeString(h)
	return b
}

func trim(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func cleanName(s string) string {
	if s = trim(s, 48); s == "" {
		return "device"
	}
	return s
}

func cleanGroups(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range in {
		g = strings.ToLower(trim(g, 32))
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}
