// Package proto holds the types shared between the hub and its clients.
package proto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Version is stamped at build time with -ldflags "-X ...proto.Version=1.2.3".
var Version = "dev"

const (
	DefaultMTU       = 1280 // safe on 4G/CGNAT paths, and the IPv6 minimum
	DefaultKeepalive = 25
)

// NetworkNameRE keeps "jv-<name>" within the 15 character Linux interface limit.
var NetworkNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,11}$`)

const tokenPrefix = "jv1."

// JoinToken is what an administrator hands to a device so it can enrol.
type JoinToken struct {
	Hub         string `json:"h"`           // e.g. https://vpn.example.com:8443
	Fingerprint string `json:"f,omitempty"` // hex SHA-256 of the hub certificate; empty = verify against system CAs
	Code        string `json:"c"`
}

func (t JoinToken) Encode() string {
	b, _ := json.Marshal(t)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func DecodeToken(s string) (JoinToken, error) {
	var t JoinToken
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, tokenPrefix) {
		return t, errors.New("not a join token (expected it to start with jv1.)")
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(tokenPrefix):])
	if err != nil {
		return t, errors.New("join token is corrupt")
	}
	if err := json.Unmarshal(b, &t); err != nil || t.Hub == "" || t.Code == "" {
		return t, errors.New("join token is corrupt")
	}
	return t, nil
}

type EnrollRequest struct {
	Code      string `json:"code"`
	PublicKey string `json:"public_key"` // base64, WireGuard format
	Name      string `json:"name"`
	OS        string `json:"os"`
}

type EnrollResponse struct {
	Network      string `json:"network"`
	Address      string `json:"address"`  // this device, with prefix: 10.77.1.5/24
	HubIP        string `json:"hub_ip"`   // pingable address of the hub inside the network
	Endpoint     string `json:"endpoint"` // host:port of the hub's WireGuard listener
	HubPublicKey string `json:"hub_public_key"`
	MTU          int    `json:"mtu"`
	Keepalive    int    `json:"keepalive"`
	DeviceID     string `json:"device_id"`
	DeviceToken  string `json:"device_token"`
}

type Peer struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	OS       string `json:"os,omitempty"`
	LastSeen int64  `json:"last_seen"` // unix seconds of last handshake, 0 = never
	Self     bool   `json:"self,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// NewPrivateKey returns a clamped Curve25519 private key.
func NewPrivateKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k
}

func PublicKey(priv []byte) []byte {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pub
}

func KeyToB64(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// KeyHex converts a base64 WireGuard key to the hex form the UAPI wants.
func KeyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

func RandomToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b) // hex, so IDs never start with "-" on a command line
}

// PeerStat is one peer's live counters parsed from the WireGuard UAPI.
type PeerStat struct {
	Endpoint      string
	LastHandshake int64
	Rx, Tx        int64
}

// ParseStats parses device.IpcGet output into a map keyed by hex public key.
func ParseStats(ipc string) map[string]*PeerStat {
	out := map[string]*PeerStat{}
	var cur *PeerStat
	for _, line := range strings.Split(ipc, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			cur = &PeerStat{}
			out[v] = cur
			continue
		}
		if cur == nil {
			continue
		}
		switch k {
		case "endpoint":
			cur.Endpoint = v
		case "last_handshake_time_sec":
			cur.LastHandshake = atoi(v)
		case "rx_bytes":
			cur.Rx = atoi(v)
		case "tx_bytes":
			cur.Tx = atoi(v)
		}
	}
	return out
}

func atoi(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
