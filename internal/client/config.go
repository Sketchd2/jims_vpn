// Package client implements the jimsvpn device daemon and its local control API.
package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// NetConfig is everything a device needs to bring one network up. It is
// written once at join time; nothing is fetched from the hub afterwards.
type NetConfig struct {
	Network      string `json:"network"`
	Address      string `json:"address"`
	HubIP        string `json:"hub_ip"`
	Endpoint     string `json:"endpoint"`
	HubPublicKey string `json:"hub_public_key"`
	PrivateKey   string `json:"private_key"`
	MTU          int    `json:"mtu"`
	Keepalive    int    `json:"keepalive"`
	Enabled      bool   `json:"enabled"`       // connect at boot
	AllowInbound bool   `json:"allow_inbound"` // Windows: open the firewall to this network's members

	HubURL      string `json:"hub_url"`
	Fingerprint string `json:"fingerprint,omitempty"`
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	DeviceName  string `json:"device_name"`
}

func networksDir() string { return filepath.Join(StateDir(), "networks") }

func (c *NetConfig) path() string { return filepath.Join(networksDir(), c.Network+".json") }

func (c *NetConfig) save() error {
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := c.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path())
}

func loadConfigs() ([]*NetConfig, error) {
	entries, err := os.ReadDir(networksDir())
	if err != nil {
		return nil, err
	}
	var out []*NetConfig
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(networksDir(), e.Name()))
		if err != nil {
			return nil, err
		}
		c := &NetConfig{}
		if err := json.Unmarshal(b, c); err != nil || c.Network == "" {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
