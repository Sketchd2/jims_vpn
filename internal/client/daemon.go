package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

// Status is one network as reported to the CLI and tray.
type Status struct {
	Network       string `json:"network"`
	Address       string `json:"address"`
	HubIP         string `json:"hub_ip"`
	Endpoint      string `json:"endpoint"`
	Enabled       bool   `json:"enabled"`
	State         string `json:"state"` // connected, connecting, idle, down, error
	Error         string `json:"error,omitempty"`
	LastHandshake int64  `json:"last_handshake"`
	Rx            int64  `json:"rx"`
	Tx            int64  `json:"tx"`
	Keepalive     int    `json:"keepalive"`
	DeviceName    string `json:"device_name"`
}

type JoinRequest struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	Keepalive *int   `json:"keepalive"`
	NoInbound bool   `json:"no_inbound"`
}

type NetRequest struct {
	Network   string `json:"network"`
	Keepalive *int   `json:"keepalive,omitempty"`
}

type netState struct {
	cfg *NetConfig
	tun *tunnel
	err string
}

type Daemon struct {
	mu   sync.Mutex
	nets map[string]*netState
}

// Run starts every enabled network and serves the local control API until ctx ends.
func Run(ctx context.Context) error {
	if err := prepareStateDir(); err != nil {
		return err
	}
	cfgs, err := loadConfigs()
	if err != nil {
		return err
	}
	d := &Daemon{nets: map[string]*netState{}}
	for _, c := range cfgs {
		ns := &netState{cfg: c}
		d.nets[c.Network] = ns
		if c.Enabled {
			d.start(ns)
		}
	}
	l, authed, err := ipcListen()
	if err != nil {
		d.stopAll()
		return err
	}
	srv := &http.Server{Handler: authed(d.handler()), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(l)
	log.Printf("jvpn %s running with %d network(s)", proto.Version, len(d.nets))

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			srv.Close()
			d.stopAll()
			return nil
		case <-tick.C:
			d.mu.Lock()
			for _, ns := range d.nets {
				if ns.tun != nil {
					ns.tun.watch(ns.cfg)
				} else if ns.cfg.Enabled {
					d.start(ns) // e.g. the driver was not ready at boot
				}
			}
			d.mu.Unlock()
		}
	}
}

func (d *Daemon) start(ns *netState) {
	if ns.tun != nil {
		return
	}
	t, err := startTunnel(ns.cfg)
	if err != nil {
		if ns.err != err.Error() {
			log.Printf("[%s] %v", ns.cfg.Network, err)
		}
		ns.err = err.Error()
		return
	}
	ns.tun, ns.err = t, ""
	log.Printf("[%s] up as %s", ns.cfg.Network, ns.cfg.Address)
}

func (d *Daemon) stop(ns *netState) {
	if ns.tun != nil {
		ns.tun.close(ns.cfg)
		ns.tun = nil
		log.Printf("[%s] down", ns.cfg.Network)
	}
	ns.err = ""
}

func (d *Daemon) stopAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ns := range d.nets {
		d.stop(ns)
	}
}

func (d *Daemon) status() []Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []Status{}
	for _, ns := range d.nets {
		c := ns.cfg
		s := Status{Network: c.Network, Address: c.Address, HubIP: c.HubIP, Endpoint: c.Endpoint, Enabled: c.Enabled,
			Keepalive: c.Keepalive, DeviceName: c.DeviceName, State: "down", Error: ns.err}
		switch {
		case ns.tun != nil:
			st := ns.tun.stat()
			s.LastHandshake, s.Rx, s.Tx = st.LastHandshake, st.Rx, st.Tx
			switch {
			case st.LastHandshake == 0:
				s.State = "connecting"
			case time.Since(time.Unix(st.LastHandshake, 0)) < staleAfter(c.Keepalive):
				s.State = "connected"
			case c.Keepalive == 0:
				s.State = "idle"
			default:
				s.State = "connecting"
			}
		case ns.err != "":
			s.State = "error"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Network < out[j].Network })
	return out
}

func (d *Daemon) join(req JoinRequest) (*Status, error) {
	tok, err := proto.DecodeToken(req.Token)
	if err != nil {
		return nil, err
	}
	if req.Keepalive != nil && (*req.Keepalive < 0 || *req.Keepalive > 3600) {
		return nil, errors.New("keepalive must be 0-3600 seconds")
	}
	name := req.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	priv := proto.NewPrivateKey()
	var resp proto.EnrollResponse
	err = hubCall(tok.Hub, tok.Fingerprint, "POST", "/api/v1/enroll", "",
		proto.EnrollRequest{Code: tok.Code, PublicKey: proto.KeyToB64(proto.PublicKey(priv)), Name: name, OS: runtime.GOOS + "/" + runtime.GOARCH}, &resp)
	if err != nil {
		return nil, err
	}
	c := &NetConfig{Network: resp.Network, Address: resp.Address, HubIP: resp.HubIP, Endpoint: resp.Endpoint,
		HubPublicKey: resp.HubPublicKey, PrivateKey: proto.KeyToB64(priv), MTU: resp.MTU, Keepalive: resp.Keepalive,
		Enabled: true, AllowInbound: !req.NoInbound, HubURL: tok.Hub, Fingerprint: tok.Fingerprint,
		DeviceID: resp.DeviceID, DeviceToken: resp.DeviceToken, DeviceName: name}
	if req.Keepalive != nil {
		c.Keepalive = *req.Keepalive
	}
	undo := func() { hubCall(c.HubURL, c.Fingerprint, "POST", "/api/v1/leave", c.DeviceToken, nil, nil) }

	d.mu.Lock()
	defer d.mu.Unlock()
	if !proto.NetworkNameRE.MatchString(c.Network) {
		undo()
		return nil, errors.New("hub returned an invalid network name")
	}
	if _, dup := d.nets[c.Network]; dup {
		undo()
		return nil, fmt.Errorf("this device is already a member of a network called %q; leave it first", c.Network)
	}
	if err := c.save(); err != nil {
		undo()
		return nil, err
	}
	ns := &netState{cfg: c}
	d.nets[c.Network] = ns
	d.start(ns)
	return &Status{Network: c.Network, Address: c.Address, HubIP: c.HubIP, Error: ns.err}, nil
}

func (d *Daemon) withNet(name string, fn func(*netState) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ns := d.nets[name]
	if ns == nil {
		return fmt.Errorf("not a member of network %q", name)
	}
	return fn(ns)
}

func (d *Daemon) handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			v = proto.ErrorResponse{Error: err.Error()}
		} else if v == nil {
			v = struct{}{}
		}
		json.NewEncoder(w).Encode(v)
	}
	netCmd := func(fn func(*netState, NetRequest) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req NetRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
				reply(w, nil, errors.New("invalid request"))
				return
			}
			reply(w, nil, d.withNet(req.Network, func(ns *netState) error { return fn(ns, req) }))
		}
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, d.status(), nil) })
	mux.HandleFunc("POST /join", func(w http.ResponseWriter, r *http.Request) {
		var req JoinRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			reply(w, nil, errors.New("invalid request"))
			return
		}
		st, err := d.join(req)
		reply(w, st, err)
	})
	mux.HandleFunc("POST /up", netCmd(func(ns *netState, _ NetRequest) error {
		ns.cfg.Enabled = true
		if err := ns.cfg.save(); err != nil {
			return err
		}
		ns.err = ""
		d.start(ns)
		if ns.err != "" {
			return errors.New(ns.err)
		}
		return nil
	}))
	mux.HandleFunc("POST /down", netCmd(func(ns *netState, _ NetRequest) error {
		ns.cfg.Enabled = false
		d.stop(ns)
		return ns.cfg.save()
	}))
	mux.HandleFunc("POST /set", netCmd(func(ns *netState, req NetRequest) error {
		if req.Keepalive == nil || *req.Keepalive < 0 || *req.Keepalive > 3600 {
			return errors.New("keepalive must be 0-3600 seconds")
		}
		ns.cfg.Keepalive = *req.Keepalive
		if ns.tun != nil {
			if err := ns.tun.setKeepalive(*req.Keepalive); err != nil {
				return err
			}
		}
		return ns.cfg.save()
	}))
	mux.HandleFunc("POST /leave", netCmd(func(ns *netState, _ NetRequest) error {
		c := ns.cfg
		// Best effort: the device is removed locally even if the hub is unreachable.
		if err := hubCall(c.HubURL, c.Fingerprint, "POST", "/api/v1/leave", c.DeviceToken, nil, nil); err != nil {
			log.Printf("[%s] could not tell the hub we left: %v", c.Network, err)
		}
		d.stop(ns)
		delete(d.nets, c.Network)
		return os.Remove(c.path())
	}))
	mux.HandleFunc("GET /peers", func(w http.ResponseWriter, r *http.Request) {
		var c NetConfig
		err := d.withNet(r.URL.Query().Get("network"), func(ns *netState) error { c = *ns.cfg; return nil })
		var peers []proto.Peer
		if err == nil {
			err = hubCall(c.HubURL, c.Fingerprint, "GET", "/api/v1/peers", c.DeviceToken, nil, &peers)
		}
		reply(w, peers, err)
	})
	return mux
}
