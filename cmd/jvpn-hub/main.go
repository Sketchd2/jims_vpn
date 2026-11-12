// jvpn-hub is the jimsvpn hub: run one on a server with a public address.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sketchd2/jims_vpn/internal/hub"
	"github.com/sketchd2/jims_vpn/internal/proto"
)

const usage = `jvpn-hub - jimsvpn hub

Setup:
  jvpn-hub init --public-host vpn.example.com     create the hub state (once)
  jvpn-hub serve                                  run the hub (normally via systemd)

Management (talks to the running hub):
  jvpn-hub status
  jvpn-hub network add NAME [--mode flat|restricted] [--subnet CIDR] [--port N] [--keepalive S]
  jvpn-hub network set NAME [--mode flat|restricted] [--keepalive S]
  jvpn-hub network rm NAME
  jvpn-hub code add NETWORK [--groups a,b] [--uses N] [--expires 24h] [--note TEXT]
  jvpn-hub code rm NETWORK CODE
  jvpn-hub device set NETWORK ID [--name NAME] [--groups a,b]
  jvpn-hub device rm NETWORK ID
  jvpn-hub passwd                                 set the web admin password

Every command accepts --dir (default /var/lib/jimsvpn-hub, or $JVPN_HUB_DIR).
`

var dir string

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	def := os.Getenv("JVPN_HUB_DIR")
	if def == "" {
		def = "/var/lib/jimsvpn-hub"
	}
	fs.StringVar(&dir, "dir", def, "hub state directory")
	return fs
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string, npos int) []string {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != npos {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	return pos
}

func run(cmd string, args []string) error {
	switch cmd {
	case "init":
		fs := newFlags("init")
		host := fs.String("public-host", "", "DNS name or IP address devices use to reach this hub")
		api := fs.String("api-listen", ":8443", "listen address of the device API (HTTPS)")
		admin := fs.String("admin-listen", "127.0.0.1:8787", "listen address of the web admin (empty to disable)")
		parse(fs, args, 0)
		pw, err := hub.Init(dir, *host, *api, *admin)
		if err != nil {
			return err
		}
		chownToServiceUser(dir)
		fmt.Printf("Hub initialised in %s\n\nWeb admin password: %s\n(change it with: jvpn-hub passwd)\n\n", dir, pw)
		fmt.Printf("Open in your firewall: TCP %s (device API) and one UDP port per network, starting at 51820.\n", *api)
		return nil
	case "serve":
		parse(newFlags("serve"), args, 0)
		h, err := hub.Load(dir)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not initialised; run: jvpn-hub init --public-host <name>", dir)
		}
		if err != nil {
			return err
		}
		defer h.Close()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		log.Printf("jvpn-hub %s started", proto.Version)
		return h.Serve(ctx)
	case "version":
		fmt.Println(proto.Version)
		return nil
	case "status":
		parse(newFlags("status"), args, 0)
		return status()
	case "passwd":
		parse(newFlags("passwd"), args, 0)
		fmt.Print("New web admin password: ")
		var pw string
		fmt.Scanln(&pw)
		return call("POST", "/admin/api/password", map[string]string{"password": pw}, nil)
	case "network", "code", "device":
		if len(args) == 0 {
			break
		}
		return manage(cmd+" "+args[0], args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
	return nil
}

func manage(cmd string, args []string) error {
	fs := newFlags(cmd)
	switch cmd {
	case "network add":
		mode := fs.String("mode", "flat", "flat or restricted")
		cidr := fs.String("subnet", "", "private IPv4 subnet (default: next free 10.77.N.0/24)")
		port := fs.Int("port", 0, "UDP port (default: next free from 51820)")
		ka := fs.Int("keepalive", proto.DefaultKeepalive, "default keepalive seconds for devices")
		p := parse(fs, args, 1)
		if err := call("POST", "/admin/api/networks", hub.NetworkOpts{Name: p[0], Mode: *mode, CIDR: *cidr, Port: *port, Keepalive: ka}, nil); err != nil {
			return err
		}
		return status()
	case "network set":
		mode := fs.String("mode", "", "flat or restricted")
		ka := fs.Int("keepalive", -1, "default keepalive seconds for newly joined devices")
		p := parse(fs, args, 1)
		body := map[string]any{}
		if *mode != "" {
			body["mode"] = *mode
		}
		if *ka >= 0 {
			body["keepalive"] = *ka
		}
		return call("PATCH", "/admin/api/networks/"+p[0], body, nil)
	case "network rm":
		p := parse(fs, args, 1)
		return call("DELETE", "/admin/api/networks/"+p[0], nil, nil)
	case "code add":
		groups := fs.String("groups", "", "comma separated groups given to devices that join with this code")
		uses := fs.Int("uses", 1, "how many devices may join with it (0 = unlimited)")
		exp := fs.Duration("expires", 7*24*time.Hour, "validity period (0 = forever)")
		note := fs.String("note", "", "reminder of who this code is for")
		p := parse(fs, args, 1)
		var out map[string]string
		err := call("POST", "/admin/api/networks/"+p[0]+"/codes",
			hub.CodeOpts{Groups: splitList(*groups), MaxUses: *uses, ExpiresHours: exp.Hours(), Note: *note}, &out)
		if err != nil {
			return err
		}
		fmt.Printf("On the device run:\n\n  jvpn join %s\n\n", out["token"])
		return nil
	case "code rm":
		p := parse(fs, args, 2)
		return call("DELETE", "/admin/api/networks/"+p[0]+"/codes/"+p[1], nil, nil)
	case "device set":
		name := fs.String("name", "", "new name")
		groups := fs.String("groups", "\x00", "comma separated groups (empty string clears)")
		p := parse(fs, args, 2)
		body := map[string]any{}
		if *name != "" {
			body["name"] = *name
		}
		if *groups != "\x00" {
			body["groups"] = splitList(*groups)
		}
		return call("PATCH", "/admin/api/networks/"+p[0]+"/devices/"+p[1], body, nil)
	case "device rm":
		p := parse(fs, args, 2)
		return call("DELETE", "/admin/api/networks/"+p[0]+"/devices/"+p[1], nil, nil)
	}
	fmt.Fprint(os.Stderr, usage)
	os.Exit(2)
	return nil
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func status() error {
	var s hub.Snapshot
	if err := call("GET", "/admin/api/state", nil, &s); err != nil {
		return err
	}
	fmt.Printf("jvpn-hub %s at %s\n", s.Version, s.PublicHost)
	if len(s.Networks) == 0 {
		fmt.Println("No networks yet. Create one with: jvpn-hub network add NAME")
	}
	for _, n := range s.Networks {
		fmt.Printf("\n%s  %s  udp/%d  %s  (%d devices, %d codes)\n", n.Name, n.CIDR, n.Port, n.Mode, len(n.Devices), len(n.Codes))
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  ID\tNAME\tIP\tOS\tGROUPS\tLAST SEEN\tENDPOINT")
		for _, d := range n.Devices {
			seen := "never"
			if d.LastSeen > 0 {
				seen = (time.Duration(s.Now-d.LastSeen) * time.Second).String() + " ago"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.IP, d.OS, strings.Join(d.Groups, ","), seen, d.Endpoint)
		}
		w.Flush()
	}
	return nil
}

// call sends a request to the running hub over its admin socket.
func call(method, path string, body, out any) error {
	sock := hub.SocketPath(dir)
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://hub"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the hub at %s (is it running, and are you root?): %w", sock, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var e proto.ErrorResponse
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// chownToServiceUser hands a root-initialised state dir to the packaged service account.
func chownToServiceUser(dir string) {
	u, err := user.Lookup("jimsvpn-hub")
	if err != nil || os.Geteuid() != 0 {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Chown(p, uid, gid)
		}
		return nil
	})
}
