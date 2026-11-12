package client

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

const notRunningHint = "is the JimsVPN service running?"

// The control API listens on loopback only and requires the token below,
// which the installer leaves readable by local users so the tray can use it.
const ipcAddr = "127.0.0.1:47193"

func StateDir() string {
	if d := os.Getenv("JVPN_DIR"); d != "" {
		return d
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "JimsVPN")
}

func tokenPath() string { return filepath.Join(StateDir(), "ipc.token") }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// prepareStateDir locks the directory holding private keys down to SYSTEM
// and Administrators; ProgramData is otherwise readable by every user.
func prepareStateDir() error {
	if err := os.MkdirAll(networksDir(), 0o700); err != nil {
		return err
	}
	return run("icacls", networksDir(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
}

func fwRule(c *NetConfig) string { return "JimsVPN " + c.Network }

func configureInterface(t tun.Device, c *NetConfig, addr netip.Prefix) error {
	nt, ok := t.(*tun.NativeTun)
	if !ok {
		return errors.New("unexpected tunnel device type")
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
		return fmt.Errorf("cannot set address: %w", err)
	}
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.NLMTU = uint32(c.MTU)
		ipif.UseAutomaticMetric = false
		ipif.Metric = 5
		ipif.Set()
	}
	// Windows treats the adapter as a public network and would block inbound
	// connections such as Remote Desktop, so allow this network's members in.
	cleanupInterface(c)
	if c.AllowInbound {
		if err := run("netsh", "advfirewall", "firewall", "add", "rule", "name="+fwRule(c), "dir=in", "action=allow",
			"remoteip="+addr.Masked().String(), "localip="+addr.Addr().String()); err != nil {
			return err
		}
	}
	return nil
}

func cleanupInterface(c *NetConfig) {
	run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRule(c))
}

func ipcListen() (net.Listener, func(http.Handler) http.Handler, error) {
	token := proto.RandomToken(32)
	if err := os.WriteFile(tokenPath(), []byte(token), 0o644); err != nil {
		return nil, nil, err
	}
	l, err := net.Listen("tcp", ipcAddr)
	if err != nil {
		return nil, nil, err
	}
	want := []byte("Bearer " + token)
	return l, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The Origin check keeps web pages in a local browser away.
			if r.Header.Get("Origin") != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
				http.Error(w, `{"error":"unauthorised"}`, http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}, nil
}

func ipcDialer() (string, func(context.Context) (net.Conn, error), error) {
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", nil, fmt.Errorf("cannot reach the jvpn service (%s)", notRunningHint)
	}
	return strings.TrimSpace(string(b)), func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ipcAddr)
	}, nil
}
