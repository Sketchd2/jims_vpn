package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const notRunningHint = "is it running? try: sudo systemctl start jvpn; and are you root or in the jimsvpn group?"

func StateDir() string {
	if d := os.Getenv("JVPN_DIR"); d != "" {
		return d
	}
	return "/var/lib/jimsvpn"
}

func socketPath() string {
	if s := os.Getenv("JVPN_SOCK"); s != "" {
		return s
	}
	return "/run/jimsvpn/jvpn.sock"
}

func prepareStateDir() error { return os.MkdirAll(networksDir(), 0o700) }

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureInterface(_ tun.Device, c *NetConfig, addr netip.Prefix) error {
	name := ifName(c.Network)
	if err := ipCmd("address", "replace", addr.String(), "dev", name); err != nil {
		return err
	}
	return ipCmd("link", "set", "dev", name, "mtu", strconv.Itoa(c.MTU), "up")
}

func cleanupInterface(*NetConfig) {}

// ipcListen opens the control socket: root always, plus the jimsvpn group if it exists.
func ipcListen() (net.Listener, func(http.Handler) http.Handler, error) {
	sock := socketPath()
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return nil, nil, err
	}
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, nil, err
	}
	mode := os.FileMode(0o600)
	if g, err := user.LookupGroup("jimsvpn"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil && os.Chown(sock, 0, gid) == nil {
			mode = 0o660
		}
	}
	os.Chmod(sock, mode)
	return l, func(h http.Handler) http.Handler { return h }, nil
}

func ipcDialer() (string, func(context.Context) (net.Conn, error), error) {
	return "", func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath())
	}, nil
}
