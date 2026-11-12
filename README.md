# JimsVPN

A small, self-hosted replacement for ZeroTier built on WireGuard.

- **Separate networks.** One hub hosts any number of networks (for example `frws` and `s33`).
  They share nothing: different keys, different subnets, different UDP ports, and no route between them.
- **Multi-network devices.** A device can be in several networks at once; each one is its own interface (`jv-frws`, `jv-s33`).
- **Starts at boot.** A background service reconnects every joined network on startup, on Windows and Linux.
- **Quiet on metered links.** After joining, a device exchanges *nothing* with the hub except the WireGuard
  keepalive, and you choose that interval per device.
- **Packaged.** Windows installer with tray icon, `.deb` for Ubuntu / Debian / Raspberry Pi OS, Arch packages.

## How it works

```
   Raspberry Pi (4G) ─┐                         ┌─ your laptop
   Raspberry Pi (4G) ─┼── WireGuard ──▶  HUB  ◀─┼─ work PC
                      │               (your VPS) │
        frws network ─┘                         └─ frws + s33 networks
```

Every device holds one WireGuard tunnel per network to the hub, and the hub relays packets between the
members of that network. Devices never need an open port or a public address; only the hub does.

The hub relays entirely in its own process. It does not create network interfaces, does not enable IP
forwarding and does not need root, so a network cannot reach the server itself or another network.

| Piece | What it is |
| --- | --- |
| `jvpn-hub` | The hub. Runs on a Linux server with a public address. Includes a web admin page. |
| `jvpn` | The device service and its command line. |
| `jvpn-tray` | Windows notification-area app for people who should not need a command line. |

### Access inside a network

Each network is one of:

- **flat** – every member reaches every other member (what ZeroTier does). Suits the flooded roads network.
- **restricted** – a member reaches only members that share a *group* with it. Suits a company: give each
  person a group, and their home computer and work computer can reach each other but nobody else's.

Groups are set by the join code a device uses and can be edited later; changes apply instantly.

## Setting up the hub

On the server (Debian/Ubuntu shown; use the `.pkg.tar.zst` with `pacman -U` on Arch):

```bash
sudo apt install ./jimsvpn-hub_<version>_amd64.deb
```

```bash
sudo jvpn-hub init --public-host vpn.example.com
```

```bash
sudo systemctl start jvpn-hub
```

`init` prints the web admin password. Then open these in the server's firewall / cloud security group:

- **TCP 8443** – device enrolment API (HTTPS).
- **UDP 51820, 51821, …** – one port per network, in creation order (shown by `jvpn-hub status`).

Create networks and join codes from the command line:

```bash
sudo jvpn-hub network add frws
```

```bash
sudo jvpn-hub network add s33 --mode restricted
```

```bash
sudo jvpn-hub code add frws --note "road sensor 12"
```

```bash
sudo jvpn-hub code add s33 --groups alice --uses 2 --note "Alice: home + work PC"
```

`code add` prints a `jvpn join jv1.…` command to run on the device. Codes are single-use and valid for
7 days unless you say otherwise (`--uses`, `--expires`).

### Web admin

The web admin does everything the command line does. By default it listens only on the server itself
(`127.0.0.1:8787`), so reach it through SSH:

```bash
ssh -L 8787:127.0.0.1:8787 you@vpn.example.com
```

then browse to <http://localhost:8787>. To expose it directly instead, set `"admin_listen": ":8787"` and
`"admin_tls": true` in `/var/lib/jimsvpn-hub/hub.json` and restart the hub (your browser will warn about the
self-signed certificate unless you configure your own with `tls_cert` / `tls_key` / `tls_public_ca`).

## Setting up devices

### Linux (Ubuntu, Debian, Raspberry Pi OS, Arch)

| System | Package |
| --- | --- |
| 64-bit PC | `jimsvpn_<version>_amd64.deb` / `jimsvpn-<version>-1-x86_64.pkg.tar.zst` |
| Raspberry Pi OS 64-bit | `jimsvpn_<version>_arm64.deb` |
| Raspberry Pi OS 32-bit (all models incl. Zero) | `jimsvpn_<version>_armhf.deb` |
| Arch Linux ARM | `aarch64`, `armv7h` or `armv6h` `.pkg.tar.zst` |

```bash
sudo apt install ./jimsvpn_<version>_arm64.deb
```

```bash
sudo jvpn join jv1.eyJ...
```

That is all: the service is enabled at install, and the network comes back on every boot. Join more
networks by running `jvpn join` again with another token.

```
jvpn status                          joined networks, handshake age, traffic counters
jvpn peers frws                      devices you can reach, with their addresses
jvpn down s33 / jvpn up s33          disconnect / reconnect (remembered across reboots)
jvpn set frws --keepalive 120        tune idle traffic
jvpn leave s33                       leave for good
```

### Windows

Run `JimsVPN-<version>-setup.exe` (add `/S` for a silent install). It installs the service, which starts
with Windows before anyone signs in, and a tray icon. To join: copy the token, right-click the tray icon and
choose **Join network from clipboard**. The command line is at `C:\Program Files\JimsVPN\jvpn.exe`.

So that Remote Desktop and similar work, joining adds a Windows Firewall rule allowing inbound connections
*from that network's subnet only*. Use `jvpn join --no-inbound` on machines that should only connect out.

## Data use on 4G

Once joined, the only background traffic is WireGuard's own: a keepalive packet every *N* seconds and a key
renewal roughly every two minutes while the link is in use. Estimated from the protocol's packet sizes
(not measured on your carrier):

| Keepalive | Idle data per device | Notes |
| --- | --- | --- |
| 25 s (default) | about 13 MB / month | Works through practically any NAT. |
| 60 s | about 9 MB / month | Fine on most mobile carriers. |
| 300 s | about 3 MB / month | The hub may be unable to *start* a connection to the device for up to 5 minutes if the carrier drops the idle mapping sooner. |
| 0 (off) | none | The device can only be reached after it has sent something itself. |

Set it at join time (`jvpn join TOKEN --keepalive 60`), later (`jvpn set frws --keepalive 60`), or change the
default for new devices in the network's settings. The right value is the largest one below your carrier's
UDP idle timeout; test by leaving a Pi idle and checking that you can still SSH in.

The tunnel MTU defaults to 1280, which avoids fragmentation on mobile networks.

## Security notes

- Each device generates its own WireGuard key; private keys never leave the device. The hub stores public keys.
- The hub relays traffic, so it sees packets unencrypted in memory. Run it on a server you control. Use
  TLS/SSH inside the tunnel (RDP and SSH already are encrypted) if that matters to you.
- Join tokens embed the fingerprint of the hub's certificate, so a device cannot be tricked into enrolling
  with an impostor even though the certificate is self-signed.
- A join code is a bearer secret until it is used up or expires. Keep them single-use and short-lived.
- Removing a device in the admin cuts it off immediately.
- On Linux the control socket is usable by root and members of the `jimsvpn` group. On Windows any local
  user can use the tray to join, leave, connect and disconnect; private keys are readable only by
  Administrators and SYSTEM.

## Limits of this first version

- All traffic goes through the hub; there are no direct device-to-device links. Put the hub near your users.
- IPv4 only inside the tunnels (the hub itself can be reached over IPv4 or IPv6).
- No built-in name resolution: use `jvpn peers` to look up addresses, which never change once assigned.
- One hub. Back up `/var/lib/jimsvpn-hub/hub.json` (it holds the networks' keys) to be able to rebuild it.
- A device cannot join two networks with the same name from different hubs.

## Building

```bash
go test ./...
```

```bash
scripts/build.sh 1.0.0
```

The build script needs Go, `makensis` (`apt install nsis`), `curl` and `unzip`, and writes all packages and
the Windows installer to `dist/`. It downloads the signed [Wintun](https://www.wintun.net) driver for the
Windows installer. Pushing a `v*` tag makes GitHub Actions build and attach everything to a release.

Layout: `cmd/` (the three programs), `internal/hub` (relay, state, APIs, web page), `internal/client`
(device daemon), `internal/proto` (shared types), `packaging/` (systemd units, package and installer definitions).

Built on [wireguard-go](https://git.zx2c4.com/wireguard-go) and [Wintun](https://www.wintun.net).
