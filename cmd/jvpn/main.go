// jvpn is the jimsvpn device client: a background service plus this CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sketchd2/jims_vpn/internal/client"
	"github.com/sketchd2/jims_vpn/internal/proto"
)

const usage = `jvpn - jimsvpn client

  jvpn join TOKEN [--name NAME] [--keepalive SECONDS] [--no-inbound]
                              join a network; it reconnects on every boot
  jvpn status                 show joined networks
  jvpn peers NETWORK          list the devices you can reach
  jvpn down NETWORK           disconnect and stay disconnected across reboots
  jvpn up NETWORK             reconnect
  jvpn set NETWORK --keepalive SECONDS
                              tune idle traffic (0 = off, see README)
  jvpn leave NETWORK          leave a network for good
  jvpn version
%s`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usage, serviceUsage)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
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
		fmt.Fprintf(os.Stderr, usage, serviceUsage)
		os.Exit(2)
	}
	return pos
}

func run(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "daemon":
		if handled, err := runAsService(); handled {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return client.Run(ctx)
	case "service":
		return serviceCommand(args)
	case "version":
		fmt.Println(proto.Version)
		return nil
	case "join":
		name := fs.String("name", "", "name shown to the administrator (default: hostname)")
		ka := fs.Int("keepalive", -1, "keepalive seconds (default: the network's setting)")
		noIn := fs.Bool("no-inbound", false, "Windows: do not open the firewall to members of this network")
		p := parse(fs, args, 1)
		req := client.JoinRequest{Token: p[0], Name: *name, NoInbound: *noIn}
		if *ka >= 0 {
			req.Keepalive = ka
		}
		var st client.Status
		if err := client.Call("POST", "/join", req, &st); err != nil {
			return err
		}
		fmt.Printf("Joined %s as %s\n", st.Network, st.Address)
		if st.Error != "" {
			return fmt.Errorf("joined, but the tunnel could not start: %s", st.Error)
		}
		fmt.Printf("Test the link with: ping %s\n", st.HubIP)
		return nil
	case "status":
		parse(fs, args, 0)
		return status()
	case "peers":
		p := parse(fs, args, 1)
		var peers []proto.Peer
		if err := client.Call("GET", "/peers?network="+url.QueryEscape(p[0]), nil, &peers); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tIP\tOS\tLAST SEEN")
		for _, pe := range peers {
			seen := ago(pe.LastSeen)
			if pe.Self {
				seen = "(this device)"
			} else if pe.Name == "hub" && pe.OS == "" {
				seen = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", pe.Name, pe.IP, pe.OS, seen)
		}
		return w.Flush()
	case "up", "down", "leave":
		p := parse(fs, args, 1)
		return client.Call("POST", "/"+cmd, client.NetRequest{Network: p[0]}, nil)
	case "set":
		ka := fs.Int("keepalive", -1, "keepalive seconds, 0 disables")
		p := parse(fs, args, 1)
		if *ka < 0 {
			return fmt.Errorf("nothing to set; use --keepalive SECONDS")
		}
		return client.Call("POST", "/set", client.NetRequest{Network: p[0], Keepalive: ka}, nil)
	}
	fmt.Fprintf(os.Stderr, usage, serviceUsage)
	os.Exit(2)
	return nil
}

func ago(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Since(time.Unix(unix, 0)).Round(time.Second).String() + " ago"
}

func status() error {
	var sts []client.Status
	if err := client.Call("GET", "/status", nil, &sts); err != nil {
		return err
	}
	if len(sts) == 0 {
		fmt.Println("No networks joined. Ask your administrator for a join token, then: jvpn join TOKEN")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NETWORK\tSTATE\tADDRESS\tHUB\tHANDSHAKE\tRX\tTX\tKEEPALIVE")
	for _, s := range sts {
		state := s.State
		if s.Error != "" {
			state += ": " + s.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%ds\n", s.Network, state, s.Address, s.HubIP, ago(s.LastHandshake), size(s.Rx), size(s.Tx), s.Keepalive)
	}
	return w.Flush()
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func init() { log.SetFlags(log.LstdFlags) }
