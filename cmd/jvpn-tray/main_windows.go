// jvpn-tray is a small notification-area app for the JimsVPN service.
package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/sketchd2/jims_vpn/internal/client"
	"github.com/sketchd2/jims_vpn/internal/proto"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procMessageBox   = user32.NewProc("MessageBoxW")
	procOpenClip     = user32.NewProc("OpenClipboard")
	procCloseClip    = user32.NewProc("CloseClipboard")
	procGetClipData  = user32.NewProc("GetClipboardData")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

const (
	mbOK       = 0x0
	mbYesNo    = 0x4
	mbIconInfo = 0x40
	mbIconWarn = 0x30
	idYes      = 6
)

func messageBox(text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("JimsVPN")
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags|0x10000 /* MB_SETFOREGROUND */)
	return int(r)
}

func clipboardText() string {
	if r, _, _ := procOpenClip.Call(0); r == 0 {
		return ""
	}
	defer procCloseClip.Call()
	h, _, _ := procGetClipData.Call(13) // CF_UNICODETEXT
	if h == 0 {
		return ""
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p)))
}

// icon draws a filled disc as a 32x32 .ico so no image asset is needed.
func icon(r, g, b byte) []byte {
	const n = 32
	xor := make([]byte, n*n*4)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-15.5, float64(y)-15.5
			d := dx*dx + dy*dy
			o := (y*n + x) * 4
			switch {
			case d <= 11*11:
				xor[o], xor[o+1], xor[o+2], xor[o+3] = b, g, r, 255
			case d <= 14*14:
				xor[o], xor[o+1], xor[o+2], xor[o+3] = 255, 255, 255, 255
			}
		}
	}
	and := make([]byte, n*n/8)
	hdr := make([]byte, 6+16+40)
	le := binary.LittleEndian
	le.PutUint16(hdr[2:], 1) // type: icon
	le.PutUint16(hdr[4:], 1) // one image
	hdr[6], hdr[7] = n, n
	le.PutUint16(hdr[10:], 1)
	le.PutUint16(hdr[12:], 32)
	le.PutUint32(hdr[14:], uint32(40+len(xor)+len(and)))
	le.PutUint32(hdr[18:], 22)
	le.PutUint32(hdr[22:], 40)
	le.PutUint32(hdr[26:], n)
	le.PutUint32(hdr[30:], n*2) // XOR + AND masks
	le.PutUint16(hdr[34:], 1)
	le.PutUint16(hdr[36:], 32)
	le.PutUint32(hdr[42:], uint32(len(xor)+len(and)))
	return append(append(hdr, xor...), and...)
}

var (
	iconUp   = icon(0x2e, 0xa0, 0x43)
	iconWarn = icon(0xd9, 0x8e, 0x04)
	iconDown = icon(0x80, 0x80, 0x80)
)

type entry struct {
	root, toggle, leave *systray.MenuItem
	stop                chan struct{}
	enabled             bool
}

var (
	entries = map[string]*entry{}
	header  *systray.MenuItem
)

func main() { systray.Run(onReady, nil) }

func onReady() {
	systray.SetIcon(iconDown)
	systray.SetTitle("JimsVPN")
	header = systray.AddMenuItem("JimsVPN", "")
	header.Disable()
	systray.AddSeparator()
	join := systray.AddMenuItem("Join network from clipboard…", "Copy a join token (jv1.…), then click here")
	quit := systray.AddMenuItem("Quit tray icon", "The VPN service keeps running")
	systray.AddSeparator()

	refresh := make(chan struct{}, 1)
	kick := func() {
		select {
		case refresh <- struct{}{}:
		default:
		}
	}
	go func() {
		for {
			select {
			case <-join.ClickedCh:
				joinFromClipboard()
				kick()
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
	go func() {
		for {
			update(kick)
			select {
			case <-refresh:
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

func joinFromClipboard() {
	tok := strings.TrimSpace(clipboardText())
	// Accept a pasted "jvpn join jv1...." command line as well as a bare token.
	if i := strings.Index(tok, "jv1."); i >= 0 {
		tok = strings.Fields(tok[i:])[0]
	}
	if _, err := proto.DecodeToken(tok); err != nil {
		messageBox("Copy the join token your administrator sent you (it starts with jv1.), then choose this menu item again.", mbOK|mbIconInfo)
		return
	}
	var st client.Status
	if err := client.Call("POST", "/join", client.JoinRequest{Token: tok}, &st); err != nil {
		messageBox("Could not join: "+err.Error(), mbOK|mbIconWarn)
		return
	}
	messageBox(fmt.Sprintf("Joined network %s.\nThis computer's address is %s.", st.Network, st.Address), mbOK|mbIconInfo)
}

func update(kick func()) {
	var sts []client.Status
	if err := client.Call("GET", "/status", nil, &sts); err != nil {
		header.SetTitle("JimsVPN service is not running")
		systray.SetIcon(iconWarn)
		systray.SetTooltip("JimsVPN: service is not running")
		return
	}
	header.SetTitle(fmt.Sprintf("JimsVPN %s", proto.Version))
	seen := map[string]bool{}
	up, trouble := 0, 0
	var tips []string
	sort.Slice(sts, func(i, j int) bool { return sts[i].Network < sts[j].Network })
	for _, s := range sts {
		seen[s.Network] = true
		e := entries[s.Network]
		if e == nil {
			e = &entry{stop: make(chan struct{})}
			e.root = systray.AddMenuItem(s.Network, "")
			e.toggle = e.root.AddSubMenuItem("Disconnect", "")
			e.leave = e.root.AddSubMenuItem("Leave network…", "")
			entries[s.Network] = e
			go watch(s.Network, e, kick)
		}
		e.enabled = s.Enabled
		addr := strings.SplitN(s.Address, "/", 2)[0]
		e.root.SetTitle(fmt.Sprintf("%s — %s — %s", s.Network, s.State, addr))
		if s.Enabled {
			e.toggle.SetTitle("Disconnect")
		} else {
			e.toggle.SetTitle("Connect")
		}
		switch s.State {
		case "connected", "idle":
			up++
		case "connecting", "error":
			trouble++
		}
		tips = append(tips, s.Network+": "+s.State)
	}
	for name, e := range entries {
		if !seen[name] {
			close(e.stop)
			e.root.Hide()
			delete(entries, name)
		}
	}
	switch {
	case trouble > 0:
		systray.SetIcon(iconWarn)
	case up > 0:
		systray.SetIcon(iconUp)
	default:
		systray.SetIcon(iconDown)
	}
	if len(tips) == 0 {
		tips = []string{"no networks joined"}
	}
	systray.SetTooltip("JimsVPN\n" + strings.Join(tips, "\n"))
}

func watch(network string, e *entry, kick func()) {
	for {
		select {
		case <-e.stop:
			return
		case <-e.toggle.ClickedCh:
			cmd := "/up"
			if e.enabled {
				cmd = "/down"
			}
			if err := client.Call("POST", cmd, client.NetRequest{Network: network}, nil); err != nil {
				messageBox(err.Error(), mbOK|mbIconWarn)
			}
		case <-e.leave.ClickedCh:
			if messageBox("Leave network "+network+"?\nYou will need a new join token to come back.", mbYesNo|mbIconWarn) == idYes {
				if err := client.Call("POST", "/leave", client.NetRequest{Network: network}, nil); err != nil {
					messageBox(err.Error(), mbOK|mbIconWarn)
				}
			}
		}
		kick()
	}
}
