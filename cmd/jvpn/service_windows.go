package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/sketchd2/jims_vpn/internal/client"
)

const serviceName = "JimsVPN"

const serviceUsage = `
  jvpn service install        register and start the background service (run as Administrator)
  jvpn service uninstall
`

type handler struct{}

func (handler) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				log.Printf("service failed: %v", err)
				return false, 1
			}
			return false, 0
		case r := <-reqs:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

// runAsService reports whether the process was started by the service manager.
func runAsService() (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	os.MkdirAll(client.StateDir(), 0o755)
	logPath := filepath.Join(client.StateDir(), "jvpn.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 5<<20 {
		os.Rename(logPath, logPath+".old")
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	return true, svc.Run(serviceName, handler{})
}

func serviceCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: jvpn service install|uninstall")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot open the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		s, err := m.OpenService(serviceName)
		if err != nil {
			s, err = m.CreateService(serviceName, exe, mgr.Config{
				DisplayName: "JimsVPN", Description: "Keeps this computer connected to its JimsVPN networks.",
				StartType: mgr.StartAutomatic,
			}, "daemon")
			if err != nil {
				return err
			}
		}
		defer s.Close()
		s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
			{Type: mgr.ServiceRestart, Delay: time.Minute},
		}, 86400)
		if err := s.Start(); err != nil {
			return fmt.Errorf("service installed but did not start: %w", err)
		}
		return nil
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return nil // not installed
		}
		defer s.Close()
		s.Control(svc.Stop)
		for i := 0; i < 20; i++ {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		return s.Delete()
	}
	return errors.New("usage: jvpn service install|uninstall")
}
