//go:build !windows

package main

import "errors"

const serviceUsage = ""

func runAsService() (bool, error) { return false, nil }

func serviceCommand([]string) error {
	return errors.New("on Linux the service is managed by systemd: systemctl enable --now jvpn")
}
