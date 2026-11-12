//go:build !windows

// jvpn-tray is the Windows notification-area app; other systems use the CLI.
package main

import "fmt"

func main() { fmt.Println("jvpn-tray is only available on Windows; use the jvpn command instead.") }
