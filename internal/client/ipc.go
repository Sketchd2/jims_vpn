package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

// Call sends one request to the local daemon. Used by the CLI and the tray.
func Call(method, path string, body, out any) error {
	token, dial, err := ipcDialer()
	if err != nil {
		return err
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: 45 * time.Second, Transport: tr}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://jvpn"+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the jvpn service (%s): %w", notRunningHint, err)
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
