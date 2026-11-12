package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

// hubCall talks to a hub's device API. Hubs normally use a self-signed
// certificate, so the join token carries its fingerprint and we pin to it.
func hubCall(hubURL, fingerprint, method, path, bearer string, body, out any) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if fingerprint != "" {
		tr.TLSClientConfig.InsecureSkipVerify = true // replaced by the pin check below
		tr.TLSClientConfig.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("hub sent no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != fingerprint {
				return errors.New("hub certificate does not match the join token")
			}
			return nil
		}
	}
	c := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, hubURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the hub: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e proto.ErrorResponse
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = "hub answered " + resp.Status
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
