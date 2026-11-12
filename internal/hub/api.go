package hub

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sketchd2/jims_vpn/internal/proto"
)

//go:embed web
var webFS embed.FS

const sessionCookie = "jvhub_session"

func SocketPath(dir string) string { return filepath.Join(dir, "admin.sock") }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, errNotFound) {
		code = http.StatusNotFound
	}
	writeJSON(w, code, proto.ErrorResponse{Error: err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, proto.ErrorResponse{Error: "expected application/json"})
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		fail(w, errors.New("invalid request body"))
		return false
	}
	return true
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// PublicHandler is the device-facing API: enrol, list peers, leave.
func (h *Hub) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req proto.EnrollRequest
		if !readJSON(w, r, &req) {
			return
		}
		resp, err := h.Enroll(req)
		if err != nil {
			fail(w, err)
			return
		}
		log.Printf("enrolled %q (%s) into %s as %s", req.Name, req.OS, resp.Network, resp.Address)
		writeJSON(w, 200, resp)
	})
	mux.HandleFunc("GET /api/v1/peers", func(w http.ResponseWriter, r *http.Request) {
		peers, err := h.Peers(bearer(r))
		if err != nil {
			writeJSON(w, http.StatusForbidden, proto.ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, 200, peers)
	})
	mux.HandleFunc("POST /api/v1/leave", func(w http.ResponseWriter, r *http.Request) {
		if err := h.Leave(bearer(r)); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, struct{}{})
	})
	return mux
}

// AdminHandler is the management API. With auth=false it is only ever served
// on the root-owned unix socket used by the jvpn-hub command line.
func (h *Hub) AdminHandler(auth, secureCookie bool) http.Handler {
	api := http.NewServeMux()
	ok := func(w http.ResponseWriter, err error) {
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, struct{}{})
	}
	api.HandleFunc("GET /admin/api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, h.Snapshot()) })
	api.HandleFunc("POST /admin/api/networks", func(w http.ResponseWriter, r *http.Request) {
		var o NetworkOpts
		if !readJSON(w, r, &o) {
			return
		}
		_, err := h.CreateNetwork(o)
		ok(w, err)
	})
	api.HandleFunc("PATCH /admin/api/networks/{net}", func(w http.ResponseWriter, r *http.Request) {
		var o struct {
			Mode      *string `json:"mode"`
			Keepalive *int    `json:"keepalive"`
		}
		if readJSON(w, r, &o) {
			ok(w, h.UpdateNetwork(r.PathValue("net"), o.Mode, o.Keepalive))
		}
	})
	api.HandleFunc("DELETE /admin/api/networks/{net}", func(w http.ResponseWriter, r *http.Request) {
		ok(w, h.DeleteNetwork(r.PathValue("net")))
	})
	api.HandleFunc("POST /admin/api/networks/{net}/codes", func(w http.ResponseWriter, r *http.Request) {
		var o CodeOpts
		if !readJSON(w, r, &o) {
			return
		}
		c, tok, err := h.CreateCode(r.PathValue("net"), o)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"code": c.Code, "token": tok})
	})
	api.HandleFunc("DELETE /admin/api/networks/{net}/codes/{code}", func(w http.ResponseWriter, r *http.Request) {
		ok(w, h.DeleteCode(r.PathValue("net"), r.PathValue("code")))
	})
	api.HandleFunc("PATCH /admin/api/networks/{net}/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		var o struct {
			Name   *string   `json:"name"`
			Groups *[]string `json:"groups"`
		}
		if readJSON(w, r, &o) {
			ok(w, h.UpdateDevice(r.PathValue("net"), r.PathValue("id"), o.Name, o.Groups))
		}
	})
	api.HandleFunc("DELETE /admin/api/networks/{net}/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		ok(w, h.DeleteDevice(r.PathValue("net"), r.PathValue("id")))
	})
	api.HandleFunc("POST /admin/api/password", func(w http.ResponseWriter, r *http.Request) {
		var o struct {
			Password string `json:"password"`
		}
		if readJSON(w, r, &o) {
			ok(w, h.SetPassword(o.Password))
		}
	})
	if !auth {
		return api
	}

	static, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(static)))
	mux.HandleFunc("POST /admin/api/login", func(w http.ResponseWriter, r *http.Request) {
		var o struct {
			Password string `json:"password"`
		}
		if !readJSON(w, r, &o) {
			return
		}
		h.loginMu.Lock() // serialise attempts; a wrong guess costs a second
		defer h.loginMu.Unlock()
		h.mu.Lock()
		hash := h.st.PasswordHash
		h.mu.Unlock()
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(o.Password)) != nil {
			time.Sleep(time.Second)
			writeJSON(w, http.StatusUnauthorized, proto.ErrorResponse{Error: "wrong password"})
			return
		}
		id := proto.RandomToken(24)
		h.mu.Lock()
		for k, exp := range h.sessions {
			if time.Now().After(exp) {
				delete(h.sessions, k)
			}
		}
		h.sessions[id] = time.Now().Add(12 * time.Hour)
		h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: secureCookie,
			SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
		writeJSON(w, 200, struct{}{})
	})
	mux.HandleFunc("POST /admin/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			h.mu.Lock()
			delete(h.sessions, c.Value)
			h.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
		writeJSON(w, 200, struct{}{})
	})
	mux.HandleFunc("/admin/api/", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		valid := false
		if err == nil {
			h.mu.Lock()
			exp, found := h.sessions[c.Value]
			valid = found && time.Now().Before(exp)
			h.mu.Unlock()
		}
		if !valid {
			writeJSON(w, http.StatusUnauthorized, proto.ErrorResponse{Error: "not logged in"})
			return
		}
		api.ServeHTTP(w, r)
	})
	return mux
}

// Serve runs the hub's listeners until ctx is cancelled.
func (h *Hub) Serve(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(h.path(h.st.TLSCert), h.path(h.st.TLSKey))
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	errc := make(chan error, 3)
	var servers []*http.Server
	start := func(name string, l net.Listener, handler http.Handler) {
		s := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		servers = append(servers, s)
		log.Printf("%s listening on %s", name, l.Addr())
		go func() {
			if err := s.Serve(l); err != http.ErrServerClosed {
				errc <- err
			}
		}()
	}

	l, err := net.Listen("tcp", h.st.APIListen)
	if err != nil {
		return err
	}
	start("device API (https)", tls.NewListener(l, tlsCfg), h.PublicHandler())

	sock := SocketPath(h.dir)
	os.Remove(sock)
	ul, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	os.Chmod(sock, 0o600)
	start("admin socket", ul, h.AdminHandler(false, false))

	if h.st.AdminListen != "" {
		al, err := net.Listen("tcp", h.st.AdminListen)
		if err != nil {
			return err
		}
		if h.st.AdminTLS {
			al = tls.NewListener(al, tlsCfg)
		}
		start("web admin", al, h.AdminHandler(true, h.st.AdminTLS))
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	for _, s := range servers {
		s.Close()
	}
	os.Remove(sock)
	return err
}
