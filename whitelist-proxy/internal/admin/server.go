// Package admin expõe endpoints REST para inspeção e recarregamento da
// whitelist. Escuta apenas em loopback (127.0.0.1) e exige um Bearer token
// salvo no arquivo admin.token (gerado no primeiro start).
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/in100tiva/goproxy/whitelist-proxy/internal/config"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/filter"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/logger"
)

// Server é a HTTP API administrativa.
type Server struct {
	addr         string
	token        string
	matcher      *filter.Matcher
	log          *logger.Logger
	whitelistPth string

	srv *http.Server
}

// New cria o servidor admin. tokenPath é o caminho do arquivo onde o token
// é persistido (criado se não existir). whitelistPath é o caminho do
// whitelist.json para que /whitelist/reload saiba o que recarregar.
func New(addr, tokenPath, whitelistPath string, m *filter.Matcher, lg *logger.Logger) (*Server, error) {
	tok, err := loadOrCreateToken(tokenPath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		addr:         addr,
		token:        tok,
		matcher:      m,
		log:          lg,
		whitelistPth: whitelistPath,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", s.auth(s.handleList))
	mux.HandleFunc("/whitelist/reload", s.auth(s.handleReload))
	mux.HandleFunc("/logs/recent", s.auth(s.handleLogs))

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// ListenAndServe inicia a API admin. Bloqueia até erro ou Shutdown.
func (s *Server) ListenAndServe() error {
	if s.log != nil {
		s.log.Infof("admin escutando em %s", s.addr)
	}
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown encerra a API admin.
func (s *Server) Shutdown() error {
	return s.srv.Close()
}

// auth aplica verificação do header Authorization: Bearer <token>.
// Usa subtle.ConstantTimeCompare para evitar timing attacks.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + s.token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": s.matcher.Rules(),
	})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, err := config.Load(s.whitelistPth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.matcher.Load(f.Rules); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.log.Infof("whitelist recarregada via admin (%d regras)", len(f.Rules))
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": len(f.Rules)})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": s.log.Recent(n)})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// loadOrCreateToken lê o token do disco ou gera um novo (32 bytes hex).
func loadOrCreateToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		// Remove whitespace para tolerar editores que acrescentam newline.
		out := make([]byte, 0, len(b))
		for _, c := range b {
			if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return string(out), nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}
