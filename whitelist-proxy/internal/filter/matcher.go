// Package filter implementa o matcher de domínios da whitelist.
//
// Suporta três tipos de regra:
//   - exact:    o host precisa bater literalmente (ex.: "google.com")
//   - wildcard: padrão "*.exemplo.com" — bate qualquer subdomínio e o domínio raiz
//   - regex:    expressão regular Go aplicada ao host normalizado (lowercase, sem porta)
package filter

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Rule representa uma única regra da whitelist, como vinda do JSON.
type Rule struct {
	Pattern string `json:"pattern"`
	Type    string `json:"type"` // "exact", "wildcard" ou "regex"
	Note    string `json:"note,omitempty"`
}

// Matcher é seguro para uso concorrente. Load() troca o conjunto de regras
// atomicamente, então um reload não interrompe lookups em andamento.
type Matcher struct {
	mu       sync.RWMutex
	exact    map[string]bool
	wildcard []string // sufixos já no formato ".exemplo.com"
	regex    []*regexp.Regexp
	rules    []Rule // mantido para introspecção via endpoint admin
}

// New devolve um matcher vazio. Tudo é bloqueado até que Load() seja chamado.
func New() *Matcher {
	return &Matcher{exact: make(map[string]bool)}
}

// Load substitui o conjunto atual de regras. Em caso de erro de validação
// (ex.: regex inválida) o matcher mantém o estado anterior intocado.
func (m *Matcher) Load(rules []Rule) error {
	exact := make(map[string]bool)
	var wildcard []string
	var regs []*regexp.Regexp

	for _, r := range rules {
		switch r.Type {
		case "exact", "":
			p := strings.ToLower(strings.TrimSpace(r.Pattern))
			if p == "" {
				return fmt.Errorf("padrão exact vazio")
			}
			exact[p] = true

		case "wildcard":
			p := strings.ToLower(strings.TrimSpace(r.Pattern))
			if !strings.HasPrefix(p, "*.") || len(p) < 3 {
				return fmt.Errorf("wildcard inválido %q (formato esperado: *.exemplo.com)", r.Pattern)
			}
			// Guardamos o sufixo com o ponto: ".exemplo.com" — assim o
			// strings.HasSuffix evita falso positivo em "maliciousexemplo.com".
			wildcard = append(wildcard, p[1:])
			// O wildcard também libera o domínio raiz (ex.: *.google.com libera google.com).
			exact[p[2:]] = true

		case "regex":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return fmt.Errorf("regex inválida %q: %w", r.Pattern, err)
			}
			regs = append(regs, re)

		default:
			return fmt.Errorf("tipo de regra desconhecido %q", r.Type)
		}
	}

	m.mu.Lock()
	m.exact, m.wildcard, m.regex, m.rules = exact, wildcard, regs, rules
	m.mu.Unlock()
	return nil
}

// Allowed devolve true se o host informado bate em alguma regra. O host pode
// vir com porta (ex.: "exemplo.com:443") — a porta é descartada antes do match.
func (m *Matcher) Allowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	// Remove porta — IPv6 entre colchetes não é tratado aqui pois a whitelist
	// é por nome, não IP literal.
	if i := strings.LastIndex(host, ":"); i != -1 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".") // tira FQDN trailing dot
	if host == "" {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.exact[host] {
		return true
	}
	for _, suffix := range m.wildcard {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	for _, re := range m.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// Rules devolve uma cópia das regras carregadas (para o endpoint admin).
func (m *Matcher) Rules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Rule, len(m.rules))
	copy(out, m.rules)
	return out
}
