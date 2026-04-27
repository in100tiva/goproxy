package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/in100tiva/goproxy/whitelist-proxy/internal/admin"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/config"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/filter"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/logger"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/proxy"
	"github.com/in100tiva/goproxy/whitelist-proxy/internal/sysproxy"
)

// Endereços padrão. Hardcoded para simplificar (não há flag --addr ainda).
const (
	proxyAddr = "127.0.0.1:8080"
	adminAddr = "127.0.0.1:8081"
)

// runtime agrupa tudo que precisa estar vivo para o serviço funcionar.
// É reutilizado tanto pelo modo foreground quanto pelo modo Windows Service.
type runtime struct {
	log      *logger.Logger
	matcher  *filter.Matcher
	watcher  *config.Watcher
	proxy    *proxy.Server
	admin    *admin.Server
	sysProxy sysproxy.Manager

	dir string // diretório base (onde está o binário)
}

// startRuntime inicializa todos os componentes e começa a aceitar conexões.
// Devolve o runtime pronto para shutdown via stop().
func startRuntime() (*runtime, error) {
	dir, err := executableDir()
	if err != nil {
		return nil, fmt.Errorf("descobrindo diretório do binário: %w", err)
	}

	logsDir := filepath.Join(dir, "logs")
	lg, err := logger.New(logsDir, 1000)
	if err != nil {
		return nil, fmt.Errorf("logger: %w", err)
	}

	whitelistPath := filepath.Join(dir, "whitelist.json")
	if err := config.EnsureExists(whitelistPath); err != nil {
		return nil, fmt.Errorf("criando whitelist padrão: %w", err)
	}
	wl, err := config.Load(whitelistPath)
	if err != nil {
		return nil, fmt.Errorf("carregando whitelist: %w", err)
	}

	matcher := filter.New()
	if err := matcher.Load(wl.Rules); err != nil {
		return nil, fmt.Errorf("aplicando whitelist: %w", err)
	}
	lg.Infof("whitelist inicial carregada (%d regras)", len(wl.Rules))

	watcher := config.NewWatcher(whitelistPath, 2*time.Second)
	watcher.Start(
		func(f *config.File) error {
			if err := matcher.Load(f.Rules); err != nil {
				return err
			}
			lg.Infof("whitelist recarregada via watcher (%d regras)", len(f.Rules))
			return nil
		},
		func(err error) {
			lg.Infof("erro no watcher: %v", err)
		},
	)

	proxySrv := proxy.New(proxyAddr, matcher, lg)
	go func() {
		if err := proxySrv.ListenAndServe(); err != nil {
			lg.Infof("proxy parou: %v", err)
		}
	}()

	tokenPath := filepath.Join(dir, "admin.token")
	adminSrv, err := admin.New(adminAddr, tokenPath, whitelistPath, matcher, lg)
	if err != nil {
		return nil, fmt.Errorf("admin: %w", err)
	}
	go func() {
		if err := adminSrv.ListenAndServe(); err != nil {
			lg.Infof("admin parou: %v", err)
		}
	}()

	sp := sysproxy.NewManager()
	if err := sp.Apply(sysproxy.Settings{
		Enabled: true,
		Server:  proxyAddr,
		Bypass:  "<local>;127.0.0.1;localhost",
	}); err != nil {
		// Não é fatal: em desenvolvimento (não-Windows) isto sempre falha.
		lg.Infof("aviso: não foi possível configurar proxy do sistema: %v", err)
	} else {
		lg.Infof("proxy do sistema configurado para %s", proxyAddr)
	}

	return &runtime{
		log:      lg,
		matcher:  matcher,
		watcher:  watcher,
		proxy:    proxySrv,
		admin:    adminSrv,
		sysProxy: sp,
		dir:      dir,
	}, nil
}

// stop encerra todos os componentes na ordem correta. Idempotente.
func (r *runtime) stop() {
	if r == nil {
		return
	}
	if err := r.sysProxy.Restore(); err != nil {
		r.log.Infof("erro restaurando proxy do sistema: %v", err)
	}
	if r.watcher != nil {
		r.watcher.Stop()
	}
	if r.admin != nil {
		_ = r.admin.Shutdown()
	}
	if r.proxy != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.proxy.Shutdown(ctx)
	}
	if r.log != nil {
		r.log.Infof("serviço parado")
		_ = r.log.Close()
	}
}

// runForeground roda em modo console (subcomando "run"). Encerra ao receber
// SIGINT/SIGTERM (Ctrl+C no Windows funciona como SIGINT também).
func runForeground() error {
	rt, err := startRuntime()
	if err != nil {
		return err
	}
	fmt.Println("Proxy ativo em", proxyAddr)
	fmt.Println("Admin ativo em", adminAddr)
	fmt.Println("Token admin em:", filepath.Join(rt.dir, "admin.token"))
	fmt.Println("Whitelist em:  ", filepath.Join(rt.dir, "whitelist.json"))
	fmt.Println("Pressione Ctrl+C para parar.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	rt.stop()
	return nil
}

// executableDir devolve o diretório do binário em execução. Como
// fallback usa o cwd (útil em "go run").
func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return os.Getwd()
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return filepath.Dir(resolved), nil
}
