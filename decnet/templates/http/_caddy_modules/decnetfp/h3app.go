package decnetfp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(H3App{})
	httpcaddyfile.RegisterGlobalOption("decnet_h3", parseH3AppOption)
}

// parseH3AppOption maps the `decnet_h3` global Caddyfile block to the
// decnet_h3 app config (empty JSON — all config comes from env).
func parseH3AppOption(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	for d.Next() {
		for d.NextBlock(0) {
		}
	}
	return json.RawMessage(`{}`), nil
}

// H3App is a Caddy app that owns the QUIC/UDP listener on port 443, forwarding
// accepted h3 connections to the Caddy HTTP app's handler chain.  This is the
// only way to inject a per-connection quic-go Tracer for h3 SETTINGS capture,
// since Caddy does not expose its QUIC config.
//
// Activate with a `decnet_h3` global Caddyfile block AND omit `h3` from the
// `:443` server's `protocols` list, otherwise both this app and Caddy's HTTP
// server will fight over UDP/443.
//
// The app is a no-op when `HTTP_VERSIONS` env does not contain `"http/3"`.
type H3App struct {
	caddyCtx   caddy.Context
	logger     *zap.Logger
	listener   *quic.Listener
	transport  *quic.Transport
	httpSrv    *http3.Server
	cancelLoop context.CancelFunc
	wg         *sync.WaitGroup
}

func (H3App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "decnet_h3",
		New: func() caddy.Module { return new(H3App) },
	}
}

func (a *H3App) Provision(ctx caddy.Context) error {
	a.caddyCtx = ctx
	a.logger = ctx.Logger()
	return nil
}

func (a *H3App) Start() error {
	a.wg = &sync.WaitGroup{}
	if !strings.Contains(os.Getenv("HTTP_VERSIONS"), "http/3") {
		return nil
	}

	cert, err := tls.LoadX509KeyPair("/opt/tls/cert.pem", "/opt/tls/key.pem")
	if err != nil {
		return fmt.Errorf("decnet_h3: load TLS cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}

	udpConn, err := net.ListenPacket("udp", ":443")
	if err != nil {
		return fmt.Errorf("decnet_h3: bind UDP/443: %w", err)
	}
	tr := &quic.Transport{Conn: udpConn.(*net.UDPConn)}
	a.transport = tr

	ln, err := tr.Listen(tlsCfg, &quic.Config{Tracer: newH3SettingsTracer})
	if err != nil {
		tr.Close()
		return fmt.Errorf("decnet_h3: quic listen: %w", err)
	}
	a.listener = ln

	handler, err := a.findHTTPHandler()
	if err != nil {
		ln.Close()
		tr.Close()
		return fmt.Errorf("decnet_h3: find HTTP handler: %w", err)
	}

	a.httpSrv = &http3.Server{Handler: handler}

	loopCtx, cancel := context.WithCancel(context.Background())
	a.cancelLoop = cancel
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.acceptLoop(loopCtx)
	}()

	a.logger.Info("decnet_h3 listening on UDP/443")
	return nil
}

func (a *H3App) acceptLoop(ctx context.Context) {
	for {
		conn, err := a.listener.Accept(ctx)
		if err != nil {
			return
		}
		wrapped := &h3SettingsTappingConn{
			Connection: conn,
			remoteAddr: conn.RemoteAddr().String(),
		}
		go func() {
			a.httpSrv.ServeQUICConn(wrapped) //nolint:errcheck
		}()
	}
}

func (a *H3App) Stop() error {
	if a.cancelLoop != nil {
		a.cancelLoop()
	}
	if a.listener != nil {
		a.listener.Close()
	}
	a.wg.Wait()
	if a.transport != nil {
		a.transport.Close()
	}
	return nil
}

// findHTTPHandler returns the http.Handler for Caddy's :443 server.
func (a *H3App) findHTTPHandler() (http.Handler, error) {
	appIface, err := a.caddyCtx.App("http")
	if err != nil {
		return nil, fmt.Errorf("get http app: %w", err)
	}
	httpApp, ok := appIface.(*caddyhttp.App)
	if !ok {
		return nil, fmt.Errorf("unexpected http app type %T", appIface)
	}
	for _, srv := range httpApp.Servers {
		for _, addr := range srv.Listen {
			if strings.Contains(addr, ":443") {
				return srv, nil
			}
		}
	}
	// Fall back to any available server.
	for _, srv := range httpApp.Servers {
		return srv, nil
	}
	return nil, fmt.Errorf("no HTTP servers found in caddy http app")
}

var (
	_ caddy.App         = (*H3App)(nil)
	_ caddy.Provisioner = (*H3App)(nil)
)
