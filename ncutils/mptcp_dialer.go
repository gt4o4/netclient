package ncutils

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// mptcpExtraConfig is a shadow decode of /etc/netclient/peers_extra_ips.json.
// We read only `mptcp_endpoints`; the wireguard package owns the rest of
// that file and decodes it independently. Unknown-field tolerance in
// encoding/json keeps both decoders happy on the same file.
//
// Schema:
//
//	{
//	  "mptcp_endpoints": {
//	    "api.nm.wenri.org:443":    "161.248.136.186:36580",
//	    "broker.nm.wenri.org:443": "161.248.136.186:36580"
//	  }
//	}
//
// Keys are the "host:port" pairs netclient would normally Dial; values
// are "ip:port" overrides. The map is the per-host MPTCP "edge address
// book" — server-side mptcpd announces alternate anycast IPs via
// ADD_ADDR (port=0 → preserves the client's edge port), so a single
// override per service is sufficient to enable a 2-subflow MPTCP
// connection.
type mptcpExtraConfig struct {
	MPTCPEndpoints map[string]string `json:"mptcp_endpoints"`
}

var (
	mptcpEndpoints     map[string]string
	mptcpEndpointsOnce sync.Once
)

func loadMPTCPEndpoints() map[string]string {
	mptcpEndpointsOnce.Do(func() {
		path := mptcpConfigPath()
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				slog.Warn("failed to read mptcp config", "path", path, "error", err)
			}
			return
		}
		var cfg mptcpExtraConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			slog.Warn("failed to parse mptcp config", "path", path, "error", err)
			return
		}
		mptcpEndpoints = cfg.MPTCPEndpoints
		if len(mptcpEndpoints) > 0 {
			slog.Info("loaded mptcp endpoint overrides", "count", len(mptcpEndpoints))
		}
	})
	return mptcpEndpoints
}

// mptcpConfigPath duplicates config.GetNetclientPath()'s logic because
// ncutils sits below config in the import graph (config imports ncutils).
func mptcpConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/Netclient/peers_extra_ips.json"
	case "windows":
		return `C:\Program Files (x86)\Netclient\peers_extra_ips.json`
	default:
		return "/etc/netclient/peers_extra_ips.json"
	}
}

// MPTCPDialer returns a *net.Dialer that opens IPPROTO_MPTCP sockets,
// with the kernel falling back to plain TCP when the peer doesn't
// support MPTCP. Used by both SendRequest (HTTPS API) and the MQTT
// CustomOpenConnectionFn.
func MPTCPDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	d.SetMultipathTCP(true)
	return d
}

// MPTCPDialContext is a DialContext for http.Transport. It calls
// MPTCPDialer().DialContext after rewriting `addr` if the literal
// host:port appears in the loaded mptcp_endpoints map. The rewrite
// preserves TLS SNI / cert verification because the caller's
// tls.Config.ServerName is taken from the URL host (unchanged), not
// from the dialed address.
func MPTCPDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := MPTCPDialer(timeout)
	overrides := loadMPTCPEndpoints()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		actual := addr
		if override, ok := overrides[addr]; ok {
			actual = override
		}
		return d.DialContext(ctx, network, actual)
	}
}

// MPTCPRewrite returns the override for `addr` if one is configured,
// otherwise `addr` unchanged. Used by callers that need to dial the
// override themselves (e.g. the MQTT websocket dialer, which goes
// through gorilla/websocket).
func MPTCPRewrite(addr string) string {
	if override, ok := loadMPTCPEndpoints()[addr]; ok {
		return override
	}
	return addr
}
