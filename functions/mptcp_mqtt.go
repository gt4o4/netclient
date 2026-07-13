package functions

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gorilla/websocket"
	"github.com/gravitl/netclient/ncutils"
)

// mptcpMqttOpenConnectionFn replaces paho's default openConnection so MQTT
// broker connections (a) become IPPROTO_MPTCP-capable via
// ncutils.MPTCPDialer (auto-fallback to TCP when the broker doesn't speak
// MPTCP) and (b) honor the per-host edge-address rewrites from
// /etc/netclient/peers_extra_ips.json (so wss://broker.nm.wenri.org
// dials the configured Cloudflare anycast edge instead of the canonical
// origin IP).
//
// Logic mirrors paho.mqtt.golang v1.5.1 netconn.go:openConnection — same
// scheme dispatch, same TLS handling — but with our dialer and a small
// websocket-conn wrapper since paho's wrapper type is unexported.
func mptcpMqttOpenConnectionFn(uri *url.URL, opts mqtt.ClientOptions) (net.Conn, error) {
	timeout := opts.ConnectTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	switch uri.Scheme {
	case "ws", "wss":
		var tlsc *tls.Config
		if uri.Scheme == "wss" {
			tlsc = opts.TLSConfig
		}
		dialURI := *uri
		dialURI.User = nil // gorilla rejects URLs with userinfo
		d := &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: timeout,
			TLSClientConfig:  tlsc,
			Subprotocols:     []string{"mqtt"},
			NetDialContext:   ncutils.MPTCPDialContext(timeout),
		}
		ws, resp, err := d.Dial(dialURI.String(), opts.HTTPHeaders)
		if err != nil {
			if resp != nil {
				return nil, fmt.Errorf("websocket handshake failed (status %d): %w", resp.StatusCode, err)
			}
			return nil, err
		}
		return &mptcpWebsocketConn{Conn: ws}, nil

	case "ssl", "tls", "mqtts", "mqtt+ssl", "tcps":
		host := withDefaultPort(uri.Host, "8883")
		host = ncutils.MPTCPRewrite(host)
		conn, err := tls.DialWithDialer(ncutils.MPTCPDialer(timeout), "tcp", host, opts.TLSConfig)
		if err != nil {
			return nil, err
		}
		return conn, nil

	case "mqtt", "tcp":
		host := withDefaultPort(uri.Host, "1883")
		dial := ncutils.MPTCPDialContext(timeout)
		return dial(context.Background(), "tcp", host)

	case "unix":
		// Unix-domain sockets aren't MPTCP-relevant; passthrough.
		path := uri.Path
		if uri.Host != "" {
			path = uri.Host
		}
		return (&net.Dialer{Timeout: timeout}).Dial("unix", path)
	}

	return nil, fmt.Errorf("mptcpMqttOpenConnectionFn: unsupported scheme %q", uri.Scheme)
}

// withDefaultPort appends `:port` if `host` has no port component.
func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

// mptcpWebsocketConn adapts a *websocket.Conn to net.Conn so that paho's
// MQTT framing layer can read/write it as a stream. Equivalent to paho's
// internal websocketConnector type, reimplemented here because that
// type is unexported.
type mptcpWebsocketConn struct {
	*websocket.Conn
	r   io.Reader
	rio sync.Mutex
	wio sync.Mutex
}

func (c *mptcpWebsocketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *mptcpWebsocketConn) Write(p []byte) (int, error) {
	c.wio.Lock()
	defer c.wio.Unlock()
	if err := c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *mptcpWebsocketConn) Read(p []byte) (int, error) {
	c.rio.Lock()
	defer c.rio.Unlock()
	for {
		if c.r == nil {
			_, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if err == io.EOF {
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}
