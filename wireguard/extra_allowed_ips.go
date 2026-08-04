package wireguard

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const extraAllowedIPsFile = "peers_extra_ips.json"

// ExtraPeerConfig defines local overrides for a peer identified by public key:
// extra AllowedIPs and/or a pinned Endpoint.
//
// Endpoint pins the peer's WireGuard endpoint to a literal ip:port, overriding
// whatever the server advertises. netmaker's `endpointip` is a HOST-level field,
// so it cannot express "this peer is reachable at a different address from
// here" — which is exactly what a client behind a censored path needs when the
// peer's real address is blocked but a proxy/CDN front-door for it is not.
// The equivalent already exists for the control plane (`mptcp_endpoints`,
// ncutils/mptcp_dialer.go); this is its data-plane counterpart.
type ExtraPeerConfig struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// ExtraRouteConfig defines an extra route to add to the WG interface
type ExtraRouteConfig struct {
	Dst string `json:"dst"`
	Gw  string `json:"gw"`
	Src string `json:"src,omitempty"`
}

// ExtraAllowedIPsConfig is the top-level config file structure
type ExtraAllowedIPsConfig struct {
	Interface       string             `json:"interface"`
	DebounceSeconds float64            `json:"debounce_seconds"`
	Peers           []ExtraPeerConfig  `json:"peers"`
	Routes          []ExtraRouteConfig `json:"routes"`
}

// extraConfigPath resolves the config file location. It is a var so tests can
// point it at a temp dir; production always uses the netclient config path.
var extraConfigPath = func() string {
	return filepath.Join(config.GetNetclientPath(), extraAllowedIPsFile)
}

// loadExtraConfig reads and parses the config file
func loadExtraConfig() *ExtraAllowedIPsConfig {
	path := extraConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to read extra config", "error", err)
		}
		return nil
	}
	var cfg ExtraAllowedIPsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("failed to parse extra config", "error", err)
		return nil
	}
	return &cfg
}

// extraPeer is the parsed form of one ExtraPeerConfig entry.
type extraPeer struct {
	nets     []net.IPNet
	endpoint *net.UDPAddr // nil = no override; leave the server's endpoint alone
}

// loadExtraPeers reads the config file and returns a map of public key ->
// extraPeer.  An entry is kept when it carries EITHER extra AllowedIPs or an
// endpoint override, so an endpoint-only entry (the common case for pinning a
// peer to a front-door address) survives.
func loadExtraPeers() map[string]extraPeer {
	cfg := loadExtraConfig()
	if cfg == nil {
		return nil
	}
	result := make(map[string]extraPeer, len(cfg.Peers))
	for _, p := range cfg.Peers {
		var e extraPeer
		for _, cidr := range strings.Split(p.AllowedIPs, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				slog.Warn("failed to parse CIDR in extra allowed IPs", "cidr", cidr, "error", err)
				continue
			}
			e.nets = append(e.nets, *ipnet)
		}
		if ep := strings.TrimSpace(p.Endpoint); ep != "" {
			// Deliberately NOT net.ResolveUDPAddr: it performs DNS, and this
			// runs while holding wgMutex on a host whose resolver may itself
			// sit behind the tunnel being configured.  Literals only.
			if ap, err := netip.ParseAddrPort(ep); err == nil {
				e.endpoint = net.UDPAddrFromAddrPort(ap)
			} else {
				// Leave the server's endpoint intact rather than nil-ing it:
				// a nil endpoint silently demotes an initiator to
				// responder-only, which blackholes with no further signal.
				slog.Warn("ignoring unparseable endpoint override (want literal ip:port)",
					"peer", p.PublicKey, "endpoint", ep, "error", err)
			}
		}
		if len(e.nets) > 0 || e.endpoint != nil {
			result[p.PublicKey] = e
		}
	}
	return result
}

// PinnedEndpoint reports whether the given peer has a locally pinned endpoint.
// Callers that discover endpoints dynamically must not override a pin.
func PinnedEndpoint(pubKey string) (*net.UDPAddr, bool) {
	e, ok := loadExtraPeers()[pubKey]
	if !ok || e.endpoint == nil {
		return nil, false
	}
	return e.endpoint, true
}

// AppendExtraEgressRoutes appends extra routes from config as synthetic egress routes
func AppendExtraEgressRoutes(routes []models.EgressNetworkRoutes) []models.EgressNetworkRoutes {
	cfg := loadExtraConfig()
	if cfg == nil || len(cfg.Routes) == 0 {
		return routes
	}
	for _, r := range cfg.Routes {
		_, dstNet, err := net.ParseCIDR(r.Dst)
		if err != nil {
			slog.Warn("failed to parse dst in extra route", "dst", r.Dst, "error", err)
			continue
		}
		gwIP := net.ParseIP(r.Gw)
		if gwIP == nil {
			slog.Warn("failed to parse gw in extra route", "gw", r.Gw)
			continue
		}
		entry := models.EgressNetworkRoutes{
			EgressGwAddr: net.IPNet{IP: gwIP, Mask: net.CIDRMask(32, 32)},
			EgressRangesWithMetric: []models.EgressRangeMetric{{
				Network: dstNet.String(),
			}},
		}
		if r.Src != "" {
			srcIP := net.ParseIP(r.Src)
			if srcIP == nil {
				slog.Warn("failed to parse src in extra route", "src", r.Src)
				continue
			}
			entry.NodeAddr = net.IPNet{IP: srcIP, Mask: net.CIDRMask(32, 32)}
		}
		routes = append(routes, entry)
		slog.Debug("appended extra egress route", "dst", dstNet.String(), "gw", gwIP.String())
	}
	return routes
}

// applyExtraAllowedIPs appends extra AllowedIPs from config to matching peers,
// and — for a config public_key that is NOT already a peer — CREATES a new
// endpoint-less (responder-only) peer carrying those AllowedIPs. A created
// peer is part of the same ConfigureDevice(ReplacePeers) call, so it is
// re-asserted on every sync and survives the full-replace rebuild; it is not
// in config.Netclient().HostPeers, so ShouldReplace is unaffected. Used to
// admit the cnix-cn hubs' Surface B tunnels onto a relay's zth0 (the hub
// initiates via a Cloudflare transit; we learn its endpoint from the
// handshake). Returns the (possibly grown) peer slice.
func applyExtraAllowedIPs(peers []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	extra := loadExtraPeers()
	if len(extra) == 0 {
		return peers
	}
	matched := make(map[string]bool, len(extra))
	for i := range peers {
		pk := peers[i].PublicKey.String()
		e, ok := extra[pk]
		if !ok {
			continue
		}
		// Mark BEFORE the Remove check: a peer the server is deleting must not
		// be re-created by the loop below in the same ConfigureDevice call.
		matched[pk] = true
		if peers[i].Remove {
			continue
		}
		if len(e.nets) > 0 {
			peers[i].AllowedIPs = append(peers[i].AllowedIPs, e.nets...)
			peers[i].AllowedIPs = logic.UniqueIPNetList(peers[i].AllowedIPs)
			slog.Debug("applied extra allowed IPs to peer", "peer", pk, "count", len(e.nets))
		}
		if e.endpoint != nil {
			peers[i].Endpoint = e.endpoint
			slog.Info("pinned peer endpoint from local config", "peer", pk, "endpoint", e.endpoint.String())
		}
	}
	// A config public_key that matched no existing peer becomes a new peer.
	// It is part of the same ConfigureDevice(ReplacePeers) call, so it is
	// re-asserted on every sync; it is not in config.Netclient().HostPeers, so
	// ShouldReplace is unaffected.
	for pk, e := range extra {
		if matched[pk] {
			continue
		}
		// Creating a peer with no AllowedIPs would be inert (WireGuard would
		// route nothing to it) — and HostPeers is empty until the first
		// successful Pull, so an endpoint-only entry must not manufacture one.
		if len(e.nets) == 0 {
			continue
		}
		key, err := wgtypes.ParseKey(pk)
		if err != nil {
			slog.Warn("failed to parse extra peer public key", "key", pk, "error", err)
			continue
		}
		p := wgtypes.PeerConfig{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        logic.UniqueIPNetList(e.nets),
			// Endpoint nil unless pinned → responder-only, learned from the handshake.
		}
		if e.endpoint != nil {
			p.Endpoint = e.endpoint
		}
		peers = append(peers, p)
		slog.Info("created extra peer", "peer", pk, "count", len(e.nets), "pinned", e.endpoint != nil)
	}
	return peers
}
