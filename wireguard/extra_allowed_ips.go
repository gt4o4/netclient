package wireguard

import (
	"encoding/json"
	"net"
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

// ExtraPeerConfig defines extra AllowedIPs for a peer identified by public key
type ExtraPeerConfig struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
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

// loadExtraConfig reads and parses the config file
func loadExtraConfig() *ExtraAllowedIPsConfig {
	path := filepath.Join(config.GetNetclientPath(), extraAllowedIPsFile)
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

// loadExtraAllowedIPs reads the config file and returns a map of public key -> []net.IPNet
func loadExtraAllowedIPs() map[string][]net.IPNet {
	cfg := loadExtraConfig()
	if cfg == nil {
		return nil
	}
	result := make(map[string][]net.IPNet, len(cfg.Peers))
	for _, p := range cfg.Peers {
		cidrs := strings.Split(p.AllowedIPs, ",")
		var nets []net.IPNet
		for _, cidr := range cidrs {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				slog.Warn("failed to parse CIDR in extra allowed IPs", "cidr", cidr, "error", err)
				continue
			}
			nets = append(nets, *ipnet)
		}
		if len(nets) > 0 {
			result[p.PublicKey] = nets
		}
	}
	return result
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
	extraIPs := loadExtraAllowedIPs()
	if len(extraIPs) == 0 {
		return peers
	}
	matched := make(map[string]bool, len(extraIPs))
	for i := range peers {
		if peers[i].Remove {
			continue
		}
		pk := peers[i].PublicKey.String()
		extra, ok := extraIPs[pk]
		if !ok {
			continue
		}
		matched[pk] = true
		peers[i].AllowedIPs = append(peers[i].AllowedIPs, extra...)
		peers[i].AllowedIPs = logic.UniqueIPNetList(peers[i].AllowedIPs)
		slog.Debug("applied extra allowed IPs to peer", "peer", pk, "count", len(extra))
	}
	// A config public_key that matched no existing peer becomes a new
	// endpoint-less peer (responder-only; endpoint learned from the handshake).
	for pk, nets := range extraIPs {
		if matched[pk] {
			continue
		}
		key, err := wgtypes.ParseKey(pk)
		if err != nil {
			slog.Warn("failed to parse extra peer public key", "key", pk, "error", err)
			continue
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        logic.UniqueIPNetList(nets),
			// Endpoint left nil → responder-only.
		})
		slog.Debug("created endpoint-less extra peer", "peer", pk, "count", len(nets))
	}
	return peers
}
