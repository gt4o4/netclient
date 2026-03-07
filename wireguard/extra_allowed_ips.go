package wireguard

import (
	"encoding/json"
	"net"
	"os"
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
	path := config.GetNetclientPath() + extraAllowedIPsFile
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

// applyExtraAllowedIPs appends extra AllowedIPs from config to matching peers
func applyExtraAllowedIPs(peers []wgtypes.PeerConfig) {
	extraIPs := loadExtraAllowedIPs()
	if len(extraIPs) == 0 {
		return
	}
	for i := range peers {
		if peers[i].Remove {
			continue
		}
		extra, ok := extraIPs[peers[i].PublicKey.String()]
		if !ok {
			continue
		}
		peers[i].AllowedIPs = append(peers[i].AllowedIPs, extra...)
		peers[i].AllowedIPs = logic.UniqueIPNetList(peers[i].AllowedIPs)
		slog.Debug("applied extra allowed IPs to peer", "peer", peers[i].PublicKey.String(), "count", len(extra))
	}
}
