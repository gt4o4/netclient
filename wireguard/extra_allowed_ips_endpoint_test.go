package wireguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// writeExtraConfig writes a peers_extra_ips.json into a temp dir and points the
// loader at it for the duration of the test.
func writeExtraConfig(t *testing.T, cfg ExtraAllowedIPsConfig) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), extraAllowedIPsFile)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
	orig := extraConfigPath
	extraConfigPath = func() string { return path }
	t.Cleanup(func() { extraConfigPath = orig })
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return k.PublicKey()
}

// An endpoint-only entry (no allowed_ips) must survive the loader — the old
// len(nets)>0 guard silently dropped exactly this case.
func TestLoadExtraPeers_EndpointOnlySurvives(t *testing.T) {
	pk := mustKey(t).String()
	writeExtraConfig(t, ExtraAllowedIPsConfig{
		Peers: []ExtraPeerConfig{{PublicKey: pk, Endpoint: "161.248.136.186:59263"}},
	})
	got := loadExtraPeers()
	e, ok := got[pk]
	if !ok {
		t.Fatal("endpoint-only entry was dropped by the loader")
	}
	if e.endpoint == nil || e.endpoint.String() != "161.248.136.186:59263" {
		t.Fatalf("endpoint = %v, want 161.248.136.186:59263", e.endpoint)
	}
	if len(e.nets) != 0 {
		t.Fatalf("nets = %v, want empty", e.nets)
	}
}

// A bad endpoint must leave the server's endpoint alone (nil override), never
// zero it — a nil endpoint demotes an initiator to responder-only.
func TestLoadExtraPeers_BadEndpointIsIgnoredNotZeroed(t *testing.T) {
	pk := mustKey(t).String()
	for _, bad := range []string{"relay.example.com:59263", "161.248.136.186", "notanaddr"} {
		writeExtraConfig(t, ExtraAllowedIPsConfig{
			Peers: []ExtraPeerConfig{{PublicKey: pk, AllowedIPs: "10.0.0.1/32", Endpoint: bad}},
		})
		e, ok := loadExtraPeers()[pk]
		if !ok {
			t.Fatalf("%q: entry dropped; the allowed_ips should have kept it", bad)
		}
		if e.endpoint != nil {
			t.Fatalf("%q: endpoint = %v, want nil (no override)", bad, e.endpoint)
		}
	}
}

// A matched peer gets the pin; PinnedEndpoint agrees.
func TestApplyExtraAllowedIPs_PinsMatchedPeer(t *testing.T) {
	key := mustKey(t)
	pk := key.String()
	writeExtraConfig(t, ExtraAllowedIPsConfig{
		Peers: []ExtraPeerConfig{{PublicKey: pk, Endpoint: "161.248.136.186:59263"}},
	})
	peers := []wgtypes.PeerConfig{{PublicKey: key}}
	out := applyExtraAllowedIPs(peers)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (must not create a duplicate)", len(out))
	}
	if out[0].Endpoint == nil || out[0].Endpoint.String() != "161.248.136.186:59263" {
		t.Fatalf("Endpoint = %v, want the pin", out[0].Endpoint)
	}
	if _, ok := PinnedEndpoint(pk); !ok {
		t.Fatal("PinnedEndpoint reported not pinned")
	}
}

// A peer the server is deleting must not be resurrected by the create loop.
func TestApplyExtraAllowedIPs_DoesNotResurrectRemovedPeer(t *testing.T) {
	key := mustKey(t)
	writeExtraConfig(t, ExtraAllowedIPsConfig{
		Peers: []ExtraPeerConfig{{PublicKey: key.String(), AllowedIPs: "10.1.2.0/24"}},
	})
	out := applyExtraAllowedIPs([]wgtypes.PeerConfig{{PublicKey: key, Remove: true}})
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 — the removed peer was recreated", len(out))
	}
	if !out[0].Remove {
		t.Fatal("Remove flag was cleared")
	}
}

// An endpoint-only entry for an unknown pubkey must NOT manufacture a peer:
// HostPeers is empty until the first successful Pull, and a peer with no
// AllowedIPs is inert anyway.
func TestApplyExtraAllowedIPs_EndpointOnlyDoesNotCreatePeer(t *testing.T) {
	pk := mustKey(t).String()
	writeExtraConfig(t, ExtraAllowedIPsConfig{
		Peers: []ExtraPeerConfig{{PublicKey: pk, Endpoint: "161.248.136.186:59263"}},
	})
	if out := applyExtraAllowedIPs(nil); len(out) != 0 {
		t.Fatalf("len(out) = %d, want 0", len(out))
	}
}

// A create-path entry that also carries a pin gets both.
func TestApplyExtraAllowedIPs_CreatesWithPin(t *testing.T) {
	pk := mustKey(t).String()
	writeExtraConfig(t, ExtraAllowedIPsConfig{
		Peers: []ExtraPeerConfig{{PublicKey: pk, AllowedIPs: "10.9.9.9/32", Endpoint: "138.252.162.176:50552"}},
	})
	out := applyExtraAllowedIPs(nil)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].Endpoint == nil || out[0].Endpoint.String() != "138.252.162.176:50552" {
		t.Fatalf("Endpoint = %v, want the pin", out[0].Endpoint)
	}
	if len(out[0].AllowedIPs) != 1 {
		t.Fatalf("AllowedIPs = %v, want one entry", out[0].AllowedIPs)
	}
}
