# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Netclient is the automated WireGuard management client for [Netmaker](https://github.com/gravitl/netmaker) networks. It runs as both a CLI tool and a daemon, managing WireGuard interfaces, firewall rules, DNS, and peer connections across Linux, macOS, Windows, and FreeBSD.

**Module:** `github.com/gravitl/netclient`
**Go version:** 1.25.3 (specified in go.mod)

## Build & Test Commands

```bash
# Build (CGO disabled for cross-platform compatibility)
CGO_ENABLED=0 go build .

# Build with version flag
go build -ldflags "-X main.version=v1.4.0" -o netclient .

# Run all unit tests
go test ./... -v

# Static analysis (used in CI)
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...

# Run a single test
go test -v -run TestFunctionName ./path/to/package/
```

There is no Makefile. CI (`.github/workflows/test.yml`) runs build, `go test ./... -v`, and `staticcheck ./...` on PRs.

## Architecture

### Entry Point & CLI

`main.go` sets the version and calls `cmd.Execute()`. The CLI uses Cobra (`cmd/` package) with commands like `join`, `leave`, `connect`, `disconnect`, `daemon`, `install`, `uninstall`, `list`, `pull`, `push`, `peers`, `ping`.

### Core Daemon Loop

`functions/daemon.go` → `Daemon()` is the main daemon entry point. It:
1. Sets up signal handlers (SIGTERM, SIGHUP for reset)
2. Starts goroutines for MQTT subscription, peer management, DNS, firewall
3. Processes configuration updates from the Netmaker server via MQTT

### MQTT Message Flow

The server-client communication uses MQTT (Eclipse Paho). `functions/mqhandlers.go` (the largest file ~36KB) contains all message handlers for node updates, DNS changes, firewall rules, and peer configuration. Messages are encrypted with AES-GCM using traffic keys. `functions/mqpublish.go` handles outbound messages.

### WireGuard Management (`wireguard/`)

Platform-specific interface creation with build-tag-separated files:
- **Linux** (`wireguard_linux.go`): Tries kernel WireGuard first via netlink, falls back to userspace if only TUN is available
- **macOS** (`wireguard_darwin.go`): Always uses userspace WireGuard
- **Windows** (`wireguard_windows.go`): Uses Windows WireGuard driver API
- **FreeBSD** (`wireguard_freebsd.go`): Checks for kernel module via `kldstat`, falls back to userspace
- **Userspace** (`wireguard_unix.go`): Shared implementation using `golang.zx2c4.com/wireguard` library (TUN device + in-process WireGuard + UAPI listener)
- **Kernel module loading** (`modprobe_linux.go`): Custom modprobe implementation that loads `wireguard` and `tun` modules with dependency resolution from `/lib/modules/`

Peer configuration is applied via `wgctrl` (`wireguard/wireguard.go`).

### Firewall (`firewall/`)

Two backends on Linux: **iptables** (`iptables_linux.go`, ~60KB) and **nftables** (`nftables_linux.go`, ~87KB). Manages ACLs, egress/ingress rules, and virtual NAT. Non-Linux platforms use `firewall_nonlinux.go`.

### DNS (`dns/`)

Platform-aware DNS configuration: systemd-resolved, resolvconf, or file-based on Linux; registry-based on Windows; launchd on macOS. Includes a built-in DNS resolver/listener.

### Configuration (`config/`)

JSON-based configuration stored in platform-specific paths:
- Linux: `/etc/netclient/`
- macOS: `/Applications/Netclient/`
- Windows: `C:\Program Files (x86)\Netclient\`

Node and server configs are managed with file locking for concurrent access. Legacy YAML configs are migrated via `config/oldconfig.go`.

### Daemon/Service Installation (`daemon/`)

Supports multiple init systems on Linux (systemd, SysVinit, OpenRC, Runit), plus LaunchAgent on macOS, Windows Service Manager, and rc.d on FreeBSD.

### Flow Logging (`flow/`)

Linux conntrack-based network flow tracking with gRPC export to the server. Uses `ti-mo/conntrack` for connection tracking.

## Key Dependencies

- `github.com/gravitl/netmaker` — Shared types, models, and logic from the server project
- `golang.zx2c4.com/wireguard` — Userspace WireGuard implementation
- `golang.zx2c4.com/wireguard/wgctrl` — WireGuard device control (kernel and userspace)
- `github.com/vishvananda/netlink` — Linux network interface management
- `github.com/eclipse/paho.mqtt.golang` — MQTT client
- `github.com/spf13/cobra` — CLI framework
- `github.com/coreos/go-iptables` / `github.com/google/nftables` — Firewall backends

## Platform Build Tags

The codebase uses Go build tags extensively. Most packages have `_linux.go`, `_darwin.go`, `_windows.go`, and `_freebsd.go` variants. The `wireguard_unix.go` file is shared across Linux, macOS, and FreeBSD for userspace WireGuard.

## PR Guidelines

From the PR template:
- Changes should affect 10 files or fewer
- Functions should be 80 lines or fewer
- New features: max 1450 lines; bug fixes: max 200 lines
- Unit tests must pass locally
