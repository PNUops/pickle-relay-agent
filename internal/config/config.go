// Package config loads the agent configuration from the environment.
// Deployment-specific values (target network, port band, public interface)
// have NO in-code defaults on purpose: the persisted mapping file is firewall
// config, and a wrong default silently widens the DNAT surface. The agent
// fails closed at startup instead.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
)

// Config is the fully validated agent configuration.
type Config struct {
	// Limits bound every mapping (target CIDR whitelist + public port band).
	Limits snapshot.Limits
	// PublicIface is the interface DNAT rules bind to (public ingress only —
	// tunnel-ingress packets must never re-match a DNAT rule).
	PublicIface string
	// StateDir holds the persisted snapshot (systemd StateDirectory).
	StateDir string
	// SnapshotMaxAge bounds boot-time re-apply of the persisted snapshot
	// (keep equal to the platform's IP quarantine window).
	SnapshotMaxAge time.Duration
	// PollInterval is the sync poll cadence.
	PollInterval time.Duration
	// SourceFile, when set, feeds snapshots from a local file instead of the
	// sync endpoint (bootstrap/testing). Mutually exclusive with SyncURL.
	SourceFile string
	// SyncURL is the platform sync endpoint (full URL, the relay id is part
	// of the path). Empty means no HTTP sync. No default on purpose: the
	// sync target decides whose desired state shapes the firewall.
	SyncURL string
	// SyncToken is the per-relay bearer token for SyncURL. Required exactly
	// when SyncURL is set; never defaulted.
	SyncToken string
	// Guards bounds each mapping's new-connection rate, concurrency and
	// per-source rate — the real defense against the conntrack-exhaustion
	// vector that shares fate with user SSH (sysctl sizing only raises the
	// bar). These are the DEFAULTS; a snapshot may override them per mapping.
	Guards nftctl.Guards
}

// SnapshotPath returns the persisted snapshot location.
func (c *Config) SnapshotPath() string { return filepath.Join(c.StateDir, "snapshot.json") }

// reservedRelayPorts are the relay's own service ports that a DNAT mapping
// must never be allowed to shadow (admin sshd, WireGuard). SSH :22 is below the
// 1024 floor already; these are the >=1024 cases the floor misses.
var reservedRelayPorts = []uint16{2222, 51820}

const (
	envTargetCIDR     = "PICKLE_RELAY_TARGET_CIDR"
	envBand           = "PICKLE_RELAY_PUBLIC_BAND"
	envPublicIface    = "PICKLE_RELAY_PUBLIC_IFACE"
	envMaxAgeH        = "PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS"
	envPollSec        = "PICKLE_RELAY_POLL_SECONDS"
	envSourceFile     = "PICKLE_RELAY_SOURCE_FILE"
	envSyncURL        = "PICKLE_RELAY_SYNC_URL"
	envSyncToken      = "PICKLE_RELAY_SYNC_TOKEN"
	envStateDir       = "STATE_DIRECTORY" // set by systemd StateDirectory=
	envCtMax          = "PICKLE_RELAY_CT_MAX_PER_MAPPING"
	envNewConnRate    = "PICKLE_RELAY_NEW_CONN_RATE"
	envNewConnBurst   = "PICKLE_RELAY_NEW_CONN_BURST"
	envPerSourceRate  = "PICKLE_RELAY_PER_SOURCE_RATE"
	envPerSourceBurst = "PICKLE_RELAY_PER_SOURCE_BURST"
)

// Load reads and validates the configuration from the environment.
func Load() (*Config, error) {
	c := &Config{}

	cidr := os.Getenv(envTargetCIDR)
	if cidr == "" {
		return nil, fmt.Errorf("%s is required (no default: it whitelists DNAT targets)", envTargetCIDR)
	}
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", envTargetCIDR, err)
	}
	if !pfx.Addr().Is4() {
		return nil, fmt.Errorf("%s: %s is not an IPv4 prefix", envTargetCIDR, pfx)
	}
	c.Limits.TargetCIDR = pfx

	band := os.Getenv(envBand)
	lo, hi, ok := strings.Cut(band, "-")
	if band == "" || !ok {
		return nil, fmt.Errorf("%s is required, form MIN-MAX (e.g. 10000-19999)", envBand)
	}
	min64, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	max64, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	// Floor at 1024: keep the band in registered/dynamic port space.
	if err1 != nil || err2 != nil || min64 < 1024 || min64 > max64 {
		return nil, fmt.Errorf("%s: bad band %q (min must be >= 1024)", envBand, band)
	}
	// A band that spans a relay service port would let a mapping DNAT it away —
	// PREROUTING DNAT shadows local delivery, so a mapping on the relay's own
	// admin sshd (2222) or WireGuard (51820) would lock the box out or kill the
	// tunnel. The floor alone does not catch these (both are >= 1024).
	for _, p := range reservedRelayPorts {
		if uint16(min64) <= p && p <= uint16(max64) {
			return nil, fmt.Errorf("%s: band %q includes reserved relay port %d", envBand, band, p)
		}
	}
	c.Limits.BandMin, c.Limits.BandMax = uint16(min64), uint16(max64)

	c.PublicIface = os.Getenv(envPublicIface)
	if c.PublicIface == "" || len(c.PublicIface) > 15 {
		return nil, fmt.Errorf("%s is required (public interface name, e.g. eth0)", envPublicIface)
	}

	c.StateDir = os.Getenv(envStateDir)
	if c.StateDir == "" {
		return nil, fmt.Errorf("%s is required (run under systemd StateDirectory=)", envStateDir)
	}

	// Required, no default: the boot re-apply window decides whether a stale
	// DNAT may be applied — it IS firewall-shaping, so it follows the same
	// no-in-code-default rule as the three above. Pin it to the platform's
	// current IP quarantine window at deploy time.
	c.SnapshotMaxAge, err = requiredHoursEnv(envMaxAgeH)
	if err != nil {
		return nil, err
	}
	pollS, err := intEnv(envPollSec, 15)
	if err != nil {
		return nil, err
	}
	if pollS < 5 || pollS > 300 {
		return nil, fmt.Errorf("%s: %d outside 5-300", envPollSec, pollS)
	}
	c.PollInterval = time.Duration(pollS) * time.Second

	c.SourceFile = os.Getenv(envSourceFile)

	// Sync endpoint + token: both-or-neither, and no defaults — together
	// they decide WHO gets to shape this firewall, which is exactly the
	// class of value that must fail closed when missing or malformed.
	c.SyncURL = os.Getenv(envSyncURL)
	token := os.Getenv(envSyncToken)
	if c.SyncURL != "" {
		u, err := url.Parse(c.SyncURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s: %q is not an http(s) URL", envSyncURL, c.SyncURL)
		}
		if token == "" {
			return nil, fmt.Errorf("%s is required when %s is set", envSyncToken, envSyncURL)
		}
		// Control characters cannot appear in a valid token and would
		// corrupt the Authorization header — reject rather than send.
		for _, r := range token {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("%s contains control characters", envSyncToken)
			}
		}
		c.SyncToken = token
	} else if token != "" {
		return nil, fmt.Errorf("%s is set but %s is not", envSyncToken, envSyncURL)
	}
	if c.SyncURL != "" && c.SourceFile != "" {
		return nil, fmt.Errorf("%s and %s are mutually exclusive (one desired-state authority)",
			envSyncURL, envSourceFile)
	}

	// Abuse guards. Defaults are conservative (they only ever TIGHTEN the
	// surface, so a default does not widen the firewall — unlike the
	// firewall-shaping vars above) but env-overridable per relay. Set an env
	// to 0 to disable a guard explicitly.
	c.Guards.MaxConn, err = uint32Env(envCtMax, 512)
	if err != nil {
		return nil, err
	}
	rate, err := uint32Env(envNewConnRate, 200)
	if err != nil {
		return nil, err
	}
	c.Guards.NewConnRate = uint64(rate)
	c.Guards.NewConnBurst, err = uint32Env(envNewConnBurst, 400)
	if err != nil {
		return nil, err
	}
	psRate, err := uint32Env(envPerSourceRate, 50)
	if err != nil {
		return nil, err
	}
	c.Guards.PerSourceRate = uint64(psRate)
	c.Guards.PerSourceBurst, err = uint32Env(envPerSourceBurst, 100)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func uint32Env(key string, def uint32) (uint32, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: bad unsigned integer %q", key, v)
	}
	return uint32(n), nil
}

func requiredHoursEnv(key string) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return 0, fmt.Errorf("%s is required (pin to the platform IP quarantine window)", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 24*30 {
		return 0, fmt.Errorf("%s: bad hours %q", key, v)
	}
	return time.Duration(n) * time.Hour, nil
}

func intEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: bad integer %q", key, v)
	}
	return n, nil
}
