// Package config loads the agent configuration from the environment.
// Deployment-specific values (target network, port band, public interface)
// have NO in-code defaults on purpose: the persisted mapping file is firewall
// config, and a wrong default silently widens the DNAT surface. The agent
// fails closed at startup instead.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	// sync endpoint (bootstrap/testing; the HTTP source arrives with the
	// transport milestone).
	SourceFile string
}

// SnapshotPath returns the persisted snapshot location.
func (c *Config) SnapshotPath() string { return filepath.Join(c.StateDir, "snapshot.json") }

const (
	envTargetCIDR  = "PICKLE_RELAY_TARGET_CIDR"
	envBand        = "PICKLE_RELAY_PUBLIC_BAND"
	envPublicIface = "PICKLE_RELAY_PUBLIC_IFACE"
	envMaxAgeH     = "PICKLE_RELAY_SNAPSHOT_MAX_AGE_HOURS"
	envPollSec     = "PICKLE_RELAY_POLL_SECONDS"
	envSourceFile  = "PICKLE_RELAY_SOURCE_FILE"
	envStateDir    = "STATE_DIRECTORY" // set by systemd StateDirectory=
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
	// Floor at 1024: a band overlapping a low service port (22, 2222, ...) would
	// let a mapping DNAT the relay's own SSH — PREROUTING DNAT shadows local
	// delivery. Registered/dynamic ports only.
	if err1 != nil || err2 != nil || min64 < 1024 || min64 > max64 {
		return nil, fmt.Errorf("%s: bad band %q (min must be >= 1024)", envBand, band)
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
	return c, nil
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
