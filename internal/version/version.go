// Package version carries the agent's build-time version string, reported
// upstream in every sync request so the platform can see which binary each
// relay runs (and gate response-field additions on agents upgrading first).
package version

// Version is stamped by scripts/build.sh via -ldflags "-X ..." from
// `git describe --tags --always`; a plain `go build` yields "dev".
var Version = "dev"
