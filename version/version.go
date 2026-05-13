package version

import "fmt"

// These variables are set at build time via ldflags.
var (
	Version = "dev"
	Commit  = "none"
)

// String returns a human-readable version string.
func String() string {
	return fmt.Sprintf("%s (commit: %s)", Version, Commit)
}
