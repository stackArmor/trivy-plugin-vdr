// Package policy exposes the canonical VDR policy embedded in the plugin.
package policy

import _ "embed"

// vdrPolicyYAML is the authoritative asset-archetype catalog used by the
// compiled plugin and synchronized into downstream consumers.
//
//go:embed vdr-policy.yaml
var vdrPolicyYAML string

// VDRPolicyYAML returns the embedded canonical VDR policy document.
func VDRPolicyYAML() string {
	return vdrPolicyYAML
}
