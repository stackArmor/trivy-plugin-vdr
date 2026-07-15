// Package buildinfo exposes version metadata embedded in vdr reports.
package buildinfo

// PluginVersion is replaced with the release version through -ldflags. Direct
// go build/go run invocations intentionally identify themselves as development
// builds unless their caller supplies the linker value.
var PluginVersion = "dev"
