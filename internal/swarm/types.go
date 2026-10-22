// Package swarm inventories Docker Swarm services for VDR scanning.
//
// The source reads Swarm's own API objects rather than discovering them over a
// live connection: the output of `docker service inspect`, optionally wrapped
// with the cluster's network list so host networking can be recognised. This
// keeps the plugin independent of how the data was collected (SSM, SSH, or a
// local Docker context).
package swarm

// Provider identifies Swarm resources in reports.
const Provider = "docker-swarm"

// DefaultStack is the namespace for services that were not deployed with
// `docker stack deploy`, so every resource still has a non-empty namespace.
const DefaultStack = "swarm"

// stackLabel is the label `docker stack deploy` sets on every service it owns.
const stackLabel = "com.docker.stack.namespace"

// Service is the subset of a Swarm service spec the scanner needs.
type Service struct {
	ID          string
	Name        string
	Stack       string
	Image       string
	Labels      map[string]string
	Mode        string // "replicated" or "global"
	Ports       []PublishedPort
	Networks    []string // network names when known, otherwise IDs
	HostNetwork bool
	// NetworksResolved is true when every attached network's identity is
	// known, so HostNetwork is authoritative. A bare inspect array leaves
	// network IDs unresolved.
	NetworksResolved bool
}

// PublishedPort is one entry of a service's endpoint ports.
type PublishedPort struct {
	Protocol      string
	TargetPort    uint32
	PublishedPort uint32
	PublishMode   string // "ingress" (routing mesh) or "host"
}
