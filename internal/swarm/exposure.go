package swarm

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
)

const (
	// ReachableLabel declares a service's internet reachability: "true" or "false".
	ReachableLabel = "vdr.fedramp.io/internet-reachable"
	// JustificationLabel explains a "false" declaration; it is required for one.
	JustificationLabel = "vdr.fedramp.io/internet-reachable-justification"
	// JustificationEvidencePrefix marks the evidence item that carries the
	// operator's justification. TSW requires it before trusting an attested
	// negative.
	JustificationEvidencePrefix = "justification: "

	statusAssessed   = "assessed"
	statusUnassessed = "unassessed"
	basisAttested    = "attested"
	basisObserved    = "observed"
)

// AnalyzeExposure decides each service's internet reachability. Swarm has no
// ingress objects to discover routes from, so, in order:
//
//  1. a vdr.fedramp.io/internet-reachable service label,
//  2. the first matching exposure.yaml rule,
//
// declare it (basis "attested"). Without a declaration, a service that
// publishes ports, carries proxy labels, or runs on the host network is
// left unassessed with that evidence; one with none of those, whose networks
// are all known, is an observed negative. Exposures are keyed by ContainerRef.
func AnalyzeExposure(contextName string, services []Service, cfg ExposureConfig) (map[model.ResourceRef]model.Exposure, []string) {
	exposures := make(map[model.ResourceRef]model.Exposure, len(services))
	var warnings, undeclared []string
	for _, service := range services {
		ref := ContainerRef(contextName, service)
		signals := exposureSignals(service, cfg.ProxyLabelPrefixes)

		declared, source, justification, ok := declaration(service, cfg.Rules)
		if ok && !declared && justification == "" {
			// An unjustified negative is not a declaration, and it must not
			// fall through to an observed negative either.
			warnings = append(warnings, fmt.Sprintf("service %s declares %s=false without %s; its exposure is left unassessed", service.Name, ReachableLabel, JustificationLabel))
			exposures[ref] = unassessed(append([]string{"unjustified " + source + " ignored"}, signals...))
			continue
		}
		if ok {
			evidence := []string{"declared by " + source}
			if justification != "" {
				evidence = append(evidence, JustificationEvidencePrefix+justification)
			}
			exposures[ref] = model.Exposure{
				InternetAccessible: declared,
				AssessmentStatus:   statusAssessed,
				AssessmentBasis:    basisAttested,
				Provider:           Provider,
				Evidence:           append(evidence, signals...),
			}
			continue
		}

		switch {
		case len(signals) > 0:
			if len(service.Ports) > 0 || hasProxyRoute(service, cfg.ProxyLabelPrefixes) {
				undeclared = append(undeclared, service.Name)
			}
			exposures[ref] = unassessed(signals)
		case !service.NetworksResolved:
			exposures[ref] = unassessed([]string{"network identities unknown: provide the swarm network list with the services file to distinguish overlay networks from the host network"})
		default:
			exposures[ref] = model.Exposure{
				InternetAccessible: false,
				AssessmentStatus:   statusAssessed,
				AssessmentBasis:    basisObserved,
				Provider:           Provider,
				Evidence:           []string{"No published ports, proxy route labels, or host networking: the service is reachable only from other services on its overlay networks."},
			}
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		warnings = append(warnings, fmt.Sprintf("%d Swarm service(s) publish ports or proxy routes without an internet-reachability declaration, so their exposure is unassessed; set %s or add exposure.yaml rules: %s", len(undeclared), ReachableLabel, strings.Join(undeclared, ", ")))
	}
	return exposures, warnings
}

func unassessed(evidence []string) model.Exposure {
	return model.Exposure{
		AssessmentStatus: statusUnassessed,
		Provider:         Provider,
		Evidence:         evidence,
	}
}

// declaration returns the service's declared reachability, where it came from,
// and the justification, if the service is declared at all.
func declaration(service Service, rules []ExposureRule) (bool, string, string, bool) {
	if value, present := service.Labels[ReachableLabel]; present {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true":
			return true, "label " + ReachableLabel + "=true", strings.TrimSpace(service.Labels[JustificationLabel]), true
		case "false":
			return false, "label " + ReachableLabel + "=false", strings.TrimSpace(service.Labels[JustificationLabel]), true
		}
	}
	image := scoring.ImageRepositoryBasename(service.Image)
	for i, rule := range rules {
		if globMatch(rule.Stack, service.Stack) && globMatch(rule.Name, service.Name) && globMatch(rule.Image, image) {
			return rule.InternetReachable, fmt.Sprintf("%s exposure.yaml rules[%d]", FedRAMPConfigName, i), rule.Justification, true
		}
	}
	return false, "", "", false
}

func globMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	ok, _ := path.Match(pattern, value)
	return ok
}

// exposureSignals lists what about the service could expose it.
func exposureSignals(service Service, proxyPrefixes []string) []string {
	var signals []string
	for _, port := range service.Ports {
		mode := "ingress routing mesh"
		if port.PublishMode == "host" {
			mode = "host mode"
		}
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		signals = append(signals, fmt.Sprintf("publishes %d/%s (%s) to container port %d", port.PublishedPort, protocol, mode, port.TargetPort))
	}
	// Any label under a proxy prefix means the proxy may route to the service,
	// with or without an explicit rule (Traefik's defaultRule, TCP routers).
	keys := proxyLabels(service, proxyPrefixes)
	for i, key := range keys {
		if i == maxProxyLabelEvidence {
			signals = append(signals, fmt.Sprintf("and %d more proxy labels", len(keys)-i))
			break
		}
		signals = append(signals, fmt.Sprintf("proxy label %s=%s", key, service.Labels[key]))
	}
	if service.HostNetwork {
		signals = append(signals, "attached to the host network: listens directly on node interfaces")
	}
	return signals
}

const maxProxyLabelEvidence = 10

func proxyLabels(service Service, proxyPrefixes []string) []string {
	var keys []string
	for key := range service.Labels {
		if hasAnyPrefix(key, proxyPrefixes) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func hasProxyRoute(service Service, proxyPrefixes []string) bool {
	return len(proxyLabels(service, proxyPrefixes)) > 0
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && (strings.HasPrefix(value, prefix) || value == strings.TrimSuffix(prefix, ".")) {
			return true
		}
	}
	return false
}
