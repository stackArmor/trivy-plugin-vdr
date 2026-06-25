// Package registry builds the Docker credentials Trivy needs to pull private
// images discovered in a cluster. Credentials come from three sources —
// Kubernetes imagePullSecrets, Google Artifact Registry/GCR (via gcloud), and
// AWS ECR (via the aws CLI) — and are merged into a single Docker config.json
// that is handed to Trivy through the DOCKER_CONFIG environment variable.
package registry

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/distribution/reference"
)

// Kind classifies a registry host by the auth mechanism it requires.
type Kind int

const (
	// KindOther is any registry authenticated only via imagePullSecrets (or anonymous).
	KindOther Kind = iota
	// KindGAR is Google Artifact Registry or Google Container Registry.
	KindGAR
	// KindECR is Amazon Elastic Container Registry (private).
	KindECR
)

// Classification describes the registry a single image lives in.
type Classification struct {
	Host   string
	Kind   Kind
	Region string // populated for KindECR only
}

// ecrPattern matches private ECR hosts and captures the region (group 2).
// Examples: 123456789012.dkr.ecr.us-east-1.amazonaws.com,
// 123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com,
// 123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn
var ecrPattern = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`)

// HostFromImage extracts the registry host from any image reference, handling
// tags, digests, and bare names ("nginx" -> "docker.io").
func HostFromImage(image string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(image))
	if err != nil {
		return "", fmt.Errorf("parse image reference %q: %w", image, err)
	}
	return reference.Domain(named), nil
}

// Classify determines the registry host and the auth mechanism for an image.
func Classify(image string) (Classification, error) {
	host, err := HostFromImage(image)
	if err != nil {
		return Classification{}, err
	}
	c := Classification{Host: host, Kind: KindOther}

	switch {
	case host == "gcr.io" || strings.HasSuffix(host, ".gcr.io") || strings.HasSuffix(host, ".pkg.dev"):
		c.Kind = KindGAR
	default:
		if m := ecrPattern.FindStringSubmatch(host); m != nil {
			c.Kind = KindECR
			c.Region = m[1]
		}
	}
	return c, nil
}
