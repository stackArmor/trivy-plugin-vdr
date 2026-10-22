package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
)

const (
	mediaTypeOCIManifest      = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex         = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerManifest   = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerManifestLs = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDSSEEnvelope     = "application/vnd.dsse.envelope.v1+json"
	mediaTypeSigstoreBundle   = "application/vnd.dev.sigstore.bundle"
	mediaTypeInToto           = "application/vnd.in-toto+json"

	maxOCIVEXManifestBytes = 4 << 20
	maxOCIVEXBlobBytes     = 16 << 20
	maxOCIVEXReferrers     = 64
)

var ociVEXManifestAccept = strings.Join([]string{
	mediaTypeOCIManifest, mediaTypeOCIIndex, mediaTypeDockerManifest, mediaTypeDockerManifestLs,
}, ", ")

// registryVEXFetcher discovers CycloneDX VEX attestations through the OCI
// distribution API: the OCI 1.1 referrers API (cosign v3 / oras) and the cosign
// sha256-<digest>.att tag (cosign v2). It uses the same host-scoped credentials
// that are handed to Trivy, so a credential is only offered to its own registry.
type registryVEXFetcher struct {
	auths  map[string]registry.DockerAuth
	client *http.Client
	// scheme is "https" outside tests.
	scheme string
}

func newRegistryVEXFetcher(auths map[string]registry.DockerAuth) *registryVEXFetcher {
	return &registryVEXFetcher{
		auths:  auths,
		client: &http.Client{Timeout: 60 * time.Second},
		scheme: "https",
	}
}

type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations"`
}

type ociManifest struct {
	MediaType    string          `json:"mediaType"`
	ArtifactType string          `json:"artifactType"`
	Config       ociDescriptor   `json:"config"`
	Layers       []ociDescriptor `json:"layers"`
	Manifests    []ociDescriptor `json:"manifests"`
}

// registrySession is one image's conversation with its registry, caching the
// bearer token negotiated for the repository's pull scope.
type registrySession struct {
	fetcher    *registryVEXFetcher
	host       string // API host
	repository string
	auth       registry.DockerAuth
	mu         sync.Mutex
	authHeader string
}

func (f *registryVEXFetcher) FetchVEX(ctx context.Context, image string) (*OCIVEXResult, error) {
	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	domain := reference.Domain(ref)
	repository := reference.Path(ref)
	host := domain
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	session := &registrySession{fetcher: f, host: host, repository: repository, auth: f.auths[domain]}

	digest := ""
	if digested, ok := ref.(reference.Digested); ok {
		digest = digested.Digest().String()
	} else {
		tag := "latest"
		if tagged, ok := reference.TagNameOnly(ref).(reference.Tagged); ok {
			tag = tagged.Tag()
		}
		digest, err = session.resolveDigest(ctx, tag)
		if err != nil {
			return nil, fmt.Errorf("resolve image digest: %w", err)
		}
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, fmt.Errorf("unsupported image digest %q", digest)
	}

	result := &OCIVEXResult{StatementSource: "oci://" + domain + "/" + repository + "@" + digest}
	seen := map[string]bool{}
	found := false

	referrers, err := session.referrers(ctx, digest)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("referrers lookup: %v", err))
	}
	for _, descriptor := range referrers {
		if seen[descriptor.Digest] {
			continue
		}
		seen[descriptor.Digest] = true
		manifest, manifestDigest, err := session.manifest(ctx, descriptor.Digest)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("referrer %s: %v", descriptor.Digest, err))
			continue
		}
		if session.collect(ctx, manifest, manifestDigest, result) {
			found = true
		}
	}

	attTag := strings.Replace(digest, ":", "-", 1) + ".att"
	manifest, manifestDigest, err := session.manifest(ctx, attTag)
	switch {
	case errors.Is(err, errRegistryNotFound):
	case err != nil:
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", attTag, err))
	case !seen[manifestDigest]:
		seen[manifestDigest] = true
		if session.collect(ctx, manifest, manifestDigest, result) {
			found = true
		}
	}

	if !found && len(result.Warnings) == 0 {
		return nil, nil
	}
	return result, nil
}

// collect parses every attestation layer of one manifest into result, reporting
// whether the manifest carried any attestation layer at all.
func (s *registrySession) collect(ctx context.Context, manifest *ociManifest, manifestDigest string, result *OCIVEXResult) bool {
	found := false
	for _, layer := range manifest.Layers {
		if !isAttestationLayer(layer) {
			continue
		}
		// cosign annotates .att layers with their predicate type; skip blobs that
		// are declared as something other than CycloneDX without fetching them.
		if predicateType := layer.Annotations["predicateType"]; predicateType != "" && !strings.HasPrefix(predicateType, cycloneDXPredicatePrefix) {
			continue
		}
		found = true
		blob, err := s.blob(ctx, layer.Digest)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s layer %s: %v", manifestDigest, layer.Digest, err))
			continue
		}
		statements, err := parseOCIVEXAttestation(blob, manifestDigest)
		if errors.Is(err, errNotCycloneDXVEX) {
			continue
		}
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s layer %s: %v", manifestDigest, layer.Digest, err))
			continue
		}
		result.Statements = append(result.Statements, statements...)
	}
	return found
}

func isAttestationLayer(layer ociDescriptor) bool {
	mediaType := layer.MediaType
	return mediaType == mediaTypeDSSEEnvelope ||
		mediaType == mediaTypeInToto ||
		strings.HasPrefix(mediaType, mediaTypeSigstoreBundle)
}

func isAttestationArtifact(descriptor ociDescriptor) bool {
	artifactType := descriptor.ArtifactType
	return artifactType == "" ||
		artifactType == mediaTypeDSSEEnvelope ||
		artifactType == mediaTypeInToto ||
		strings.HasPrefix(artifactType, mediaTypeSigstoreBundle) ||
		strings.HasPrefix(artifactType, "application/vnd.cyclonedx")
}

var errRegistryNotFound = errors.New("not found")

func (s *registrySession) resolveDigest(ctx context.Context, tag string) (string, error) {
	resp, err := s.do(ctx, http.MethodHead, "/manifests/"+tag, ociVEXManifestAccept)
	if err == nil {
		resp.Body.Close()
		if digest := resp.Header.Get("Docker-Content-Digest"); digest != "" {
			return digest, nil
		}
	}
	_, digest, getErr := s.manifest(ctx, tag)
	if getErr != nil {
		return "", getErr
	}
	return digest, nil
}

// referrers lists attestation-like referrers of digest. A registry without the
// referrers API (404/400/405) yields no referrers and no error.
func (s *registrySession) referrers(ctx context.Context, digest string) ([]ociDescriptor, error) {
	resp, err := s.do(ctx, http.MethodGet, "/referrers/"+digest, mediaTypeOCIIndex)
	if err != nil {
		var status *registryStatusError
		if errors.Is(err, errRegistryNotFound) || (errors.As(err, &status) && (status.code == http.StatusBadRequest || status.code == http.StatusMethodNotAllowed)) {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxOCIVEXManifestBytes)
	if err != nil {
		return nil, err
	}
	var index ociManifest
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("parse referrers index: %w", err)
	}
	var descriptors []ociDescriptor
	for _, descriptor := range index.Manifests {
		if descriptor.Digest == "" || !isAttestationArtifact(descriptor) {
			continue
		}
		descriptors = append(descriptors, descriptor)
		if len(descriptors) == maxOCIVEXReferrers {
			break
		}
	}
	return descriptors, nil
}

// manifest fetches a manifest by tag or digest and returns it with its digest.
func (s *registrySession) manifest(ctx context.Context, ref string) (*ociManifest, string, error) {
	resp, err := s.do(ctx, http.MethodGet, "/manifests/"+ref, ociVEXManifestAccept)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxOCIVEXManifestBytes)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(ref, "sha256:") && ref != digest {
		return nil, "", fmt.Errorf("manifest digest mismatch: got %s", digest)
	}
	var manifest ociManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, "", fmt.Errorf("parse manifest: %w", err)
	}
	return &manifest, digest, nil
}

func (s *registrySession) blob(ctx context.Context, digest string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, "/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxOCIVEXBlobBytes)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(digest, "sha256:") {
		sum := sha256.Sum256(body)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
			return nil, fmt.Errorf("blob digest mismatch: got %s", got)
		}
	}
	return body, nil
}

type registryStatusError struct {
	code int
	path string
}

func (e *registryStatusError) Error() string {
	return fmt.Sprintf("registry returned %d %s for %s", e.code, http.StatusText(e.code), e.path)
}

// do issues one registry API request, answering a 401 challenge once with a
// bearer token or basic credentials for this repository's pull scope.
func (s *registrySession) do(ctx context.Context, method, path, accept string) (*http.Response, error) {
	endpoint := s.fetcher.scheme + "://" + s.host + "/v2/" + s.repository + path
	send := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		s.mu.Lock()
		authHeader := s.authHeader
		s.mu.Unlock()
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		return s.fetcher.client.Do(req)
	}
	resp, err := send()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if err := s.authorize(ctx, challenge); err != nil {
			return nil, err
		}
		if resp, err = send(); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, errRegistryNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, &registryStatusError{code: resp.StatusCode, path: "/v2/" + s.repository + path}
	}
	return resp, nil
}

func (s *registrySession) authorize(ctx context.Context, challenge string) error {
	scheme, params := parseAuthChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if s.auth.Username == "" && s.auth.Password == "" {
			return &registryStatusError{code: http.StatusUnauthorized, path: "/v2/" + s.repository}
		}
		s.setAuthHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(s.auth.Username+":"+s.auth.Password)))
		return nil
	case "bearer":
		token, err := s.fetchToken(ctx, params)
		if err != nil {
			return err
		}
		s.setAuthHeader("Bearer " + token)
		return nil
	default:
		return fmt.Errorf("unsupported registry auth challenge %q", challenge)
	}
}

func (s *registrySession) setAuthHeader(value string) {
	s.mu.Lock()
	s.authHeader = value
	s.mu.Unlock()
}

func (s *registrySession) fetchToken(ctx context.Context, params map[string]string) (string, error) {
	realm := params["realm"]
	if realm == "" {
		return "", errors.New("registry bearer challenge has no realm")
	}
	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse token realm: %w", err)
	}
	query := tokenURL.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + s.repository + ":pull"
	}
	query.Set("scope", scope)
	tokenURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	if s.auth.Username != "" || s.auth.Password != "" {
		req.SetBasicAuth(s.auth.Username, s.auth.Password)
	}
	resp, err := s.fetcher.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch registry token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch registry token: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	body, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		return "", err
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("parse registry token: %w", err)
	}
	if token.Token != "" {
		return token.Token, nil
	}
	if token.AccessToken != "" {
		return token.AccessToken, nil
	}
	return "", errors.New("registry token response had no token")
}

// parseAuthChallenge splits a WWW-Authenticate header such as
// `Bearer realm="https://auth/token",service="registry",scope="repository:a:pull"`.
func parseAuthChallenge(header string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, value, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(value, `"`) {
			end := strings.Index(value[1:], `"`)
			if end < 0 {
				params[key] = value[1:]
				break
			}
			params[key] = value[1 : end+1]
			rest = value[end+2:]
			continue
		}
		value, rest, _ = strings.Cut(value, ",")
		params[key] = strings.TrimSpace(value)
	}
	return scheme, params
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}
