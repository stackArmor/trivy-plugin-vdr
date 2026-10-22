package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

// OCI VEX is read directly from the image's registry attestations rather than
// through Trivy's --vex oci, whose ExperimentalModifiedFindings collapse
// CycloneDX analysis.justification and analysis.detail into a single Statement
// and move the finding out of the scored result set. Statements read here are
// attached to the still-active finding as model.VEXAnalysis.
const (
	ociVEXSource              = "oci-cyclonedx-vex"
	ociVEXFormatCycloneDX     = "cyclonedx"
	cycloneDXVEXPredicateType = "https://cyclonedx.org/vex"
	cycloneDXPredicatePrefix  = "https://cyclonedx.org/"
	inTotoPayloadType         = "application/vnd.in-toto+json"
)

// OCIVEXFetcher returns the CycloneDX VEX statements attached to an image in its
// registry. A nil result with a nil error means the image has no attestations.
type OCIVEXFetcher interface {
	FetchVEX(ctx context.Context, image string) (*OCIVEXResult, error)
}

// OCIVEXResult is the set of CycloneDX VEX statements discovered for one image.
type OCIVEXResult struct {
	// StatementSource is oci://<registry>/<repository>@<image digest>.
	StatementSource string
	Statements      []OCIVEXStatement
	// Warnings records attestations that were found but could not be fetched or
	// parsed. They never fail the image scan.
	Warnings []string
}

// OCIVEXStatement is one CycloneDX vulnerabilities[] entry with its analysis.
type OCIVEXStatement struct {
	// IDs holds the vulnerability id plus any references[].id aliases.
	IDs []string
	// PURLs scopes the statement to specific components (from affects[].ref).
	// Empty means the statement applies to every component in the image.
	PURLs             []string
	State             string
	Justification     string
	Detail            string
	Responses         []string
	AttestationDigest string
	// Timestamp is the CycloneDX metadata.timestamp of the carrying document,
	// used to prefer the newest statement when several apply.
	Timestamp time.Time
}

// dsseEnvelope is a DSSE envelope as stored in cosign .att layers and OCI
// referrer layers.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// sigstoreBundle is the subset of a Sigstore bundle (cosign v3 referrers) that
// wraps the DSSE envelope.
type sigstoreBundle struct {
	MediaType    string        `json:"mediaType"`
	DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"`
}

type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type cdxDocument struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  *struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components      []cdxDocComponent `json:"components"`
	Vulnerabilities []cdxDocVuln      `json:"vulnerabilities"`
}

type cdxDocComponent struct {
	BOMRef     string            `json:"bom-ref"`
	PURL       string            `json:"purl"`
	Components []cdxDocComponent `json:"components"`
}

type cdxDocVuln struct {
	ID         string `json:"id"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Analysis *struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

var errNotCycloneDXVEX = errors.New("attestation is not a CycloneDX VEX predicate")

// parseAttestationStatement decodes a DSSE envelope (or a Sigstore bundle that
// wraps one) into its in-toto statement.
//
// TODO: the DSSE signatures are not verified. Trivy's --vex oci path, which
// this replaces, did not verify attestation signatures either, and no trust
// policy (keys, identities, Rekor) is configured for the plugin yet. The
// statement is surfaced as an unreviewed claim for downstream ISSM review.
func parseAttestationStatement(data []byte) (*inTotoStatement, error) {
	var probe struct {
		PayloadType  string          `json:"payloadType"`
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse attestation envelope: %w", err)
	}
	var envelope dsseEnvelope
	switch {
	case len(probe.DSSEEnvelope) > 0:
		var bundle sigstoreBundle
		if err := json.Unmarshal(data, &bundle); err != nil || bundle.DSSEEnvelope == nil {
			return nil, errors.New("parse attestation envelope: sigstore bundle has no DSSE envelope")
		}
		envelope = *bundle.DSSEEnvelope
	case probe.PayloadType != "":
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("parse attestation envelope: %w", err)
		}
	default:
		return nil, errors.New("parse attestation envelope: not a DSSE envelope")
	}
	if envelope.PayloadType != inTotoPayloadType {
		return nil, fmt.Errorf("parse attestation envelope: unsupported payload type %q", envelope.PayloadType)
	}
	payload, err := decodeDSSEPayload(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("parse attestation envelope: %w", err)
	}
	var statement inTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	return &statement, nil
}

func decodeDSSEPayload(payload string) ([]byte, error) {
	if payload == "" {
		return nil, errors.New("empty DSSE payload")
	}
	if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
		return decoded, nil
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	return decoded, nil
}

// cycloneDXVEXStatements extracts the analysed vulnerabilities from a CycloneDX
// VEX (or CycloneDX BOM with vulnerabilities[]) in-toto statement. Any other
// predicate returns errNotCycloneDXVEX.
func cycloneDXVEXStatements(statement *inTotoStatement, attestationDigest string) ([]OCIVEXStatement, error) {
	if statement == nil || len(statement.Predicate) == 0 {
		return nil, errNotCycloneDXVEX
	}
	var doc cdxDocument
	if err := json.Unmarshal(statement.Predicate, &doc); err != nil {
		if strings.HasPrefix(statement.PredicateType, cycloneDXPredicatePrefix) {
			return nil, fmt.Errorf("parse CycloneDX predicate: %w", err)
		}
		return nil, errNotCycloneDXVEX
	}
	if statement.PredicateType != cycloneDXVEXPredicateType && doc.BOMFormat != "CycloneDX" {
		return nil, errNotCycloneDXVEX
	}

	var timestamp time.Time
	if doc.Metadata != nil && doc.Metadata.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, doc.Metadata.Timestamp); err == nil {
			timestamp = parsed
		}
	}
	bomRefPURLs := map[string]string{}
	collectBOMRefPURLs(doc.Components, bomRefPURLs)

	var statements []OCIVEXStatement
	for _, vuln := range doc.Vulnerabilities {
		if vuln.ID == "" || vuln.Analysis == nil {
			continue
		}
		analysis := vuln.Analysis
		if analysis.State == "" && analysis.Justification == "" && analysis.Detail == "" && len(analysis.Response) == 0 {
			continue
		}
		ids := []string{vuln.ID}
		for _, reference := range vuln.References {
			if reference.ID != "" && reference.ID != vuln.ID {
				ids = append(ids, reference.ID)
			}
		}
		var purls []string
		for _, affect := range vuln.Affects {
			if strings.HasPrefix(affect.Ref, "pkg:") {
				purls = append(purls, affect.Ref)
			} else if purl := bomRefPURLs[affect.Ref]; purl != "" {
				purls = append(purls, purl)
			}
		}
		statements = append(statements, OCIVEXStatement{
			IDs:               ids,
			PURLs:             purls,
			State:             analysis.State,
			Justification:     analysis.Justification,
			Detail:            analysis.Detail,
			Responses:         append([]string(nil), analysis.Response...),
			AttestationDigest: attestationDigest,
			Timestamp:         timestamp,
		})
	}
	return statements, nil
}

func collectBOMRefPURLs(components []cdxDocComponent, out map[string]string) {
	for _, component := range components {
		if component.BOMRef != "" && strings.HasPrefix(component.PURL, "pkg:") {
			out[component.BOMRef] = component.PURL
		}
		collectBOMRefPURLs(component.Components, out)
	}
}

// parseOCIVEXAttestation turns one attestation blob into CycloneDX VEX
// statements. Non-CycloneDX predicates return errNotCycloneDXVEX.
func parseOCIVEXAttestation(data []byte, attestationDigest string) ([]OCIVEXStatement, error) {
	statement, err := parseAttestationStatement(data)
	if err != nil {
		return nil, err
	}
	return cycloneDXVEXStatements(statement, attestationDigest)
}

// annotateOCIVEX attaches the best matching statement to each finding. Findings
// are never removed or marked suppressed: the statement is evidence for review.
func annotateOCIVEX(findings []model.Finding, result *OCIVEXResult) int {
	if result == nil || len(result.Statements) == 0 {
		return 0
	}
	var annotated int
	for i := range findings {
		statement := selectOCIVEXStatement(findings[i], result.Statements)
		if statement == nil {
			continue
		}
		findings[i].VEX = &model.VEXAnalysis{
			Source:            ociVEXSource,
			Format:            ociVEXFormatCycloneDX,
			State:             statement.State,
			Justification:     statement.Justification,
			Detail:            statement.Detail,
			Responses:         append([]string(nil), statement.Responses...),
			StatementSource:   result.StatementSource,
			AttestationDigest: statement.AttestationDigest,
		}
		annotated++
	}
	return annotated
}

// selectOCIVEXStatement prefers a statement scoped to the finding's package over
// an image-wide one, then the newest document. A component-scoped statement is
// never applied to a finding whose package it does not name.
func selectOCIVEXStatement(finding model.Finding, statements []OCIVEXStatement) *OCIVEXStatement {
	var best *OCIVEXStatement
	bestSpecific := false
	for i := range statements {
		statement := &statements[i]
		if !statementMatchesID(*statement, finding) {
			continue
		}
		specific := len(statement.PURLs) > 0
		if specific && !purlMatchesAny(finding.PackagePURL, statement.PURLs) {
			continue
		}
		switch {
		case best == nil,
			specific && !bestSpecific,
			specific == bestSpecific && statement.Timestamp.After(best.Timestamp):
			best = statement
			bestSpecific = specific
		}
	}
	return best
}

func statementMatchesID(statement OCIVEXStatement, finding model.Finding) bool {
	for _, id := range statement.IDs {
		if strings.EqualFold(id, finding.ID) {
			return true
		}
		for _, vendorID := range finding.VendorIDs {
			if strings.EqualFold(id, vendorID) {
				return true
			}
		}
	}
	return false
}

// purlMatchesAny compares package URLs ignoring qualifiers and subpath. A
// versionless statement purl matches any version of the package.
func purlMatchesAny(findingPURL string, purls []string) bool {
	if findingPURL == "" {
		return false
	}
	findingBase, findingVersion := splitPURL(findingPURL)
	for _, purl := range purls {
		base, version := splitPURL(purl)
		if base != findingBase {
			continue
		}
		if version == "" || version == findingVersion {
			return true
		}
	}
	return false
}

func splitPURL(purl string) (string, string) {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if unescaped, err := url.PathUnescape(purl); err == nil {
		purl = unescaped
	}
	base, version := purl, ""
	if i := strings.LastIndex(purl, "@"); i > strings.LastIndex(purl, "/") {
		base, version = purl[:i], purl[i+1:]
	}
	return strings.ToLower(base), version
}

// applyOCIVEX fetches and attaches OCI CycloneDX VEX for one image. Any lookup
// or parse failure is logged and leaves the findings un-annotated.
func (r TrivyRunner) applyOCIVEX(ctx context.Context, image string, timeout time.Duration, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	fetcher := r.OCIVEXFetcher
	if fetcher == nil {
		fetcher = newRegistryVEXFetcher(r.RegistryAuths)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	result, err := fetcher.FetchVEX(ctx, image)
	if err != nil {
		r.Logger.Warn("OCI VEX lookup failed for %s: %v; findings are reported without VEX annotations", image, err)
		return
	}
	if result == nil {
		r.Logger.Debug("no OCI VEX attestations found for %s", image)
		return
	}
	for _, warning := range result.Warnings {
		r.Logger.Warn("OCI VEX attestation for %s skipped: %s", image, warning)
	}
	if annotated := annotateOCIVEX(findings, result); annotated > 0 {
		r.Logger.Info("OCI VEX: annotated %d findings for %s from %s", annotated, image, result.StatementSource)
	}
}
