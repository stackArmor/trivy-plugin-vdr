package chainanalysis

import (
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestFindResourceTransitionsRequiresExplicitPathAndSameResource(t *testing.T) {
	catalog := transitionTestCatalog(t)
	upstream := model.Finding{
		ID:               "CVE-2026-1000",
		PackageName:      "network-parser",
		InstalledVersion: "1.0",
		CVSSVector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWEs:             []string{"CWE-120"},
	}
	downstream := model.Finding{
		ID:               "CVE-2026-2000",
		PackageName:      "privileged-helper",
		InstalledVersion: "2.0",
		CVSSVector:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		CWEs:             []string{"CWE-648"},
	}
	upstream.ChainTaxonomy = ClassifyTaxonomy(upstream, catalog)
	downstream.ChainTaxonomy = ClassifyTaxonomy(downstream, catalog)
	resource := model.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "app"}

	got := FindResourceTransitions(resource, true, []model.Finding{upstream, downstream}, catalog)

	if len(got) != 1 {
		t.Fatalf("FindResourceTransitions = %#v, want one transition", got)
	}
	transition := got[0]
	if transition.CandidateClass != CAPECTransitionClass ||
		transition.Upstream.ID != upstream.ID || transition.Downstream.ID != downstream.ID ||
		transition.Upstream.Role != CAPECTransitionEntrypointRole ||
		transition.Downstream.Role != CAPECTransitionFollowerRole ||
		!reflect.DeepEqual(transition.Upstream.CWEIDs, []string{"CWE-120"}) ||
		transition.SourceCAPECID != "CAPEC-100" ||
		!reflect.DeepEqual(transition.Downstream.CWEIDs, []string{"CWE-648"}) ||
		transition.TargetCAPECID != "CAPEC-234" {
		t.Fatalf("transition = %#v, want CVE-1000/CAPEC-100 -> CAPEC-234/CVE-2000", transition)
	}
	if !transition.UpstreamInternetAccessible || transition.Upstream.AttackVector != "N" ||
		transition.Upstream.PrivilegesRequired != "N" ||
		transition.Downstream.AttackVector != "L" || transition.Downstream.PrivilegesRequired != "L" {
		t.Fatalf("transition context = %#v", transition)
	}
	if !reflect.DeepEqual(transition.SourceConsequenceImpacts, []string{"Execute Unauthorized Commands"}) ||
		!reflect.DeepEqual(transition.TargetPrerequisites, []string{"A privileged process is hijackable."}) {
		t.Fatalf("transition CAPEC evidence = %#v", transition)
	}
	if transition.EvidenceLevel != CAPECTransitionEvidenceLevel || transition.PolicyVersion != CAPECTransitionPolicyVersion {
		t.Fatalf("transition policy = %#v", transition)
	}
	if transition.Confidence != "low" || !transition.ReviewRequired {
		t.Fatalf("transition confidence = %#v, want low/review-required", transition)
	}
}

func TestAddTransitionSummaryCountsDistinctResourceEntrypoints(t *testing.T) {
	firstResource := model.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "app"}
	secondResource := model.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "worker", ContainerName: "app"}
	transitions := []model.CAPECTransitionCandidate{
		{Resource: firstResource, Upstream: model.CAPECTransitionEndpoint{ID: "CVE-A"}},
		{Resource: firstResource, Upstream: model.CAPECTransitionEndpoint{ID: "CVE-A"}},
		{Resource: firstResource, Upstream: model.CAPECTransitionEndpoint{ID: "CVE-B"}},
		{Resource: secondResource, Upstream: model.CAPECTransitionEndpoint{ID: "CVE-A"}},
	}
	summary := &model.ChainTaxonomySummary{}

	AddTransitionSummary(summary, transitions)

	if summary.TransitionCandidates != 4 || summary.EntrypointCandidates != 3 ||
		summary.UniqueEntrypointCVEs != 2 || summary.ResourcesWithTransitions != 2 {
		t.Fatalf("transition summary = %#v, want 4 transitions/3 resource entrypoints/2 CVEs/2 resources", summary)
	}
}

func TestFindResourceTransitionsDoesNotJoinUnrelatedOrSameCVE(t *testing.T) {
	catalog := transitionTestCatalog(t)
	first := model.Finding{ID: "CVE-SAME", CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CWEs: []string{"CWE-120"}}
	second := model.Finding{ID: "CVE-SAME", CVSSVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", CWEs: []string{"CWE-648"}}
	unrelated := model.Finding{ID: "CVE-OTHER", CVSSVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", CWEs: []string{"CWE-79"}}
	first.ChainTaxonomy = ClassifyTaxonomy(first, catalog)
	second.ChainTaxonomy = ClassifyTaxonomy(second, catalog)
	unrelated.ChainTaxonomy = ClassifyTaxonomy(unrelated, catalog)

	if got := FindResourceTransitions(model.ResourceRef{Kind: "Image", Name: "test"}, true, []model.Finding{first, second, unrelated}, catalog); len(got) != 0 {
		t.Fatalf("FindResourceTransitions = %#v, want no self/unrelated transition", got)
	}
}

func TestFindResourceTransitionsRequiresExternalUpstreamContext(t *testing.T) {
	catalog := transitionTestCatalog(t)
	resource := model.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "app"}
	upstream := model.Finding{
		ID:         "CVE-UPSTREAM",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWEs:       []string{"CWE-120"},
	}
	downstream := model.Finding{
		ID:         "CVE-DOWNSTREAM",
		CVSSVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		CWEs:       []string{"CWE-648"},
	}
	upstream.ChainTaxonomy = ClassifyTaxonomy(upstream, catalog)
	downstream.ChainTaxonomy = ClassifyTaxonomy(downstream, catalog)

	if got := FindResourceTransitions(resource, false, []model.Finding{upstream, downstream}, catalog); len(got) != 0 {
		t.Fatalf("unexposed transitions = %#v, want none", got)
	}
	privilegedUpstream := upstream
	privilegedUpstream.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	if got := FindResourceTransitions(resource, true, []model.Finding{privilegedUpstream, downstream}, catalog); len(got) != 0 {
		t.Fatalf("privileged upstream transitions = %#v, want none", got)
	}
	networkDownstream := downstream
	networkDownstream.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	if got := FindResourceTransitions(resource, true, []model.Finding{upstream, networkDownstream}, catalog); len(got) != 1 {
		t.Fatalf("network downstream transitions = %#v, want one", got)
	}
	unknownDownstream := downstream
	unknownDownstream.CVSSVector = ""
	if got := FindResourceTransitions(resource, true, []model.Finding{upstream, unknownDownstream}, catalog); len(got) != 1 {
		t.Fatalf("unknown-vector downstream transitions = %#v, want one", got)
	}
}

func TestFindResourceTransitionsAggregatesPackageOccurrences(t *testing.T) {
	catalog := transitionTestCatalog(t)
	resource := model.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "app"}
	upstreamA := model.Finding{
		ID: "CVE-UPSTREAM", PackageName: "parser-a", InstalledVersion: "1.0",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CWEs: []string{"CWE-120"},
	}
	upstreamB := upstreamA
	upstreamB.PackageName = "parser-b"
	downstreamA := model.Finding{
		ID: "CVE-DOWNSTREAM", PackageName: "helper-a", InstalledVersion: "2.0",
		CVSSVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", CWEs: []string{"CWE-648"},
	}
	downstreamB := downstreamA
	downstreamB.PackageName = "helper-b"
	upstreamA.ChainTaxonomy = ClassifyTaxonomy(upstreamA, catalog)
	upstreamB.ChainTaxonomy = ClassifyTaxonomy(upstreamB, catalog)
	downstreamA.ChainTaxonomy = ClassifyTaxonomy(downstreamA, catalog)
	downstreamB.ChainTaxonomy = ClassifyTaxonomy(downstreamB, catalog)

	got := FindResourceTransitions(resource, true, []model.Finding{upstreamA, upstreamB, downstreamA, downstreamB}, catalog)

	if len(got) != 1 || len(got[0].Upstream.Findings) != 2 || len(got[0].Downstream.Findings) != 2 {
		t.Fatalf("aggregated transitions = %#v, want one candidate with two occurrences per endpoint", got)
	}
}

func transitionTestCatalog(t *testing.T) *chaincatalog.Catalog {
	t.Helper()
	raw := []byte(`{
		"schemaVersion":"1",
		"sources":{
			"capecVersion":"test",
			"capecSha256":"capec",
			"attackVersion":"test",
			"attackSha256":"attack"
		},
		"patterns":{
			"CAPEC-100":{
				"id":"CAPEC-100",
				"name":"Overflow Buffers",
				"abstraction":"Standard",
				"status":"Stable",
				"cwes":["CWE-120"],
				"successors":["CAPEC-234"],
				"consequences":[{"impact":"Execute Unauthorized Commands"}]
			},
			"CAPEC-234":{
				"id":"CAPEC-234",
				"name":"Hijacking a Privileged Process",
				"abstraction":"Standard",
				"status":"Stable",
				"cwes":["CWE-648"],
				"predecessors":["CAPEC-100"],
				"prerequisites":["A privileged process is hijackable."]
			},
			"CAPEC-63":{
				"id":"CAPEC-63",
				"name":"Cross-Site Scripting",
				"abstraction":"Standard",
				"status":"Stable",
				"cwes":["CWE-79"]
			}
		},
		"cwes":{
			"CWE-120":["CAPEC-100"],
			"CWE-648":["CAPEC-234"],
			"CWE-79":["CAPEC-63"]
		}
	}`)
	catalog, err := chaincatalog.Parse(raw)
	if err != nil {
		t.Fatalf("parse transition catalog: %v", err)
	}
	return catalog
}
