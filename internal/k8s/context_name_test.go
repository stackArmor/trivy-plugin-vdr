package k8s

import "testing"

func TestResolveContextName(t *testing.T) {
	tests := []struct {
		name         string
		explicit     string
		kubeContext  string
		apiServerURL string
		want         string
	}{
		{
			name:         "explicit wins over everything",
			explicit:     "tenant-prod-eks",
			kubeContext:  "arn:aws:eks:us-east-1:1234:cluster/other",
			apiServerURL: "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
			want:         "tenant-prod-eks",
		},
		{
			name:         "kubeconfig context when no explicit value",
			kubeContext:  "arn:aws:eks:us-east-1:1234:cluster/prod",
			apiServerURL: "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
			want:         "arn:aws:eks:us-east-1:1234:cluster/prod",
		},
		{
			name:         "in-cluster derives from the API server host",
			apiServerURL: "https://ABC123.gr7.us-east-1.eks.amazonaws.com:443",
			want:         "in-cluster/ABC123.gr7.us-east-1.eks.amazonaws.com",
		},
		{
			name:         "in-cluster tolerates a host with no scheme",
			apiServerURL: "10.100.0.1:443",
			want:         "in-cluster/10.100.0.1",
		},
		{
			name: "never empty",
			want: "in-cluster",
		},
		{
			name:        "whitespace-only values are ignored",
			explicit:    "   ",
			kubeContext: "\t",
			want:        "in-cluster",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveContextName(tc.explicit, tc.kubeContext, tc.apiServerURL)
			if got != tc.want {
				t.Fatalf("ResolveContextName(%q, %q, %q) = %q, want %q",
					tc.explicit, tc.kubeContext, tc.apiServerURL, got, tc.want)
			}
		})
	}
}

// The report identity must never be empty, because consumers degrade silently
// when it is: internal/report/cyclonedx.go omits the BOM root component, and the
// compliance report records a blank cluster name.
func TestResolveContextNameIsNeverEmpty(t *testing.T) {
	for _, apiServerURL := range []string{"", "   ", "://bad", "https://", "not a url at all"} {
		if got := ResolveContextName("", "", apiServerURL); got == "" {
			t.Fatalf("ResolveContextName(\"\", \"\", %q) returned an empty identity", apiServerURL)
		}
	}
}

func TestAPIServerHost(t *testing.T) {
	tests := map[string]string{
		"https://ABC.gr7.us-east-1.eks.amazonaws.com":     "ABC.gr7.us-east-1.eks.amazonaws.com",
		"https://ABC.gr7.us-east-1.eks.amazonaws.com:443": "ABC.gr7.us-east-1.eks.amazonaws.com",
		"https://10.100.0.1:6443/some/path":               "10.100.0.1",
		"kubernetes.default.svc":                          "kubernetes.default.svc",
		"":                                                "",
		"   ":                                             "",
	}
	for input, want := range tests {
		if got := apiServerHost(input); got != want {
			t.Fatalf("apiServerHost(%q) = %q, want %q", input, got, want)
		}
	}
}
