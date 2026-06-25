package registry

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		image      string
		wantHost   string
		wantKind   Kind
		wantRegion string
	}{
		{"nginx", "docker.io", KindOther, ""},
		{"nginx:1.25", "docker.io", KindOther, ""},
		{"ghcr.io/org/app:v1", "ghcr.io", KindOther, ""},
		{"quay.io/org/app", "quay.io", KindOther, ""},
		{"gcr.io/proj/app:1", "gcr.io", KindGAR, ""},
		{"us.gcr.io/proj/app", "us.gcr.io", KindGAR, ""},
		{"us-central1-docker.pkg.dev/proj/repo/app:1", "us-central1-docker.pkg.dev", KindGAR, ""},
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1", "123456789012.dkr.ecr.us-east-1.amazonaws.com", KindECR, "us-east-1"},
		{"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com/app", "123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com", KindECR, "us-gov-west-1"},
		{"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app", "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", KindECR, "cn-north-1"},
		{"public.ecr.aws/x/app:1", "public.ecr.aws", KindOther, ""},
		{"gcr.io/proj/app@sha256:" + "0000000000000000000000000000000000000000000000000000000000000000", "gcr.io", KindGAR, ""},
		{"containers.na2.s1gov.net/cws-agent/s1agent:25.1.3-ga", "containers.na2.s1gov.net", KindOther, ""},
	}
	for _, c := range cases {
		got, err := Classify(c.image)
		if err != nil {
			t.Fatalf("Classify(%q) error: %v", c.image, err)
		}
		if got.Host != c.wantHost || got.Kind != c.wantKind || got.Region != c.wantRegion {
			t.Fatalf("Classify(%q) = %+v, want host=%q kind=%v region=%q", c.image, got, c.wantHost, c.wantKind, c.wantRegion)
		}
	}
}

func TestClassifyMalformed(t *testing.T) {
	if _, err := Classify("UPPER CASE not valid"); err == nil {
		t.Fatal("expected error for malformed image reference")
	}
}
