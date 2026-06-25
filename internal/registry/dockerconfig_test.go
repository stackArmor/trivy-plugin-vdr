package registry

import (
	"encoding/base64"
	"testing"
)

func TestParseDockerConfigJSON(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	body := `{"auths":{"https://index.docker.io/v1/":{"auth":"` + auth + `"},"registry.example.com":{"username":"u","password":"p"}}}`

	got, err := ParseDockerConfigJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseDockerConfigJSON error: %v", err)
	}

	hub, ok := got["docker.io"]
	if !ok {
		t.Fatalf("expected docker.io key, got %v", keys(got))
	}
	if hub.Username != "user" || hub.Password != "pass" {
		t.Fatalf("auth not decoded: %+v", hub)
	}

	ex, ok := got["registry.example.com"]
	if !ok {
		t.Fatalf("expected registry.example.com key, got %v", keys(got))
	}
	if ex.Auth != base64.StdEncoding.EncodeToString([]byte("u:p")) {
		t.Fatalf("auth not computed from user/pass: %+v", ex)
	}
}

func TestParseDockerCfgLegacy(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("AWS:tok"))
	body := `{"123456789012.dkr.ecr.us-east-1.amazonaws.com":{"auth":"` + auth + `"}}`

	got, err := ParseDockerCfg([]byte(body))
	if err != nil {
		t.Fatalf("ParseDockerCfg error: %v", err)
	}
	entry, ok := got["123456789012.dkr.ecr.us-east-1.amazonaws.com"]
	if !ok {
		t.Fatalf("missing ecr key: %v", keys(got))
	}
	if entry.Username != "AWS" || entry.Password != "tok" {
		t.Fatalf("legacy auth not decoded: %+v", entry)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	if _, err := ParseDockerConfigJSON([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid dockerconfigjson")
	}
}

func TestNewAuth(t *testing.T) {
	a := newAuth("AWS", "secret")
	want := base64.StdEncoding.EncodeToString([]byte("AWS:secret"))
	if a.Auth != want {
		t.Fatalf("newAuth Auth = %q, want %q", a.Auth, want)
	}
}

func keys(m map[string]DockerAuth) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
