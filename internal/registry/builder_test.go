package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls   []fakeCall
	outputs map[string]string // keyed by command name
	errs    map[string]error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, fakeCall{name: name, args: args})
	if err, ok := f.errs[name]; ok {
		return nil, nil, err
	}
	return []byte(f.outputs[name]), nil, nil
}

func (f *fakeRunner) countCalls(name string) int {
	n := 0
	for _, c := range f.calls {
		if c.name == name {
			n++
		}
	}
	return n
}

func TestBuildGcloudCalledOnceForMultipleGARHosts(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"gcloud": "gar-token"}}
	images := []string{
		"gcr.io/p/a:1",
		"us-central1-docker.pkg.dev/p/r/b:2",
		"gcr.io/p/c:3",
	}
	res, err := Build(context.Background(), images, nil, Options{EnableGcloud: true, Runner: runner}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	if got := runner.countCalls("gcloud"); got != 1 {
		t.Fatalf("gcloud called %d times, want 1", got)
	}
	auths := readAuths(t, res.Dir)
	for _, host := range []string{"gcr.io", "us-central1-docker.pkg.dev"} {
		a, ok := auths[host]
		if !ok {
			t.Fatalf("missing auth for %s", host)
		}
		if a.Username != "oauth2accesstoken" || a.Password != "gar-token" {
			t.Fatalf("unexpected GAR auth for %s: %+v", host, a)
		}
	}
}

func TestBuildECRCalledOncePerRegion(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"aws": "ecr-token"}}
	images := []string{
		"111111111111.dkr.ecr.us-east-1.amazonaws.com/a:1",
		"111111111111.dkr.ecr.us-east-1.amazonaws.com/b:2", // same host -> no extra call
		"222222222222.dkr.ecr.eu-west-1.amazonaws.com/c:3",
	}
	res, err := Build(context.Background(), images, nil, Options{EnableECR: true, Runner: runner}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	if got := runner.countCalls("aws"); got != 2 {
		t.Fatalf("aws called %d times, want 2", got)
	}
	// Verify region was threaded into the argv.
	regions := map[string]bool{}
	for _, c := range runner.calls {
		if c.name == "aws" {
			for i, a := range c.args {
				if a == "--region" && i+1 < len(c.args) {
					regions[c.args[i+1]] = true
				}
			}
		}
	}
	if !regions["us-east-1"] || !regions["eu-west-1"] {
		t.Fatalf("expected both regions, got %v", regions)
	}
}

func TestBuildGcloudFailureWarnsNoToken(t *testing.T) {
	runner := &fakeRunner{errs: map[string]error{"gcloud": errors.New("exec: \"gcloud\": executable file not found in $PATH")}}
	res, err := Build(context.Background(), []string{"gcr.io/p/a:1"}, nil, Options{EnableGcloud: true, Runner: runner}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	if res.Dir != "" {
		t.Fatalf("expected no config dir when only source failed, got %q", res.Dir)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "gcloud not found") {
		t.Fatalf("expected gcloud-not-found warning, got %v", res.Warnings)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "token") && strings.Contains(w, "gar") {
			t.Fatalf("warning leaked token-like content: %q", w)
		}
	}
}

func TestBuildSecretPrecedenceOverCloud(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"gcloud": "gar-token"}}
	secretAuths := map[string]DockerAuth{
		"gcr.io": newAuth("secretuser", "secretpass"),
	}
	res, err := Build(context.Background(), []string{"gcr.io/p/a:1"}, secretAuths, Options{EnableGcloud: true, Runner: runner}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	auths := readAuths(t, res.Dir)
	if auths["gcr.io"].Username != "secretuser" {
		t.Fatalf("secret should win over cloud token, got %+v", auths["gcr.io"])
	}
}

func TestBuildEmptyNoDir(t *testing.T) {
	res, err := Build(context.Background(), []string{"nginx:1.25"}, nil, Options{EnableGcloud: true, EnableECR: true, Runner: &fakeRunner{}}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()
	if res.Dir != "" {
		t.Fatalf("expected empty dir for public-only images, got %q", res.Dir)
	}
}

func TestBuildFilePermissions(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"gcloud": "tok"}}
	res, err := Build(context.Background(), []string{"gcr.io/p/a:1"}, nil, Options{EnableGcloud: true, Runner: runner}, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	dirInfo, err := os.Stat(res.Dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != fs.FileMode(0o700) {
		t.Fatalf("dir perm = %o, want 700", perm)
	}
	fileInfo, err := os.Stat(filepath.Join(res.Dir, "config.json"))
	if err != nil {
		t.Fatalf("stat config.json: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != fs.FileMode(0o600) {
		t.Fatalf("config.json perm = %o, want 600", perm)
	}
}

func readAuths(t *testing.T, dir string) map[string]DockerAuth {
	t.Helper()
	if dir == "" {
		t.Fatal("expected a config dir but got empty")
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var cfg DockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config.json: %v", err)
	}
	return cfg.Auths
}
