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
	calls         []fakeCall
	outputs       map[string]string // keyed by command name
	outputsByArgs map[string]string
	errs          map[string]error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, fakeCall{name: name, args: args})
	key := name + " " + strings.Join(args, " ")
	if err, ok := f.errs[name]; ok {
		return nil, nil, err
	}
	if output, ok := f.outputsByArgs[key]; ok {
		return []byte(output), nil, nil
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

func TestBuildECRAssumesRoleARNBeforeLogin(t *testing.T) {
	runner := &fakeRunner{outputsByArgs: map[string]string{
		"aws sts assume-role --role-arn arn:aws:iam::123456789012:role/VDRReadOnly --role-session-name vdr-ecr-auth": `{
		  "Credentials": {
		    "AccessKeyId": "ASIAVDR",
		    "SecretAccessKey": "secret",
		    "SessionToken": "session"
		  }
		}`,
		"aws ecr get-login-password --region us-east-1": "ecr-token",
	}}

	res, err := Build(context.Background(),
		[]string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/a:1"},
		nil,
		Options{EnableECR: true, AWSRoleARN: "arn:aws:iam::123456789012:role/VDRReadOnly", Runner: runner},
		nil,
	)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	if got := runner.countCalls("aws"); got != 2 {
		t.Fatalf("aws called %d times, want sts assume-role and ecr login", got)
	}
	if len(runner.calls) != 2 || strings.Join(runner.calls[0].args, " ") != "sts assume-role --role-arn arn:aws:iam::123456789012:role/VDRReadOnly --role-session-name vdr-ecr-auth" {
		t.Fatalf("first call = %#v, want sts assume-role", runner.calls)
	}
	auths := readAuths(t, res.Dir)
	if auths["111111111111.dkr.ecr.us-east-1.amazonaws.com"].Password != "ecr-token" {
		t.Fatalf("unexpected ECR auth: %+v", auths["111111111111.dkr.ecr.us-east-1.amazonaws.com"])
	}
}

func TestBuildGcloudUsesImpersonatedServiceAccount(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"gcloud": "gar-token"}}

	res, err := Build(context.Background(),
		[]string{"gcr.io/p/a:1"},
		nil,
		Options{EnableGcloud: true, GCPImpersonateServiceAccount: "vdr-reader@example.iam.gserviceaccount.com", Runner: runner},
		nil,
	)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	if got := runner.countCalls("gcloud"); got != 1 {
		t.Fatalf("gcloud called %d times, want 1", got)
	}
	args := strings.Join(runner.calls[0].args, " ")
	if !strings.Contains(args, "--impersonate-service-account vdr-reader@example.iam.gserviceaccount.com") {
		t.Fatalf("gcloud args = %q, want impersonation flag", args)
	}
}

func TestBuildMergesAmbientDockerConfigWithGeneratedCredentials(t *testing.T) {
	ambientDir := t.TempDir()
	ambientAuth := newAuth("hub-user", "hub-pass")
	data, err := json.Marshal(map[string]any{
		"auths": map[string]DockerAuth{
			"https://index.docker.io/v1/": ambientAuth,
		},
		"credsStore": "desktop",
	})
	if err != nil {
		t.Fatalf("marshal ambient docker config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ambientDir, "config.json"), data, 0o600); err != nil {
		t.Fatalf("write ambient docker config: %v", err)
	}
	t.Setenv("DOCKER_CONFIG", ambientDir)

	runner := &fakeRunner{outputs: map[string]string{"gcloud": "gar-token"}}
	res, err := Build(context.Background(),
		[]string{"gcr.io/p/a:1", "ripcord/private:1"},
		nil,
		Options{EnableGcloud: true, Runner: runner},
		nil,
	)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	defer res.Cleanup()

	auths := readAuths(t, res.Dir)
	if auths["gcr.io"].Password != "gar-token" {
		t.Fatalf("missing generated GAR auth: %+v", auths["gcr.io"])
	}
	hub, ok := auths["docker.io"]
	if !ok {
		t.Fatalf("missing ambient Docker Hub auth, got keys %v", keys(auths))
	}
	if hub.Username != "hub-user" || hub.Password != "hub-pass" {
		t.Fatalf("unexpected Docker Hub auth: %+v", hub)
	}
	raw := readRawDockerConfig(t, res.Dir)
	if string(raw["credsStore"]) != `"desktop"` {
		t.Fatalf("credsStore = %s, want desktop", raw["credsStore"])
	}
}

func TestBuildGcloudFailureWarnsNoToken(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())

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
	t.Setenv("DOCKER_CONFIG", t.TempDir())

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

func readRawDockerConfig(t *testing.T, dir string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw config.json: %v", err)
	}
	return raw
}
