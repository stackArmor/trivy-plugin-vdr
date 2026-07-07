package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
)

// CommandRunner runs an external command (gcloud, aws) and returns stdout/stderr.
// It mirrors scanner.CommandRunner so it can be faked in tests.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// Options controls which credential sources Build consults.
type Options struct {
	EnableGcloud                 bool
	EnableECR                    bool
	GCPImpersonateServiceAccount string
	AWSRoleARN                   string
	Runner                       CommandRunner
}

// Result is the outcome of building registry credentials.
type Result struct {
	// Dir is the DOCKER_CONFIG directory holding config.json, or "" when no
	// credentials were assembled (Trivy then falls back to ambient auth).
	Dir string
	// Cleanup removes the temp directory; always safe to call.
	Cleanup func()
	// Warnings describes non-fatal problems (missing CLI, unreadable secret).
	// Token contents are never included.
	Warnings []string
	// Registries is the number of hosts with credentials configured.
	Registries int
}

// Build merges k8s secret credentials with cloud-CLI tokens for the registries
// referenced by images, writes a Docker config.json to a temp dir, and returns
// the dir for use as DOCKER_CONFIG. Failures of optional sources are recorded
// as warnings rather than errors.
func Build(ctx context.Context, images []string, secretAuths map[string]DockerAuth, opts Options, logger *log.Logger) (Result, error) {
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}

	var warnings []string
	ambientAuths, ambientRaw, err := readAmbientDockerConfig()
	if err != nil {
		warnings = append(warnings, "ambient Docker config ignored: "+err.Error())
	}

	auths := make(map[string]DockerAuth, len(ambientAuths)+len(secretAuths))
	for host, auth := range ambientAuths {
		auths[host] = auth
	}
	secretHosts := make(map[string]struct{}, len(secretAuths))
	for host, auth := range secretAuths {
		host = normalizeHost(host)
		auths[host] = normalizeAuth(auth)
		secretHosts[host] = struct{}{}
	}

	needGAR := false
	garHosts := map[string]struct{}{}
	ecrHosts := map[string]string{} // host -> region
	for _, image := range images {
		c, err := Classify(image)
		if err != nil {
			logger.Debug("registry: skipping unclassifiable image %q: %v", image, err)
			continue
		}
		switch c.Kind {
		case KindGAR:
			needGAR = true
			garHosts[c.Host] = struct{}{}
		case KindECR:
			ecrHosts[c.Host] = c.Region
		}
	}

	if needGAR && opts.EnableGcloud {
		args := []string{"auth", "print-access-token"}
		if opts.GCPImpersonateServiceAccount != "" {
			args = append(args, "--impersonate-service-account", opts.GCPImpersonateServiceAccount)
		}
		token, err := runToken(ctx, runner, "gcloud", args...)
		if err != nil {
			warnings = append(warnings, "Google Artifact Registry auth unavailable: "+cliError("gcloud", err))
		} else {
			for host := range garHosts {
				if _, exists := secretHosts[host]; exists {
					continue // explicit cluster secret wins
				}
				auths[host] = newAuth("oauth2accesstoken", token)
				logger.Debug("registry: configured gcloud credentials for %s", host)
			}
		}
	}

	if opts.EnableECR {
		env, err := awsRoleEnv(ctx, runner, opts.AWSRoleARN)
		if err != nil {
			warnings = append(warnings, "AWS role assumption unavailable: "+cliError("aws", err))
		}
		for _, host := range sortedKeys(ecrHosts) {
			if _, exists := secretHosts[host]; exists {
				continue
			}
			region := ecrHosts[host]
			token, err := runTokenWithEnv(ctx, runner, env, "aws", "ecr", "get-login-password", "--region", region)
			if err != nil {
				warnings = append(warnings, "AWS ECR auth unavailable for "+host+": "+cliError("aws", err))
				continue
			}
			auths[host] = newAuth("AWS", token)
			logger.Debug("registry: configured ECR credentials for %s", host)
		}
	}

	result := Result{Cleanup: func() {}, Warnings: warnings, Registries: len(auths)}
	if len(auths) == 0 {
		return result, nil
	}

	dir, err := os.MkdirTemp("", "vdr-dockercfg-")
	if err != nil {
		return result, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return result, err
	}
	data, err := marshalDockerConfig(ambientRaw, auths)
	if err != nil {
		os.RemoveAll(dir)
		return result, err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		os.RemoveAll(dir)
		return result, err
	}

	result.Dir = dir
	result.Cleanup = func() { os.RemoveAll(dir) }
	return result, nil
}

func readAmbientDockerConfig() (map[string]DockerAuth, map[string]json.RawMessage, error) {
	path, ok := ambientDockerConfigPath()
	if !ok {
		return nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, err
	}
	var cfg DockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, err
	}
	return normalizeAuths(cfg.Auths), raw, nil
}

func ambientDockerConfigPath() (string, bool) {
	if dir := strings.TrimSpace(os.Getenv("DOCKER_CONFIG")); dir != "" {
		return filepath.Join(dir, "config.json"), true
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", false
	}
	return filepath.Join(home, ".docker", "config.json"), true
}

func marshalDockerConfig(base map[string]json.RawMessage, auths map[string]DockerAuth) ([]byte, error) {
	if len(base) == 0 {
		return json.MarshalIndent(DockerConfig{Auths: auths}, "", "  ")
	}
	out := make(map[string]json.RawMessage, len(base)+1)
	for key, value := range base {
		out[key] = value
	}
	authData, err := json.Marshal(auths)
	if err != nil {
		return nil, err
	}
	out["auths"] = authData
	return json.MarshalIndent(out, "", "  ")
}

// runToken runs a command expected to print a credential token to stdout and
// returns the trimmed token. The token is never logged.
func runToken(ctx context.Context, runner CommandRunner, name string, args ...string) (string, error) {
	return runTokenWithEnv(ctx, runner, nil, name, args...)
}

type envCommandRunner interface {
	RunWithEnv(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error)
}

func runTokenWithEnv(ctx context.Context, runner CommandRunner, env []string, name string, args ...string) (string, error) {
	var stdout []byte
	var err error
	if len(env) > 0 {
		if envRunner, ok := runner.(envCommandRunner); ok {
			stdout, _, err = envRunner.RunWithEnv(ctx, env, name, args...)
		} else {
			stdout, _, err = runner.Run(ctx, name, args...)
		}
	} else {
		stdout, _, err = runner.Run(ctx, name, args...)
	}
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(stdout))
	if token == "" {
		return "", errEmptyToken
	}
	return token, nil
}

type awsAssumeRoleResponse struct {
	Credentials struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
	} `json:"Credentials"`
}

func awsRoleEnv(ctx context.Context, runner CommandRunner, roleARN string) ([]string, error) {
	if roleARN == "" {
		return nil, nil
	}
	stdout, _, err := runner.Run(ctx, "aws", "sts", "assume-role", "--role-arn", roleARN, "--role-session-name", "vdr-ecr-auth")
	if err != nil {
		return nil, err
	}
	var response awsAssumeRoleResponse
	if err := json.Unmarshal(stdout, &response); err != nil {
		return nil, err
	}
	if response.Credentials.AccessKeyID == "" || response.Credentials.SecretAccessKey == "" || response.Credentials.SessionToken == "" {
		return nil, errString("assume-role response missing credentials")
	}
	return []string{
		"AWS_ACCESS_KEY_ID=" + response.Credentials.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + response.Credentials.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + response.Credentials.SessionToken,
	}, nil
}

// cliError returns a token-free description of a failed CLI invocation.
func cliError(name string, err error) string {
	if errIsNotFound(err) {
		return name + " not found on PATH"
	}
	return name + " failed: " + err.Error()
}

func errIsNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "executable file not found")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type errString string

func (e errString) Error() string { return string(e) }

const errEmptyToken = errString("command produced an empty token")

// execRunner is the production CommandRunner.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return execRunner{}.RunWithEnv(ctx, nil, name, args...)
}

func (execRunner) RunWithEnv(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
