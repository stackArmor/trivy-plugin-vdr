package awsconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
)

// isolate points the SDK at temp config files with one profile, "p", and
// clears ambient credentials so the test never reads the caller's.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	credentials := filepath.Join(dir, "credentials")
	if err := os.WriteFile(config, []byte("[profile p]\nregion = us-gov-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentials, []byte("[p]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", config)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentials)
	for _, name := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestLoadUsesProfile(t *testing.T) {
	isolate(t)
	cfg, err := Load(context.Background(), "us-east-1", "p", "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIDPROFILE" {
		t.Fatalf("access key = %q, want the profile's", creds.AccessKeyID)
	}
	if cfg.Region != "us-east-1" {
		t.Fatalf("region = %q, an explicit region must win over the profile's", cfg.Region)
	}
}

func TestLoadUsesProfileThenRole(t *testing.T) {
	isolate(t)
	cfg, err := Load(context.Background(), "us-gov-west-1", "p", "arn:aws-us-gov:iam::111111111111:role/r")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cache, ok := cfg.Credentials.(*aws.CredentialsCache)
	if !ok || !cache.IsCredentialsProvider(&stscreds.AssumeRoleProvider{}) {
		t.Fatalf("credentials = %T, want a cached assume-role provider", cfg.Credentials)
	}
}

func TestLoadWithoutProfileOrRoleUsesDefaultChain(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	cfg, err := Load(context.Background(), "us-east-1", "", "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != "AKIDENV" {
		t.Fatalf("creds = %+v, err = %v; want the environment's", creds, err)
	}
}

func TestCLIEnvironment(t *testing.T) {
	if got := CLIEnvironment("p"); len(got) != 1 || got[0] != "AWS_PROFILE=p" {
		t.Fatalf("CLIEnvironment(p) = %v", got)
	}
	if got := CLIEnvironment(""); got != nil {
		t.Fatalf("CLIEnvironment(\"\") = %v, want nil", got)
	}
}
