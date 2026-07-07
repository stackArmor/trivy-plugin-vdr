package ecs

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestRegistryAuthLoadsRepositoryCredentialsFromSecretsManager(t *testing.T) {
	secrets := &fakeSecretsClient{
		values: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123:secret:dockerhub": `{"username":"docker-user","password":"docker-pass"}`,
		},
	}
	taskDefinitions := []TaskDefinition{{
		Region:   "us-east-1",
		Family:   "api",
		Revision: 7,
		Containers: []ContainerDefinition{{
			Name:                           "api",
			Image:                          "registry.example.com/api:1",
			RepositoryCredentialsSecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:dockerhub",
		}},
	}}

	auths, warnings := RepositoryCredentialAuths(context.Background(), taskDefinitions, secrets)

	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	auth, ok := auths["registry.example.com"]
	if !ok {
		t.Fatalf("auth hosts = %#v, want registry.example.com", auths)
	}
	if auth.Username != "docker-user" || auth.Password != "docker-pass" {
		t.Fatalf("auth = %#v, want docker-user/docker-pass", auth)
	}
	wantAuth := base64.StdEncoding.EncodeToString([]byte("docker-user:docker-pass"))
	if auth.Auth != wantAuth {
		t.Fatalf("Auth = %q, want %q", auth.Auth, wantAuth)
	}

	gotInventory, err := (Collector{Client: &fakeInventoryClient{taskDefinitions: map[string][]TaskDefinition{"us-east-1": taskDefinitions}}}).Collect(context.Background(), Options{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if strings.Contains(gotInventory.Images[0].ImageRef, "docker-pass") || strings.Contains(reflect.ValueOf(gotInventory).String(), "docker-pass") {
		t.Fatalf("inventory leaked repository credential secret: %#v", gotInventory)
	}
}

func TestRegistryAuthWarningsDoNotIncludeSecretValues(t *testing.T) {
	secrets := &fakeSecretsClient{
		values: map[string]string{
			"arn:aws:secretsmanager:us-east-1:123:secret:bad": `{"username":"docker-user","password":"docker-pass"`,
		},
	}
	taskDefinitions := []TaskDefinition{{
		Region: "us-east-1",
		Containers: []ContainerDefinition{{
			Image:                          "registry.example.com/api:1",
			RepositoryCredentialsSecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:bad",
		}},
	}}

	_, warnings := RepositoryCredentialAuths(context.Background(), taskDefinitions, secrets)

	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want one", warnings)
	}
	if strings.Contains(warnings[0], "docker-user") || strings.Contains(warnings[0], "docker-pass") {
		t.Fatalf("warning leaked secret value: %q", warnings[0])
	}
}

type fakeSecretsClient struct {
	values map[string]string
}

func (f *fakeSecretsClient) GetSecretString(ctx context.Context, region, secretARN string) (string, error) {
	return f.values[secretARN], nil
}
