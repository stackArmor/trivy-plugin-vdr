package ecs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
)

type SecretsClient interface {
	GetSecretString(ctx context.Context, region, secretARN string) (string, error)
}

type repositoryCredentialSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func RepositoryCredentialAuths(ctx context.Context, taskDefinitions []TaskDefinition, client SecretsClient) (map[string]registry.DockerAuth, []string) {
	auths := map[string]registry.DockerAuth{}
	if client == nil {
		return auths, nil
	}

	var warnings []string
	for _, taskDefinition := range taskDefinitions {
		for _, container := range taskDefinition.Containers {
			if container.RepositoryCredentialsSecretARN == "" || container.Image == "" {
				continue
			}
			host, err := registry.HostFromImage(container.Image)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("ECS repository credentials for %s ignored: cannot parse image reference", taskDefinition.Name()))
				continue
			}
			if _, exists := auths[host]; exists {
				continue
			}
			secretString, err := client.GetSecretString(ctx, taskDefinition.Region, container.RepositoryCredentialsSecretARN)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("ECS repository credentials for %s on %s unavailable: %v", taskDefinition.Name(), host, err))
				continue
			}
			auth, err := parseRepositoryCredentialSecret(secretString)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("ECS repository credentials for %s on %s invalid: %v", taskDefinition.Name(), host, err))
				continue
			}
			auths[host] = auth
		}
	}
	return auths, warnings
}

func (t TaskDefinition) Name() string {
	return taskDefinitionName(t)
}

func parseRepositoryCredentialSecret(secretString string) (registry.DockerAuth, error) {
	var secret repositoryCredentialSecret
	if err := json.Unmarshal([]byte(secretString), &secret); err != nil {
		return registry.DockerAuth{}, fmt.Errorf("parse username/password JSON")
	}
	if secret.Username == "" || secret.Password == "" {
		return registry.DockerAuth{}, fmt.Errorf("missing username or password")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(secret.Username + ":" + secret.Password))
	return registry.DockerAuth{
		Username: secret.Username,
		Password: secret.Password,
		Auth:     encoded,
	}, nil
}
