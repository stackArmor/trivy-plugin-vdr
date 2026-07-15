package ecs

import "context"

const Provider = "aws-ecs"

type Options struct {
	Regions []string
}

type TaskDefinition struct {
	Region                  string
	Arn                     string
	Family                  string
	Revision                int32
	Status                  string
	Tags                    map[string]string
	NetworkMode             string
	ExecutionRoleArn        string
	TaskRoleArn             string
	RequiresCompatibilities []string
	Containers              []ContainerDefinition
}

type ContainerDefinition struct {
	Name                           string
	Image                          string
	Essential                      bool
	Privileged                     bool
	ReadonlyRootFilesystem         bool
	User                           string
	CapabilitiesAdd                []string
	CapabilitiesDrop               []string
	DockerSecurityOptions          []string
	InitProcessEnabled             *bool
	LogDriver                      string
	RepositoryCredentialsSecretARN string
	PortMappings                   []PortMapping
	Secrets                        []SecretRef
	EnvironmentFiles               []EnvironmentFileRef
}

type PortMapping struct {
	ContainerPort int32
	HostPort      int32
	Protocol      string
}

type SecretRef struct {
	Name      string
	ValueFrom string
}

type EnvironmentFileRef struct {
	Type  string
	Value string
}

type InventoryClient interface {
	ListTaskDefinitions(ctx context.Context, region string) ([]TaskDefinition, error)
}

type Collector struct {
	Client InventoryClient
}
