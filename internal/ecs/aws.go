package ecs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type ClientOptions struct{}

type AWSClient struct {
	options ClientOptions
	clients map[string]InventoryClient
	secrets map[string]*secretsmanager.Client
	cfgs    map[string]aws.Config
}

func NewAWSClient(ctx context.Context, options ...ClientOptions) (*AWSClient, error) {
	var clientOptions ClientOptions
	if len(options) > 0 {
		clientOptions = options[0]
	}
	return &AWSClient{
		options: clientOptions,
		clients: map[string]InventoryClient{},
		secrets: map[string]*secretsmanager.Client{},
		cfgs:    map[string]aws.Config{},
	}, nil
}

func (c *AWSClient) Close() error {
	return nil
}

func (c *AWSClient) ListTaskDefinitions(ctx context.Context, region string) ([]TaskDefinition, error) {
	client, ok := c.clients[region]
	if !ok {
		cfg, err := c.config(ctx, region)
		if err != nil {
			return nil, err
		}
		client = awsInventoryClient{region: region, ecs: awsecs.NewFromConfig(cfg)}
		c.clients[region] = client
	}
	return client.ListTaskDefinitions(ctx, region)
}

func (c *AWSClient) GetSecretString(ctx context.Context, region, secretARN string) (string, error) {
	client, ok := c.secrets[region]
	if !ok {
		cfg, err := c.config(ctx, region)
		if err != nil {
			return "", err
		}
		client = secretsmanager.NewFromConfig(cfg)
		c.secrets[region] = client
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN)})
	if err != nil {
		return "", err
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("secret has no string value")
	}
	return *out.SecretString, nil
}

func (c *AWSClient) CollectRuntimeSignals(ctx context.Context, regions []string) ([]RuntimeSignal, []string) {
	var signals []RuntimeSignal
	var warnings []string
	for _, region := range regions {
		cfg, err := c.config(ctx, region)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ECS runtime in %s unavailable: %v", region, err))
			continue
		}
		regionSignals, err := (awsRuntimeClient{ecs: awsecs.NewFromConfig(cfg)}).CollectRuntimeSignals(ctx, region)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ECS runtime in %s unavailable: %v", region, err))
			continue
		}
		signals = append(signals, regionSignals...)
	}
	return signals, warnings
}

func (c *AWSClient) CollectExposureGraph(ctx context.Context, regions []string, taskDefinitions []TaskDefinition) (ExposureGraph, []string) {
	graph := ExposureGraph{Ports: taskDefinitionPorts(taskDefinitions)}
	var warnings []string
	for _, region := range regions {
		cfg, err := c.config(ctx, region)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ECS exposure in %s unavailable: %v", region, err))
			continue
		}
		regionGraph, err := (awsExposureClient{
			ecs: awsecs.NewFromConfig(cfg),
			elb: elbv2.NewFromConfig(cfg),
			ec2: awsec2.NewFromConfig(cfg),
		}).CollectExposureGraph(ctx, region, taskDefinitionsInRegion(taskDefinitions, region))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ECS exposure in %s unavailable: %v", region, err))
			continue
		}
		graph.Services = append(graph.Services, regionGraph.Services...)
		graph.LoadBalancers = append(graph.LoadBalancers, regionGraph.LoadBalancers...)
		graph.Tasks = append(graph.Tasks, regionGraph.Tasks...)
		graph.SecurityGroups = append(graph.SecurityGroups, regionGraph.SecurityGroups...)
		for key, ports := range regionGraph.Ports {
			graph.Ports[key] = ports
		}
	}
	return graph, warnings
}

func (c *AWSClient) config(ctx context.Context, region string) (aws.Config, error) {
	if cfg, ok := c.cfgs[region]; ok {
		return cfg, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config for %s: %w", region, err)
	}
	c.cfgs[region] = cfg
	return cfg, nil
}

func taskDefinitionsInRegion(taskDefinitions []TaskDefinition, region string) []TaskDefinition {
	var result []TaskDefinition
	for _, taskDefinition := range taskDefinitions {
		if taskDefinition.Region == region {
			result = append(result, taskDefinition)
		}
	}
	return result
}

type ecsAPI interface {
	ListTaskDefinitions(ctx context.Context, input *awsecs.ListTaskDefinitionsInput, optFns ...func(*awsecs.Options)) (*awsecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(ctx context.Context, input *awsecs.DescribeTaskDefinitionInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeTaskDefinitionOutput, error)
}

type awsInventoryClient struct {
	region string
	ecs    ecsAPI
}

func (c awsInventoryClient) ListTaskDefinitions(ctx context.Context, region string) ([]TaskDefinition, error) {
	var taskDefinitions []TaskDefinition
	var nextToken *string
	for {
		page, err := c.ecs.ListTaskDefinitions(ctx, &awsecs.ListTaskDefinitionsInput{
			NextToken: nextToken,
			Status:    types.TaskDefinitionStatusActive,
		})
		if err != nil {
			return nil, fmt.Errorf("list task definitions: %w", err)
		}
		for _, arn := range page.TaskDefinitionArns {
			describe, err := c.ecs.DescribeTaskDefinition(ctx, &awsecs.DescribeTaskDefinitionInput{
				TaskDefinition: aws.String(arn),
			})
			if err != nil {
				return nil, fmt.Errorf("describe task definition %s: %w", arn, err)
			}
			if describe.TaskDefinition == nil {
				continue
			}
			taskDefinitions = append(taskDefinitions, convertTaskDefinition(region, *describe.TaskDefinition))
		}
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		nextToken = page.NextToken
	}
	return taskDefinitions, nil
}

func convertTaskDefinition(region string, taskDefinition types.TaskDefinition) TaskDefinition {
	converted := TaskDefinition{
		Region:           region,
		Arn:              aws.ToString(taskDefinition.TaskDefinitionArn),
		Family:           aws.ToString(taskDefinition.Family),
		Revision:         taskDefinition.Revision,
		Status:           string(taskDefinition.Status),
		NetworkMode:      string(taskDefinition.NetworkMode),
		ExecutionRoleArn: aws.ToString(taskDefinition.ExecutionRoleArn),
		TaskRoleArn:      aws.ToString(taskDefinition.TaskRoleArn),
	}
	for _, compatibility := range taskDefinition.RequiresCompatibilities {
		converted.RequiresCompatibilities = append(converted.RequiresCompatibilities, string(compatibility))
	}
	for _, container := range taskDefinition.ContainerDefinitions {
		converted.Containers = append(converted.Containers, convertContainerDefinition(container))
	}
	return converted
}

func convertContainerDefinition(container types.ContainerDefinition) ContainerDefinition {
	converted := ContainerDefinition{
		Name:                   aws.ToString(container.Name),
		Image:                  aws.ToString(container.Image),
		Essential:              aws.ToBool(container.Essential),
		Privileged:             aws.ToBool(container.Privileged),
		ReadonlyRootFilesystem: aws.ToBool(container.ReadonlyRootFilesystem),
		User:                   aws.ToString(container.User),
	}
	if container.LinuxParameters != nil {
		converted.InitProcessEnabled = container.LinuxParameters.InitProcessEnabled
		if container.LinuxParameters.Capabilities != nil {
			converted.CapabilitiesAdd = append([]string(nil), container.LinuxParameters.Capabilities.Add...)
			converted.CapabilitiesDrop = append([]string(nil), container.LinuxParameters.Capabilities.Drop...)
		}
	}
	if container.LogConfiguration != nil {
		converted.LogDriver = string(container.LogConfiguration.LogDriver)
	}
	if container.RepositoryCredentials != nil {
		converted.RepositoryCredentialsSecretARN = aws.ToString(container.RepositoryCredentials.CredentialsParameter)
	}
	for _, port := range container.PortMappings {
		converted.PortMappings = append(converted.PortMappings, PortMapping{
			ContainerPort: aws.ToInt32(port.ContainerPort),
			HostPort:      aws.ToInt32(port.HostPort),
			Protocol:      string(port.Protocol),
		})
	}
	for _, secret := range container.Secrets {
		converted.Secrets = append(converted.Secrets, SecretRef{
			Name:      aws.ToString(secret.Name),
			ValueFrom: aws.ToString(secret.ValueFrom),
		})
	}
	for _, envFile := range container.EnvironmentFiles {
		converted.EnvironmentFiles = append(converted.EnvironmentFiles, EnvironmentFileRef{
			Type:  string(envFile.Type),
			Value: aws.ToString(envFile.Value),
		})
	}
	return converted
}
