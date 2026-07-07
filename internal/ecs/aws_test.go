package ecs

import (
	"context"
	"errors"
	"reflect"
	"testing"

	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestAWSClientInventoryListsAndDescribesActiveTaskDefinitions(t *testing.T) {
	api := &fakeECSAPI{
		listPages: []*awsecs.ListTaskDefinitionsOutput{
			{
				TaskDefinitionArns: []string{"arn:aws:ecs:us-east-1:123:task-definition/api:7"},
				NextToken:          stringPtr("next"),
			},
			{
				TaskDefinitionArns: []string{"arn:aws:ecs:us-east-1:123:task-definition/worker:2"},
			},
		},
		describe: map[string]*awsecs.DescribeTaskDefinitionOutput{
			"arn:aws:ecs:us-east-1:123:task-definition/api:7": {
				TaskDefinition: &types.TaskDefinition{
					TaskDefinitionArn: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/api:7"),
					Family:            stringPtr("api"),
					Revision:          7,
					Status:            types.TaskDefinitionStatusActive,
					NetworkMode:       types.NetworkModeAwsvpc,
					ExecutionRoleArn:  stringPtr("arn:aws:iam::123:role/exec"),
					TaskRoleArn:       stringPtr("arn:aws:iam::123:role/task"),
					RequiresCompatibilities: []types.Compatibility{
						types.CompatibilityFargate,
					},
					ContainerDefinitions: []types.ContainerDefinition{{
						Name:      stringPtr("api"),
						Image:     stringPtr("123.dkr.ecr.us-east-1.amazonaws.com/api:1"),
						Essential: boolPtr(true),
						RepositoryCredentials: &types.RepositoryCredentials{
							CredentialsParameter: stringPtr("arn:aws:secretsmanager:us-east-1:123:secret:dockerhub"),
						},
						PortMappings: []types.PortMapping{{
							ContainerPort: int32Ptr(443),
							HostPort:      int32Ptr(443),
							Protocol:      types.TransportProtocolTcp,
						}},
					}},
				},
			},
			"arn:aws:ecs:us-east-1:123:task-definition/worker:2": {
				TaskDefinition: &types.TaskDefinition{
					TaskDefinitionArn: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/worker:2"),
					Family:            stringPtr("worker"),
					Revision:          2,
					Status:            types.TaskDefinitionStatusActive,
					ContainerDefinitions: []types.ContainerDefinition{{
						Name:  stringPtr("worker"),
						Image: stringPtr("example.com/worker:2"),
					}},
				},
			},
		},
	}
	client := awsInventoryClient{region: "us-east-1", ecs: api}

	got, err := client.ListTaskDefinitions(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("ListTaskDefinitions returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("task definitions = %d, want 2: %#v", len(got), got)
	}
	wantFirst := TaskDefinition{
		Region:                  "us-east-1",
		Arn:                     "arn:aws:ecs:us-east-1:123:task-definition/api:7",
		Family:                  "api",
		Revision:                7,
		Status:                  "ACTIVE",
		NetworkMode:             "awsvpc",
		ExecutionRoleArn:        "arn:aws:iam::123:role/exec",
		TaskRoleArn:             "arn:aws:iam::123:role/task",
		RequiresCompatibilities: []string{"FARGATE"},
		Containers: []ContainerDefinition{{
			Name:                           "api",
			Image:                          "123.dkr.ecr.us-east-1.amazonaws.com/api:1",
			Essential:                      true,
			RepositoryCredentialsSecretARN: "arn:aws:secretsmanager:us-east-1:123:secret:dockerhub",
			PortMappings: []PortMapping{{
				ContainerPort: 443,
				HostPort:      443,
				Protocol:      "tcp",
			}},
		}},
	}
	if !reflect.DeepEqual(got[0], wantFirst) {
		t.Fatalf("first task definition = %#v, want %#v", got[0], wantFirst)
	}
}

type fakeECSAPI struct {
	listPages []*awsecs.ListTaskDefinitionsOutput
	describe  map[string]*awsecs.DescribeTaskDefinitionOutput
	listCalls int
}

func (f *fakeECSAPI) ListTaskDefinitions(ctx context.Context, input *awsecs.ListTaskDefinitionsInput, optFns ...func(*awsecs.Options)) (*awsecs.ListTaskDefinitionsOutput, error) {
	if input.Status != types.TaskDefinitionStatusActive {
		return nil, errors.New("status was not ACTIVE")
	}
	if f.listCalls >= len(f.listPages) {
		return &awsecs.ListTaskDefinitionsOutput{}, nil
	}
	page := f.listPages[f.listCalls]
	f.listCalls++
	return page, nil
}

func (f *fakeECSAPI) DescribeTaskDefinition(ctx context.Context, input *awsecs.DescribeTaskDefinitionInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeTaskDefinitionOutput, error) {
	return f.describe[*input.TaskDefinition], nil
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func int32Ptr(value int32) *int32 {
	return &value
}
