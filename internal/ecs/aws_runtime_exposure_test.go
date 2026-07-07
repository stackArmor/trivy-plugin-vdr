package ecs

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func TestAWSRuntimeClientCollectsServiceAndRunningTaskSignals(t *testing.T) {
	ecsAPI := &fakeRuntimeECSAPI{
		clusters: []string{"arn:aws:ecs:us-east-1:123:cluster/prod"},
		services: []ecstypes.Service{{
			ClusterArn:     stringPtr("arn:aws:ecs:us-east-1:123:cluster/prod"),
			ServiceName:    stringPtr("api"),
			TaskDefinition: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/api:7"),
			DesiredCount:   2,
			RunningCount:   1,
		}},
		tasks: []ecstypes.Task{{
			TaskArn:           stringPtr("arn:aws:ecs:us-east-1:123:task/prod/abc"),
			TaskDefinitionArn: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/api:7"),
		}},
	}
	client := awsRuntimeClient{ecs: ecsAPI}

	got, err := client.CollectRuntimeSignals(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("CollectRuntimeSignals returned error: %v", err)
	}

	want := []RuntimeSignal{
		{
			TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/api:7",
			Source:            RuntimeSourceService,
			Cluster:           "arn:aws:ecs:us-east-1:123:cluster/prod",
			Service:           "api",
			DesiredCount:      2,
			RunningCount:      1,
		},
		{
			TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/api:7",
			Source:            RuntimeSourceStandaloneTask,
			Cluster:           "arn:aws:ecs:us-east-1:123:cluster/prod",
			TaskArn:           "arn:aws:ecs:us-east-1:123:task/prod/abc",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %#v, want %#v", got, want)
	}
}

func TestAWSExposureClientBuildsLoadBalancerAndENIGraph(t *testing.T) {
	ecsAPI := &fakeRuntimeECSAPI{
		clusters: []string{"arn:aws:ecs:us-east-1:123:cluster/prod"},
		services: []ecstypes.Service{{
			ClusterArn:     stringPtr("arn:aws:ecs:us-east-1:123:cluster/prod"),
			ServiceName:    stringPtr("api"),
			TaskDefinition: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/api:7"),
			LoadBalancers: []ecstypes.LoadBalancer{{
				TargetGroupArn: stringPtr("tg-api"),
			}},
		}},
		tasks: []ecstypes.Task{{
			TaskArn:           stringPtr("arn:aws:ecs:us-east-1:123:task/prod/abc"),
			TaskDefinitionArn: stringPtr("arn:aws:ecs:us-east-1:123:task-definition/api:7"),
			Attachments: []ecstypes.Attachment{{
				Type: stringPtr("ElasticNetworkInterface"),
				Details: []ecstypes.KeyValuePair{{
					Name:  stringPtr("networkInterfaceId"),
					Value: stringPtr("eni-123"),
				}},
			}},
		}},
	}
	graphClient := awsExposureClient{
		ecs: ecsAPI,
		elb: &fakeELBAPI{
			targetGroups: []elbtypes.TargetGroup{{
				TargetGroupArn:   stringPtr("tg-api"),
				LoadBalancerArns: []string{"lb-public"},
			}},
			loadBalancers: []elbtypes.LoadBalancer{{
				LoadBalancerArn:  stringPtr("lb-public"),
				LoadBalancerName: stringPtr("app-public"),
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
			}},
		},
		ec2: &fakeEC2API{
			networkInterfaces: []ec2types.NetworkInterface{{
				NetworkInterfaceId: stringPtr("eni-123"),
				Association:        &ec2types.NetworkInterfaceAssociation{PublicIp: stringPtr("203.0.113.10")},
				Groups:             []ec2types.GroupIdentifier{{GroupId: stringPtr("sg-123")}},
			}},
			securityGroups: []ec2types.SecurityGroup{{
				GroupId: stringPtr("sg-123"),
				IpPermissions: []ec2types.IpPermission{{
					IpProtocol: aws.String("tcp"),
					FromPort:   int32Ptr(443),
					ToPort:     int32Ptr(443),
					IpRanges:   []ec2types.IpRange{{CidrIp: stringPtr("0.0.0.0/0")}},
				}},
			}},
		},
	}

	got, err := graphClient.CollectExposureGraph(context.Background(), "us-east-1", []TaskDefinition{{
		Arn:      "arn:aws:ecs:us-east-1:123:task-definition/api:7",
		Family:   "api",
		Revision: 7,
		Containers: []ContainerDefinition{{
			Name:         "api",
			PortMappings: []PortMapping{{ContainerPort: 443, Protocol: "tcp"}},
		}},
	}})
	if err != nil {
		t.Fatalf("CollectExposureGraph returned error: %v", err)
	}
	if len(got.Services) != 1 || got.Services[0].TargetGroups[0] != "tg-api" {
		t.Fatalf("Services = %#v", got.Services)
	}
	if len(got.LoadBalancers) != 1 || got.LoadBalancers[0].Scheme != "internet-facing" {
		t.Fatalf("LoadBalancers = %#v", got.LoadBalancers)
	}
	if len(got.Tasks) != 1 || got.Tasks[0].PublicIP != "203.0.113.10" || got.Tasks[0].SecurityGroups[0] != "sg-123" {
		t.Fatalf("Tasks = %#v", got.Tasks)
	}
	if len(got.SecurityGroups) != 1 || got.SecurityGroups[0].Ingress[0].CIDR != "0.0.0.0/0" {
		t.Fatalf("SecurityGroups = %#v", got.SecurityGroups)
	}
	if len(got.Ports["api:7/api"]) != 1 {
		t.Fatalf("Ports = %#v", got.Ports)
	}
}

type fakeRuntimeECSAPI struct {
	clusters []string
	services []ecstypes.Service
	tasks    []ecstypes.Task
}

func (f *fakeRuntimeECSAPI) ListClusters(ctx context.Context, input *awsecs.ListClustersInput, optFns ...func(*awsecs.Options)) (*awsecs.ListClustersOutput, error) {
	return &awsecs.ListClustersOutput{ClusterArns: append([]string(nil), f.clusters...)}, nil
}

func (f *fakeRuntimeECSAPI) ListServices(ctx context.Context, input *awsecs.ListServicesInput, optFns ...func(*awsecs.Options)) (*awsecs.ListServicesOutput, error) {
	arns := make([]string, len(f.services))
	for i, service := range f.services {
		arns[i] = aws.ToString(service.ServiceArn)
		if arns[i] == "" {
			arns[i] = aws.ToString(service.ServiceName)
		}
	}
	return &awsecs.ListServicesOutput{ServiceArns: arns}, nil
}

func (f *fakeRuntimeECSAPI) DescribeServices(ctx context.Context, input *awsecs.DescribeServicesInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeServicesOutput, error) {
	return &awsecs.DescribeServicesOutput{Services: append([]ecstypes.Service(nil), f.services...)}, nil
}

func (f *fakeRuntimeECSAPI) ListTasks(ctx context.Context, input *awsecs.ListTasksInput, optFns ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error) {
	arns := make([]string, len(f.tasks))
	for i, task := range f.tasks {
		arns[i] = aws.ToString(task.TaskArn)
	}
	return &awsecs.ListTasksOutput{TaskArns: arns}, nil
}

func (f *fakeRuntimeECSAPI) DescribeTasks(ctx context.Context, input *awsecs.DescribeTasksInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error) {
	return &awsecs.DescribeTasksOutput{Tasks: append([]ecstypes.Task(nil), f.tasks...)}, nil
}

type fakeELBAPI struct {
	targetGroups  []elbtypes.TargetGroup
	loadBalancers []elbtypes.LoadBalancer
}

func (f *fakeELBAPI) DescribeTargetGroups(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	return &elbv2.DescribeTargetGroupsOutput{TargetGroups: append([]elbtypes.TargetGroup(nil), f.targetGroups...)}, nil
}

func (f *fakeELBAPI) DescribeLoadBalancers(ctx context.Context, input *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: append([]elbtypes.LoadBalancer(nil), f.loadBalancers...)}, nil
}

type fakeEC2API struct {
	networkInterfaces []ec2types.NetworkInterface
	securityGroups    []ec2types.SecurityGroup
}

func (f *fakeEC2API) DescribeNetworkInterfaces(ctx context.Context, input *awsec2.DescribeNetworkInterfacesInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeNetworkInterfacesOutput, error) {
	return &awsec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: append([]ec2types.NetworkInterface(nil), f.networkInterfaces...)}, nil
}

func (f *fakeEC2API) DescribeSecurityGroups(ctx context.Context, input *awsec2.DescribeSecurityGroupsInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeSecurityGroupsOutput, error) {
	return &awsec2.DescribeSecurityGroupsOutput{SecurityGroups: append([]ec2types.SecurityGroup(nil), f.securityGroups...)}, nil
}
