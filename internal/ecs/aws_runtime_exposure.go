package ecs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

type ecsRuntimeAPI interface {
	ListClusters(ctx context.Context, input *awsecs.ListClustersInput, optFns ...func(*awsecs.Options)) (*awsecs.ListClustersOutput, error)
	ListServices(ctx context.Context, input *awsecs.ListServicesInput, optFns ...func(*awsecs.Options)) (*awsecs.ListServicesOutput, error)
	DescribeServices(ctx context.Context, input *awsecs.DescribeServicesInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeServicesOutput, error)
	ListTasks(ctx context.Context, input *awsecs.ListTasksInput, optFns ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, input *awsecs.DescribeTasksInput, optFns ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error)
}

type elbAPI interface {
	DescribeTargetGroups(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	DescribeLoadBalancers(ctx context.Context, input *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
}

type ec2API interface {
	DescribeNetworkInterfaces(ctx context.Context, input *awsec2.DescribeNetworkInterfacesInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeNetworkInterfacesOutput, error)
	DescribeSecurityGroups(ctx context.Context, input *awsec2.DescribeSecurityGroupsInput, optFns ...func(*awsec2.Options)) (*awsec2.DescribeSecurityGroupsOutput, error)
}

type awsRuntimeClient struct {
	ecs ecsRuntimeAPI
}

func (c awsRuntimeClient) CollectRuntimeSignals(ctx context.Context, region string) ([]RuntimeSignal, error) {
	clusters, err := c.listClusters(ctx)
	if err != nil {
		return nil, err
	}
	var signals []RuntimeSignal
	for _, cluster := range clusters {
		services, err := c.listServices(ctx, cluster)
		if err != nil {
			return nil, err
		}
		for _, service := range services {
			if aws.ToString(service.TaskDefinition) == "" {
				continue
			}
			signals = append(signals, RuntimeSignal{
				TaskDefinitionArn: aws.ToString(service.TaskDefinition),
				Source:            RuntimeSourceService,
				Cluster:           cluster,
				Service:           aws.ToString(service.ServiceName),
				DesiredCount:      service.DesiredCount,
				RunningCount:      service.RunningCount,
			})
		}
		tasks, err := c.listRunningTasks(ctx, cluster)
		if err != nil {
			return nil, err
		}
		for _, task := range tasks {
			if aws.ToString(task.TaskDefinitionArn) == "" {
				continue
			}
			signals = append(signals, RuntimeSignal{
				TaskDefinitionArn: aws.ToString(task.TaskDefinitionArn),
				Source:            RuntimeSourceStandaloneTask,
				Cluster:           cluster,
				TaskArn:           aws.ToString(task.TaskArn),
			})
		}
	}
	return signals, nil
}

func (c awsRuntimeClient) listClusters(ctx context.Context) ([]string, error) {
	var clusters []string
	var nextToken *string
	for {
		out, err := c.ecs.ListClusters(ctx, &awsecs.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list ECS clusters: %w", err)
		}
		clusters = append(clusters, out.ClusterArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			return clusters, nil
		}
		nextToken = out.NextToken
	}
}

func (c awsRuntimeClient) listServices(ctx context.Context, cluster string) ([]ecstypes.Service, error) {
	var serviceARNs []string
	var nextToken *string
	for {
		out, err := c.ecs.ListServices(ctx, &awsecs.ListServicesInput{Cluster: aws.String(cluster), NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list ECS services in %s: %w", cluster, err)
		}
		serviceARNs = append(serviceARNs, out.ServiceArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	if len(serviceARNs) == 0 {
		return nil, nil
	}
	out, err := c.ecs.DescribeServices(ctx, &awsecs.DescribeServicesInput{Cluster: aws.String(cluster), Services: serviceARNs})
	if err != nil {
		return nil, fmt.Errorf("describe ECS services in %s: %w", cluster, err)
	}
	return out.Services, nil
}

func (c awsRuntimeClient) listRunningTasks(ctx context.Context, cluster string) ([]ecstypes.Task, error) {
	var taskARNs []string
	var nextToken *string
	for {
		out, err := c.ecs.ListTasks(ctx, &awsecs.ListTasksInput{Cluster: aws.String(cluster), DesiredStatus: ecstypes.DesiredStatusRunning, NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("list running ECS tasks in %s: %w", cluster, err)
		}
		taskARNs = append(taskARNs, out.TaskArns...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	if len(taskARNs) == 0 {
		return nil, nil
	}
	out, err := c.ecs.DescribeTasks(ctx, &awsecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: taskARNs})
	if err != nil {
		return nil, fmt.Errorf("describe running ECS tasks in %s: %w", cluster, err)
	}
	return out.Tasks, nil
}

type awsExposureClient struct {
	ecs ecsRuntimeAPI
	elb elbAPI
	ec2 ec2API
}

func (c awsExposureClient) CollectExposureGraph(ctx context.Context, region string, taskDefinitions []TaskDefinition) (ExposureGraph, error) {
	graph := ExposureGraph{Ports: taskDefinitionPorts(taskDefinitions)}
	taskDefinitionNames := taskDefinitionNamesByARN(taskDefinitions)
	runtimeClient := awsRuntimeClient{ecs: c.ecs}

	clusters, err := runtimeClient.listClusters(ctx)
	if err != nil {
		return graph, err
	}
	var eniIDs []string
	for _, cluster := range clusters {
		services, err := runtimeClient.listServices(ctx, cluster)
		if err != nil {
			return graph, err
		}
		for _, service := range services {
			name := taskDefinitionNames[aws.ToString(service.TaskDefinition)]
			if name == "" {
				continue
			}
			serviceExposure := ECSServiceExposure{
				Name:               aws.ToString(service.ServiceName),
				Cluster:            cluster,
				TaskDefinitionName: name,
			}
			for _, lb := range service.LoadBalancers {
				if aws.ToString(lb.TargetGroupArn) != "" {
					serviceExposure.TargetGroups = append(serviceExposure.TargetGroups, aws.ToString(lb.TargetGroupArn))
				}
			}
			graph.Services = append(graph.Services, serviceExposure)
		}
		tasks, err := runtimeClient.listRunningTasks(ctx, cluster)
		if err != nil {
			return graph, err
		}
		for _, task := range tasks {
			name := taskDefinitionNames[aws.ToString(task.TaskDefinitionArn)]
			if name == "" {
				continue
			}
			eni := taskENI(task)
			graph.Tasks = append(graph.Tasks, RunningTaskExposure{
				TaskArn:            aws.ToString(task.TaskArn),
				TaskDefinitionName: name,
				ENI:                eni,
			})
			if eni != "" {
				eniIDs = append(eniIDs, eni)
			}
		}
	}

	if err := c.addLoadBalancers(ctx, &graph); err != nil {
		return graph, err
	}
	if err := c.addNetworkInterfaces(ctx, &graph, eniIDs); err != nil {
		return graph, err
	}
	return graph, nil
}

func (c awsExposureClient) addLoadBalancers(ctx context.Context, graph *ExposureGraph) error {
	tgOut, err := c.elb.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{})
	if err != nil {
		return fmt.Errorf("describe target groups: %w", err)
	}
	lbOut, err := c.elb.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return fmt.Errorf("describe load balancers: %w", err)
	}
	lbs := map[string]elbtypes.LoadBalancer{}
	for _, lb := range lbOut.LoadBalancers {
		lbs[aws.ToString(lb.LoadBalancerArn)] = lb
	}
	for _, tg := range tgOut.TargetGroups {
		for _, lbArn := range tg.LoadBalancerArns {
			lb := lbs[lbArn]
			graph.LoadBalancers = append(graph.LoadBalancers, LoadBalancerExposure{
				Name:        aws.ToString(lb.LoadBalancerName),
				Scheme:      string(lb.Scheme),
				TargetGroup: aws.ToString(tg.TargetGroupArn),
			})
		}
	}
	return nil
}

func (c awsExposureClient) addNetworkInterfaces(ctx context.Context, graph *ExposureGraph, eniIDs []string) error {
	if len(eniIDs) == 0 {
		return nil
	}
	eniOut, err := c.ec2.DescribeNetworkInterfaces(ctx, &awsec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: eniIDs})
	if err != nil {
		return fmt.Errorf("describe network interfaces: %w", err)
	}
	securityGroupIDs := map[string]struct{}{}
	for _, eni := range eniOut.NetworkInterfaces {
		id := aws.ToString(eni.NetworkInterfaceId)
		for i := range graph.Tasks {
			if graph.Tasks[i].ENI != id {
				continue
			}
			if eni.Association != nil {
				graph.Tasks[i].PublicIP = aws.ToString(eni.Association.PublicIp)
			}
			for _, group := range eni.Groups {
				groupID := aws.ToString(group.GroupId)
				graph.Tasks[i].SecurityGroups = append(graph.Tasks[i].SecurityGroups, groupID)
				securityGroupIDs[groupID] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(securityGroupIDs))
	for id := range securityGroupIDs {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	sgOut, err := c.ec2.DescribeSecurityGroups(ctx, &awsec2.DescribeSecurityGroupsInput{GroupIds: ids})
	if err != nil {
		return fmt.Errorf("describe security groups: %w", err)
	}
	for _, group := range sgOut.SecurityGroups {
		graph.SecurityGroups = append(graph.SecurityGroups, convertSecurityGroup(group))
	}
	return nil
}

func taskDefinitionNamesByARN(taskDefinitions []TaskDefinition) map[string]string {
	result := map[string]string{}
	for _, taskDefinition := range taskDefinitions {
		result[taskDefinition.Arn] = taskDefinitionName(taskDefinition)
	}
	return result
}

func taskDefinitionPorts(taskDefinitions []TaskDefinition) map[string][]PortMapping {
	result := map[string][]PortMapping{}
	for _, taskDefinition := range taskDefinitions {
		taskDefinitionName := taskDefinitionName(taskDefinition)
		for _, container := range taskDefinition.Containers {
			name := container.Name
			if name == "" {
				name = "container"
			}
			result[taskDefinitionName+"/"+name] = append([]PortMapping(nil), container.PortMappings...)
		}
	}
	return result
}

func taskENI(task ecstypes.Task) string {
	for _, attachment := range task.Attachments {
		if aws.ToString(attachment.Type) != "ElasticNetworkInterface" {
			continue
		}
		for _, detail := range attachment.Details {
			if aws.ToString(detail.Name) == "networkInterfaceId" {
				return aws.ToString(detail.Value)
			}
		}
	}
	return ""
}

func convertSecurityGroup(group ec2types.SecurityGroup) SecurityGroupExposure {
	converted := SecurityGroupExposure{ID: aws.ToString(group.GroupId)}
	for _, permission := range group.IpPermissions {
		for _, ipRange := range permission.IpRanges {
			converted.Ingress = append(converted.Ingress, IngressRule{
				CIDR:     aws.ToString(ipRange.CidrIp),
				Protocol: aws.ToString(permission.IpProtocol),
				FromPort: aws.ToInt32(permission.FromPort),
				ToPort:   aws.ToInt32(permission.ToPort),
			})
		}
		for _, ipRange := range permission.Ipv6Ranges {
			converted.Ingress = append(converted.Ingress, IngressRule{
				CIDR:     aws.ToString(ipRange.CidrIpv6),
				Protocol: aws.ToString(permission.IpProtocol),
				FromPort: aws.ToInt32(permission.FromPort),
				ToPort:   aws.ToInt32(permission.ToPort),
			})
		}
	}
	return converted
}
