package ecs

import (
	"fmt"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

type ExposureGraph struct {
	Services       []ECSServiceExposure
	LoadBalancers  []LoadBalancerExposure
	Tasks          []RunningTaskExposure
	SecurityGroups []SecurityGroupExposure
	Ports          map[string][]PortMapping
}

type ECSServiceExposure struct {
	Name               string
	Cluster            string
	TaskDefinitionName string
	TargetGroups       []string
}

type LoadBalancerExposure struct {
	Name        string
	Scheme      string
	TargetGroup string
}

type RunningTaskExposure struct {
	TaskArn            string
	TaskDefinitionName string
	ENI                string
	PublicIP           string
	SecurityGroups     []string
}

type SecurityGroupExposure struct {
	ID      string
	Ingress []IngressRule
}

type IngressRule struct {
	CIDR     string
	Protocol string
	FromPort int32
	ToPort   int32
}

func AnalyzeExposureFromGraph(inventory *model.Inventory, runtime map[string]RuntimeMetadata, graph ExposureGraph) map[model.ResourceRef]model.Exposure {
	exposures := map[model.ResourceRef]model.Exposure{}
	if inventory == nil {
		return exposures
	}
	lbsByTargetGroup := loadBalancersByTargetGroup(graph.LoadBalancers)
	securityGroups := securityGroupsByID(graph.SecurityGroups)

	for _, resource := range inventory.Resources {
		for _, image := range resource.Images {
			ref := resource.Resource
			ref.ContainerName = image.Name
			ref.ContainerType = image.ContainerType
			exposure := model.Exposure{
				Provider:           Provider,
				InternetAccessible: false,
				Evidence:           []string{fmt.Sprintf("ECS task definition %s is not internet reachable by collected evidence", ref.Name)},
			}
			status := runtime[ref.Name].Status
			if status == RuntimeDefinedOnly {
				exposure.Evidence = []string{fmt.Sprintf("task definition %s is defined_only; internet reachability not inferred without runtime evidence", ref.Name)}
				exposures[ref] = exposure
				continue
			}
			if serviceExposure, ok := loadBalancerExposure(ref.Name, graph.Services, lbsByTargetGroup); ok {
				exposure = serviceExposure
			}
			if taskExposure, ok := publicTaskExposure(ref, graph.Tasks, securityGroups, graph.Ports); ok {
				exposure = taskExposure
			}
			exposures[ref] = exposure
		}
	}
	return exposures
}

func loadBalancersByTargetGroup(loadBalancers []LoadBalancerExposure) map[string][]LoadBalancerExposure {
	result := map[string][]LoadBalancerExposure{}
	for _, lb := range loadBalancers {
		result[lb.TargetGroup] = append(result[lb.TargetGroup], lb)
	}
	return result
}

func securityGroupsByID(groups []SecurityGroupExposure) map[string]SecurityGroupExposure {
	result := map[string]SecurityGroupExposure{}
	for _, group := range groups {
		result[group.ID] = group
	}
	return result
}

func loadBalancerExposure(taskDefinitionName string, services []ECSServiceExposure, lbsByTargetGroup map[string][]LoadBalancerExposure) (model.Exposure, bool) {
	for _, service := range services {
		if service.TaskDefinitionName != taskDefinitionName {
			continue
		}
		for _, targetGroup := range service.TargetGroups {
			for _, lb := range lbsByTargetGroup[targetGroup] {
				if lb.Scheme != "internet-facing" {
					continue
				}
				return model.Exposure{
					InternetAccessible: true,
					Provider:           Provider,
					RouteKind:          "LoadBalancer",
					RouteName:          lb.Name,
					Evidence: []string{
						fmt.Sprintf("ECS service %s in cluster %s uses internet-facing load balancer %s and target group %s", service.Name, service.Cluster, lb.Name, targetGroup),
					},
				}, true
			}
		}
	}
	return model.Exposure{}, false
}

func publicTaskExposure(ref model.ResourceRef, tasks []RunningTaskExposure, securityGroups map[string]SecurityGroupExposure, ports map[string][]PortMapping) (model.Exposure, bool) {
	for _, task := range tasks {
		if task.TaskDefinitionName != ref.Name || task.PublicIP == "" {
			continue
		}
		for _, port := range ports[ref.Name+"/"+ref.ContainerName] {
			if openInternetIngress(task.SecurityGroups, securityGroups, port) {
				return model.Exposure{
					InternetAccessible: true,
					Provider:           Provider,
					RouteKind:          "TaskENI",
					RouteName:          task.ENI,
					Evidence: []string{
						fmt.Sprintf("running ECS task %s has public ENI %s with security group allowing internet ingress to %s/%d", task.TaskArn, task.ENI, protocol(port.Protocol), port.ContainerPort),
					},
				}, true
			}
		}
	}
	return model.Exposure{}, false
}

func openInternetIngress(groupIDs []string, groups map[string]SecurityGroupExposure, port PortMapping) bool {
	for _, groupID := range groupIDs {
		group := groups[groupID]
		for _, rule := range group.Ingress {
			if !internetCIDR(rule.CIDR) {
				continue
			}
			if protocol(rule.Protocol) != protocol(port.Protocol) && rule.Protocol != "-1" {
				continue
			}
			if rule.FromPort <= port.ContainerPort && port.ContainerPort <= rule.ToPort {
				return true
			}
		}
	}
	return false
}

func internetCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

func protocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "tcp"
	}
	return value
}
