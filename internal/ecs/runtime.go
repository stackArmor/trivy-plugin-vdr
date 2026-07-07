package ecs

import (
	"fmt"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

type RuntimeStatus string

const (
	RuntimeObservedRunning  RuntimeStatus = "observed_running"
	RuntimeServiceDesired   RuntimeStatus = "service_desired"
	RuntimeScheduled        RuntimeStatus = "scheduled"
	RuntimeStandaloneRecent RuntimeStatus = "standalone_recent"
	RuntimeDefinedOnly      RuntimeStatus = "defined_only"
)

type RuntimeSource string

const (
	RuntimeSourceService        RuntimeSource = "service"
	RuntimeSourceSchedule       RuntimeSource = "schedule"
	RuntimeSourceStandaloneTask RuntimeSource = "standalone_task"
)

type RuntimeSignal struct {
	TaskDefinitionArn string
	Source            RuntimeSource
	Cluster           string
	Service           string
	DesiredCount      int32
	RunningCount      int32
	ScheduleName      string
	TaskArn           string
}

type RuntimeMetadata struct {
	Status   RuntimeStatus
	Observed bool
	Evidence []string
}

func AnalyzeRuntime(taskDefinitions []TaskDefinition, signals []RuntimeSignal) map[string]RuntimeMetadata {
	byARN := map[string]string{}
	result := map[string]RuntimeMetadata{}
	for _, taskDefinition := range taskDefinitions {
		key := taskDefinitionName(taskDefinition)
		byARN[taskDefinition.Arn] = key
		result[key] = RuntimeMetadata{
			Status:   RuntimeDefinedOnly,
			Evidence: []string{fmt.Sprintf("task definition %s is defined_only; no service, schedule, or running task evidence was found", key)},
		}
	}

	for _, signal := range signals {
		key := byARN[signal.TaskDefinitionArn]
		if key == "" {
			continue
		}
		current := result[key]
		candidate := runtimeFromSignal(signal)
		if runtimePrecedence(candidate.Status) > runtimePrecedence(current.Status) {
			result[key] = candidate
			continue
		}
		if runtimePrecedence(candidate.Status) == runtimePrecedence(current.Status) {
			current.Evidence = append(current.Evidence, candidate.Evidence...)
			result[key] = current
		}
	}
	return result
}

func runtimeFromSignal(signal RuntimeSignal) RuntimeMetadata {
	switch signal.Source {
	case RuntimeSourceService:
		if signal.RunningCount > 0 {
			return RuntimeMetadata{
				Status:   RuntimeObservedRunning,
				Observed: true,
				Evidence: []string{fmt.Sprintf("ECS service %s in cluster %s uses task definition with desiredCount=%d runningCount=%d", signal.Service, signal.Cluster, signal.DesiredCount, signal.RunningCount)},
			}
		}
		if signal.DesiredCount > 0 {
			return RuntimeMetadata{
				Status:   RuntimeServiceDesired,
				Evidence: []string{fmt.Sprintf("ECS service %s in cluster %s desires %d task(s) with runningCount=%d", signal.Service, signal.Cluster, signal.DesiredCount, signal.RunningCount)},
			}
		}
	case RuntimeSourceSchedule:
		return RuntimeMetadata{
			Status:   RuntimeScheduled,
			Evidence: []string{fmt.Sprintf("ECS task definition is targeted by schedule %s", signal.ScheduleName)},
		}
	case RuntimeSourceStandaloneTask:
		return RuntimeMetadata{
			Status:   RuntimeStandaloneRecent,
			Evidence: []string{fmt.Sprintf("ECS standalone task %s was observed for this task definition", signal.TaskArn)},
		}
	}
	return RuntimeMetadata{Status: RuntimeDefinedOnly}
}

func runtimePrecedence(status RuntimeStatus) int {
	switch status {
	case RuntimeObservedRunning:
		return 5
	case RuntimeServiceDesired:
		return 4
	case RuntimeScheduled:
		return 3
	case RuntimeStandaloneRecent:
		return 2
	case RuntimeDefinedOnly:
		return 1
	default:
		return 0
	}
}

func AttachRuntimeMetadata(inventory *model.Inventory, runtime map[string]RuntimeMetadata) {
	if inventory == nil {
		return
	}
	for i := range inventory.Resources {
		key := inventory.Resources[i].Resource.Name
		metadata, ok := runtime[key]
		if !ok {
			continue
		}
		inventory.Resources[i].Runtime = &model.RuntimeMetadata{
			Status:   string(metadata.Status),
			Observed: metadata.Observed,
			Evidence: append([]string(nil), metadata.Evidence...),
		}
	}
}
