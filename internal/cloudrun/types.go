package cloudrun

import (
	"context"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const Provider = "gcp-cloud-run"

type Options struct {
	Project string
	Regions []string
}

type Container struct {
	Name  string
	Image string
}

type Service struct {
	Project          string
	Region           string
	Name             string
	Ingress          string
	URI              string
	RuntimeClassName string
	Labels           map[string]string
	Annotations      map[string]string
	Containers       []Container
}

type Job struct {
	Project     string
	Region      string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Containers  []Container
}

type InventoryClient interface {
	ListServices(ctx context.Context, project, region string) ([]Service, error)
	ListJobs(ctx context.Context, project, region string) ([]Job, error)
}

type ProjectLabelClient interface {
	GetProjectLabels(ctx context.Context, project string) (map[string]string, error)
}

type PolicyBinding struct {
	Role    string
	Members []string
}

type LoadBalancerRoute struct {
	Name                 string
	Scheme               string
	IPAddress            string
	TargetProxy          string
	URLMap               string
	BackendService       string
	ServerlessNEG        string
	CloudRunService      string
	CloudRunRegion       string
	IAPEnabled           bool
	IAPOAuth2ClientID    string
	CloudArmorPolicy     string
	BackendServiceRegion string
	Hostnames            []string
	Paths                []RoutePath
	Headers              []RouteHeader
	PathRedirects        []RouteRewrite
	BackendReference     string
}

type RoutePath = model.RoutePath
type RouteHeader = model.RouteHeader
type RouteRewrite = model.RouteRewrite

type ExposureClient interface {
	GetServicePolicy(ctx context.Context, project, region, service string) ([]PolicyBinding, error)
	ListLoadBalancerRoutes(ctx context.Context, project string) ([]LoadBalancerRoute, error)
}

type Collector struct {
	Client InventoryClient
}
