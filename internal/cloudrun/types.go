package cloudrun

import "context"

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
	Project     string
	Region      string
	Name        string
	Ingress     string
	URI         string
	Labels      map[string]string
	Annotations map[string]string
	Containers  []Container
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

type Collector struct {
	Client InventoryClient
}
