package k8scompliance

import (
	"encoding/json"
	"time"
)

const ReportSchemaVersion = "k8s-compliance/v1"

type Report struct {
	ReportSchemaVersion string           `json:"reportSchemaVersion"`
	GeneratedAt         time.Time        `json:"generatedAt"`
	ScannerVersion      string           `json:"scannerVersion"`
	PluginVersion       string           `json:"pluginVersion"`
	ClusterName         string           `json:"clusterName"`
	Summary             Summary          `json:"summary"`
	Resources           []ResourceReport `json:"resources"`
	Warnings            []string         `json:"warnings,omitempty"`
}

type Summary struct {
	Resources       int            `json:"resources"`
	FailedResources int            `json:"failedResources"`
	FailedChecks    int            `json:"failedChecks"`
	BySeverity      map[string]int `json:"bySeverity"`
}

type ObjectRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

type ResourceReport struct {
	Resource         ObjectRef  `json:"resource"`
	ParentController *ObjectRef `json:"parentController,omitempty"`
	Results          []Result   `json:"results,omitempty"`
	Error            string     `json:"error,omitempty"`
}

type Result struct {
	Target         string          `json:"target"`
	Class          string          `json:"class,omitempty"`
	Type           string          `json:"type,omitempty"`
	MisconfSummary *MisconfSummary `json:"misconfSummary,omitempty"`
	Checks         []Check         `json:"checks,omitempty"`
}

type MisconfSummary struct {
	Successes int `json:"successes"`
	Failures  int `json:"failures"`
}

type Check struct {
	Type          string          `json:"type,omitempty"`
	ID            string          `json:"id"`
	AVDID         string          `json:"avdId,omitempty"`
	Title         string          `json:"title,omitempty"`
	Description   string          `json:"description,omitempty"`
	Message       string          `json:"message,omitempty"`
	Namespace     string          `json:"namespace,omitempty"`
	Query         string          `json:"query,omitempty"`
	Resolution    string          `json:"resolution,omitempty"`
	Severity      string          `json:"severity,omitempty"`
	PrimaryURL    string          `json:"primaryUrl,omitempty"`
	References    []string        `json:"references,omitempty"`
	Status        string          `json:"status,omitempty"`
	CauseMetadata json.RawMessage `json:"causeMetadata,omitempty"`
	Traces        []string        `json:"traces,omitempty"`
}
