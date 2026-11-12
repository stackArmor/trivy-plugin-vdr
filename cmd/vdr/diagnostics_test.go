package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/config"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
)

func TestK8sDebugBundleCapturesSupportEvidenceAndSurvivesFailure(t *testing.T) {
	for _, tt := range []struct {
		name                         string
		enabled, denyJobs, failImage bool
	}{
		{name: "enabled", enabled: true}, {name: "disabled"}, {name: "inventory-fails", enabled: true, denyJobs: true},
		{name: "image-fails", enabled: true, failImage: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var eventsCalls int
			var methods []string
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/version" {
					fmt.Fprint(w, `{"gitVersion":"v1.34.1"}`)
					return
				}
				parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
				resource := parts[len(parts)-1]
				if resource == "vdr-fedramp" {
					w.WriteHeader(404)
					fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`)
					return
				}
				if resource == "roles" || resource == "jobs" && tt.denyJobs {
					w.WriteHeader(403)
					fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","reason":"Forbidden","message":"support role cannot list resource","code":403}`)
					return
				}
				kinds := map[string]string{"pods": "Pod", "events": "Event", "nodes": "Node", "namespaces": "Namespace", "jobs": "Job", "cronjobs": "CronJob", "deployments": "Deployment", "replicasets": "ReplicaSet", "daemonsets": "DaemonSet", "statefulsets": "StatefulSet", "services": "Service", "ingresses": "Ingress", "ingressclasses": "IngressClass", "networkpolicies": "NetworkPolicy", "poddisruptionbudgets": "PodDisruptionBudget"}
				kind, ok := kinds[resource]
				if !ok {
					w.WriteHeader(404)
					fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`)
					return
				}
				apiVersion := "v1"
				if parts[0] == "apis" {
					apiVersion = parts[1] + "/" + parts[2]
				}
				items := []any{}
				continuation := ""
				switch resource {
				case "pods":
					items = []any{map[string]any{"metadata": map[string]any{"name": "pull-pod", "namespace": "default", "ownerReferences": []any{map[string]any{"apiVersion": "batch/v1", "kind": "Job", "name": "migration", "controller": true}}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "runner", "image": "registry/migration:old", "env": []any{map[string]any{"name": "PASSWORD", "value": "must-never-leak"}}}}}, "status": map[string]any{"phase": "Pending", "containerStatuses": []any{map[string]any{"name": "runner", "state": map[string]any{"waiting": map[string]any{"reason": "ImagePullBackOff", "message": "MANIFEST_UNKNOWN: old image is gone"}}}}}}}
				case "jobs":
					items = []any{map[string]any{"metadata": map[string]any{"name": "migration", "namespace": "default", "creationTimestamp": "2026-10-01T01:00:00Z"}, "spec": map[string]any{"activeDeadlineSeconds": 600, "ttlSecondsAfterFinished": 3600, "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "runner", "image": "registry/migration:old"}}}}}, "status": map[string]any{"active": 1}}}
				case "cronjobs":
					items = []any{map[string]any{"metadata": map[string]any{"name": "nightly", "namespace": "default"}, "spec": map[string]any{"schedule": "0 1 * * *", "successfulJobsHistoryLimit": 3, "failedJobsHistoryLimit": 1, "jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "runner", "image": "registry/migration:current"}}}}}}}}}
				case "events":
					eventsCalls++
					message := "first pull error MANIFEST_UNKNOWN"
					if r.URL.Query().Get("continue") == "" {
						continuation = "next-event-page"
					} else {
						message = "later pull error"
					}
					items = []any{map[string]any{"metadata": map[string]any{"name": "pull-event", "namespace": "default"}, "reason": "Failed", "message": message, "involvedObject": map[string]any{"kind": "Pod", "name": "pull-pod", "namespace": "default"}}}
				case "namespaces":
					items = []any{map[string]any{"metadata": map[string]any{"name": "default"}}}
				}
				json.NewEncoder(w).Encode(map[string]any{"apiVersion": apiVersion, "kind": kind + "List", "metadata": map[string]any{"continue": continuation}, "items": items})
			}))
			defer fixture.Close()
			dir := t.TempDir()
			kubeconfig := fmt.Sprintf("apiVersion: v1\nkind: Config\ncurrent-context: customer\nclusters:\n- name: cluster\n  cluster:\n    server: %s\ncontexts:\n- name: customer\n  context:\n    cluster: cluster\n    user: scanner\nusers:\n- name: scanner\n  user:\n    token: must-never-leak-auth\n", fixture.URL)
			configPath := filepath.Join(dir, "kubeconfig")
			if err := os.WriteFile(configPath, []byte(kubeconfig), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("KUBECONFIG", configPath)
			t.Setenv("PATH", dir) // No external scanner/registry tools are needed.
			if tt.failImage {
				fakeTrivy := `#!/bin/sh
if [ "$1" = "version" ]; then echo '{"Version":"0.test"}'; exit 0; fi
for arg in "$@"; do
 case "$arg" in --download-db-only|--download-java-db-only) exit 0;; esac
 last="$arg"
done
if [ "$last" = "registry/migration:old" ]; then echo 'MANIFEST_UNKNOWN: image pruned' >&2; exit 1; fi
echo '{"Results":[]}'
`
				if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(fakeTrivy), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Default()
			cfg.ReachabilityOnly = !tt.failImage
			cfg.SkipRegistryAuth = true
			cfg.SkipEnrichment = true
			cfg.CacheDir = dir
			cfg.CacheCleanup = "never"
			cfg.ParallelScans = 1
			cfg.SkipExposure = true
			cfg.Namespaces = []string{"default"}
			cfg.AllNamespaces = false
			target := filepath.Join(dir, "support.zip")
			if tt.enabled {
				cfg.DebugBundle = target
			}
			var output bytes.Buffer
			scanErr := runK8s(context.Background(), cfg, log.NewWithWriter(io.Discard, log.LevelQuiet), &output)
			if (scanErr != nil) != (tt.denyJobs || tt.failImage) {
				t.Fatalf("runK8s error=%v denyJobs=%v", scanErr, tt.denyJobs)
			}
			for _, method := range methods {
				if method != "GET" {
					t.Fatalf("diagnostics mutated cluster: %s", method)
				}
			}
			if !tt.enabled {
				if eventsCalls != 0 {
					t.Fatal("extra diagnostic reads without flag")
				}
				if _, err := os.Stat(target); !os.IsNotExist(err) {
					t.Fatal("bundle created without flag")
				}
				return
			}
			if eventsCalls != 2 {
				t.Fatalf("pagination read %d event pages", eventsCalls)
			}
			archive, err := zip.OpenReader(target)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			files := map[string]string{}
			var all strings.Builder
			for _, file := range archive.File {
				r, _ := file.Open()
				data, readErr := io.ReadAll(r)
				r.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				files[file.Name] = string(data)
				all.Write(data)
			}
			if strings.Contains(all.String(), "must-never-leak") {
				t.Fatal("bundle leaked credentials")
			}
			for _, want := range []string{"ImagePullBackOff", "MANIFEST_UNKNOWN", "ownerReferences", "CronJobList", "failedJobsHistoryLimit", "later pull error", "Forbidden", "v1.34.1"} {
				if !strings.Contains(all.String(), want) {
					t.Errorf("missing support evidence %q", want)
				}
			}
			if tt.failImage && (scanErr != errCompletedWithFailures || !strings.Contains(files["manifest.json"], "completed with image scan failures") || !strings.Contains(files["scan/report.json"], "failedImages")) {
				t.Fatalf("image scan failure missing from bundle: %v", scanErr)
			}
			if tt.denyJobs {
				if !strings.Contains(files["manifest.json"], "scan error") || files["scan/error.json"] == "" {
					t.Fatal("failed scan did not preserve partial bundle")
				}
			} else {
				for _, name := range []string{"scan/report.json", "scan/inventory.json", "scan/settings.json", "scan/scoring-config.json", "scan/runtime-issues.json"} {
					if files[name] == "" {
						t.Errorf("missing %s", name)
					}
				}
				if !strings.Contains(all.String(), "activeDeadlineSeconds") {
					t.Fatal("job cleanup configuration missing")
				}
			}
		})
	}
}
