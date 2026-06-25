package k8s

import (
	"context"
	"fmt"

	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CollectPullSecretAuths gathers the imagePullSecrets referenced by workload
// pod specs across the selected namespaces, fetches the referenced Secrets, and
// returns a merged host -> DockerAuth map for use as Trivy registry credentials.
//
// It reads only secrets named in pod specs (not ServiceAccounts). Missing
// secrets, RBAC denials, and parse failures are returned as warnings and do not
// abort collection; only context cancellation is a hard error.
func (c *Collector) CollectPullSecretAuths(ctx context.Context, opts Options, logger *log.Logger) (map[string]registry.DockerAuth, []string, error) {
	if c == nil || c.Client == nil {
		return nil, nil, nil
	}
	namespaces, err := namespacesForCollection(opts)
	if err != nil {
		return nil, nil, err
	}

	refs, warnings, err := c.collectPullSecretRefs(ctx, namespaces, opts)
	if err != nil {
		return nil, nil, err
	}

	auths := map[string]registry.DockerAuth{}
	for namespace, names := range refs {
		for name := range names {
			secret, err := c.Client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, nil, ctxErr
				}
				warnings = append(warnings, fmt.Sprintf("registry auth skipped secret %q in namespace %q: %v", name, namespace, err))
				continue
			}
			parsed, perr := parseRegistrySecret(secret)
			if perr != nil {
				warnings = append(warnings, fmt.Sprintf("registry auth could not parse secret %q in namespace %q: %v", name, namespace, perr))
				continue
			}
			for host, auth := range parsed {
				if _, exists := auths[host]; exists {
					continue // first secret wins
				}
				auths[host] = auth
				logger.Debug("registry auth: loaded credentials for %s from secret %s/%s", host, namespace, name)
			}
		}
	}

	return auths, warnings, nil
}

// collectPullSecretRefs returns namespace -> set of imagePullSecret names found
// across all collected workload pod specs.
func (c *Collector) collectPullSecretRefs(ctx context.Context, namespaces []string, opts Options) (map[string]map[string]struct{}, []string, error) {
	refs := map[string]map[string]struct{}{}
	var warnings []string

	add := func(namespace string, pullSecrets []corev1.LocalObjectReference) {
		for _, ref := range pullSecrets {
			if ref.Name == "" {
				continue
			}
			if refs[namespace] == nil {
				refs[namespace] = map[string]struct{}{}
			}
			refs[namespace][ref.Name] = struct{}{}
		}
	}

	for _, namespace := range namespaces {
		pods, err := c.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped Pods in namespace %q: %v", namespace, err))
		} else {
			for _, pod := range pods.Items {
				add(pod.Namespace, pod.Spec.ImagePullSecrets)
			}
		}

		deployments, err := c.Client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped Deployments in namespace %q: %v", namespace, err))
		} else {
			for _, d := range deployments.Items {
				add(d.Namespace, d.Spec.Template.Spec.ImagePullSecrets)
			}
		}

		statefulSets, err := c.Client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped StatefulSets in namespace %q: %v", namespace, err))
		} else {
			for _, s := range statefulSets.Items {
				add(s.Namespace, s.Spec.Template.Spec.ImagePullSecrets)
			}
		}

		daemonSets, err := c.Client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped DaemonSets in namespace %q: %v", namespace, err))
		} else {
			for _, ds := range daemonSets.Items {
				add(ds.Namespace, ds.Spec.Template.Spec.ImagePullSecrets)
			}
		}

		jobs, err := c.Client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped Jobs in namespace %q: %v", namespace, err))
		} else {
			for _, j := range jobs.Items {
				add(j.Namespace, j.Spec.Template.Spec.ImagePullSecrets)
			}
		}

		cronJobs, err := c.Client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("registry auth skipped CronJobs in namespace %q: %v", namespace, err))
		} else {
			for _, cj := range cronJobs.Items {
				add(cj.Namespace, cj.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets)
			}
		}
	}

	return refs, warnings, nil
}

// parseRegistrySecret extracts registry auths from a dockerconfigjson or legacy
// dockercfg Secret. Other secret types yield no auths.
func parseRegistrySecret(secret *corev1.Secret) (map[string]registry.DockerAuth, error) {
	switch secret.Type {
	case corev1.SecretTypeDockerConfigJson:
		data, ok := secret.Data[corev1.DockerConfigJsonKey]
		if !ok {
			return nil, fmt.Errorf("missing %q key", corev1.DockerConfigJsonKey)
		}
		return registry.ParseDockerConfigJSON(data)
	case corev1.SecretTypeDockercfg:
		data, ok := secret.Data[corev1.DockerConfigKey]
		if !ok {
			return nil, fmt.Errorf("missing %q key", corev1.DockerConfigKey)
		}
		return registry.ParseDockerCfg(data)
	default:
		return nil, nil
	}
}
