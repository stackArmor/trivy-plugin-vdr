# Cluster scoring ConfigMap examples

`trivy-plugin-vdr` reads a ConfigMap named **`vdr-fedramp`** in the
**`kube-system`** namespace to set cluster-wide FedRAMP metadata and the
asset-archetype rules used for PAIN scoring and the VDR-TFR-PVR remediation
deadline. The plugin reads it from the cluster automatically — no
`--scoring-config` flag is required.

This directory has a starter ConfigMap per managed-Kubernetes provider:

| file | provider |
|---|---|
| [`vdr-fedramp-configmap.gke.yaml`](vdr-fedramp-configmap.gke.yaml) | Google GKE |
| [`vdr-fedramp-configmap.eks.yaml`](vdr-fedramp-configmap.eks.yaml) | Amazon EKS |
| [`vdr-fedramp-configmap.aks.yaml`](vdr-fedramp-configmap.aks.yaml) | Azure AKS |

## What goes in the ConfigMap

Only tenant-specific overrides. The plugin ships the full rubric built in:

- the archetype catalog (CR/IR/AR per archetype),
- the scoring algorithm,
- the EPSS LEV threshold (`0.70`),
- the H/H/H **`unclassified`** cluster-default archetype that catches new or
  otherwise-unclassified resources (noisy PAIN-4, single-agency) so they surface
  for deliberate classification.

The ConfigMap carries:

- `class` — your FedRAMP Certification Class (`A`/`B`/`C`/`D`).
- `multiAgency` — `"true"` if the cluster serves more than one agency.
- `scoring.yaml` — `nameRules` / `namespaceRules` assigning archetypes to the
  cloud-managed, shared-responsibility components (`kube-system`, `gke-managed-*`,
  `amazon-cloudwatch`, `azure-*`, …) that cannot carry `vdr.fedramp.io/*` labels
  because their managed reconcilers revert manual changes. The same `scoring.yaml`
  can override any built-in default — including the calibratable PAIN word
  thresholds (defaults shown):

  ```yaml
  scoring.yaml: |
    wordThresholds:
      narrow: 0.25        # S below this is Minimal
      disruptive: 0.55    # S at/above this is Disruptive
      debilitating: 0.85  # S at/above this is Debilitating
    nameRules: [ ... ]
  ```

Workloads you control should instead carry the label directly:

```yaml
metadata:
  labels:
    vdr.fedramp.io/asset-archetype: app-tier
```

## Resolution precedence

```
workload label
  → namespace label
  → nameRule   (ConfigMap scoring.yaml; first match wins)
  → namespaceRule (ConfigMap scoring.yaml; first match wins)
  → built-in "unclassified" default archetype (H/H/H)
```

`class` and `multiAgency` follow the same most-specific-wins idea: workload label →
namespace label → this ConfigMap → built-in default (`B`, single-agency).

## Apply

```bash
kubectl apply -f vdr-fedramp-configmap.<provider>.yaml
```

If the ConfigMap is absent, the plugin emits a warning and scores with its built-in
defaults — a missing ConfigMap is visible, not silent.

## Customize

Edit the `nameRules` / `namespaceRules` to match the add-ons actually installed in
your cluster (the lists here cover the common managed components). Put specific
rules before broad globs. Valid archetype names:

`cicd-pipeline`, `orchestrator`, `config-actuation`, `identity-secrets`,
`security-tooling`, `change-record`, `platform-foundation`, `data-sensitive`,
`data-backbone`, `app-tier`, `batch-analytics`, `public-edge`, `internal-tooling`,
`dev-test`.

> **Note:** `platform-foundation` (CR:L, IR:H, AR:H) is for **metadata-only**
> foundation services the whole estate depends on — DNS, NTP, service discovery,
> plain L4 internal load balancers. Its low confidentiality requirement assumes the
> service sees only operational metadata (names, times, the call graph), not
> payload. Anything that **terminates TLS or handles request payload** (an internal
> LB doing TLS termination, a service-mesh sidecar that sees plaintext) should be
> `app-tier` or higher instead.
