# Cluster scoring ConfigMap examples

`trivy-plugin-vdr` reads a ConfigMap named **`vdr-fedramp`** in the
**`fedramp-vdr-trivy`** namespace to set cluster-wide FedRAMP metadata and the
raw security-requirements rules used for PAIN scoring and the VDR-TFR-PVR remediation
deadline. The plugin reads it from the cluster automatically — no
`--scoring-config` flag is required.

This directory has a starter ConfigMap per managed-Kubernetes provider:

| file | provider |
|---|---|
| [`vdr-fedramp-configmap.gke.yaml`](vdr-fedramp-configmap.gke.yaml) | Google GKE |
| [`vdr-fedramp-configmap.eks.yaml`](vdr-fedramp-configmap.eks.yaml) | Amazon EKS |
| [`vdr-fedramp-configmap.aks.yaml`](vdr-fedramp-configmap.aks.yaml) | Azure AKS |

## What goes in the ConfigMap

Only tenant-specific overrides. The plugin ships the scoring algorithm, the
EPSS LEV threshold (`0.50`), and a `CR:H/IR:H/AR:H` cluster default that catches
new or otherwise-unclassified resources (noisy PAIN-4, single-agency).

The ConfigMap carries:

- `class` — your FedRAMP Certification Class (`A`/`B`/`C`/`D`).
- `multiAgency` — `"true"` if the cluster serves more than one agency.
- `scoring.yaml` — `nameRules` / `kindRules` / `namespaceRules` assigning raw
  `securityRequirements` vectors to cloud-managed, shared-responsibility components
  (`kube-system`, `gke-managed-*`, `amazon-cloudwatch`, `azure-*`, …) that cannot
  carry `vdr.fedramp.io/*` labels because their managed reconcilers revert manual
  changes.
- `internetAccessibleIngressClasses` / `internetAccessibleGatewayClasses` —
  optional lists of Ingress/Gateway class names to treat as internet-reachable
  (for edge load balancers built outside Kubernetes, e.g. ingress-nginx fronted by
  a standalone-NEG / Terraform L7 LB). A cleaner alternative to labeling each
  resource with `vdr.fedramp.io/internet-reachable` (which a Helm chart may apply
  to undesired resources). Each value is a YAML list, or a newline- or
  comma-separated string. A per-class `vdr.fedramp.io/internet-reachable` label
  still wins over the list. See
  [`../../docs/internet-reachability.md`](../../docs/internet-reachability.md).

> **Governance:** the calibratable PAIN word thresholds (`wordThresholds`) are
> **not** read from this ConfigMap — a `wordThresholds` block in the ConfigMap's
> `scoring.yaml` is ignored. They can only be changed via a governed
> `--scoring-config` file (or left at the built-in defaults
> 0.28115159694107 / 0.56230319388214 / 0.933), so
> the scoring calibration isn't altered by ad-hoc in-cluster edits.
>
Workloads you control should instead carry the label directly:

```yaml
metadata:
  labels:
    vdr.fedramp.io/security-requirements: cr-h_ir-m_ar-l
```

The wire value is Kubernetes-label-safe. Reports display this example as
`CR:H/IR:M/AR:L`.

## Resolution precedence

```
workload security-requirements label
  → namespace/project security-requirements label
  → securityRequirements nameRule   (ConfigMap scoring.yaml; first match wins)
  → securityRequirements kindRule   (ConfigMap scoring.yaml; first match wins)
  → securityRequirements namespaceRule (ConfigMap scoring.yaml; first match wins)
  → built-in CR:H/IR:H/AR:H default
```

`class` and `multiAgency` follow the same most-specific-wins idea: workload label →
namespace label → this ConfigMap → built-in default (`B`, single-agency).

## Apply

```bash
kubectl apply -f vdr-fedramp-configmap.<provider>.yaml
```

If the ConfigMap is absent, the plugin emits a warning and scores with its
built-in defaults — a missing ConfigMap is visible, not silent.

## Customize

Edit the `nameRules` / `kindRules` / `namespaceRules` to match the add-ons
actually installed in your cluster (the lists here cover common managed
components). Put specific rules before broad globs.

> **Note:** `cr-l_ir-h_ar-h` is for **metadata-only**
> foundation services the whole estate depends on — DNS, NTP, service discovery,
> plain L4 internal load balancers. Its low confidentiality requirement assumes the
> service sees only operational metadata (names, times, the call graph), not
> payload. Anything that **terminates TLS or handles request payload** (an internal
> LB doing TLS termination, a service-mesh sidecar that sees plaintext) should be
> a vector with the appropriate confidentiality requirement instead.
