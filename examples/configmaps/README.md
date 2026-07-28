# Cluster scoring ConfigMap examples

`trivy-plugin-vdr` reads a ConfigMap named **`vdr-fedramp`** in the
**`fedramp-vdr-trivy`** namespace to set cluster-wide FedRAMP metadata and the
asset security-impact-profile rules used for PAIN scoring and the VDR-TFR-PVR remediation
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

- the governed disclosure/trusted-change/dependency reason registries used to
  derive CR/IR/AR from compositional traces,
- the optional illustrative named-archetype catalog,
- the scoring algorithm,
- the EPSS LEV threshold (`0.50`),
- the H/H/H **`unclassified`** cluster-default profile that catches new or
  otherwise-unclassified resources (noisy PAIN-4, single-agency) so they surface
  for deliberate classification.

The ConfigMap carries:

- `class` — your FedRAMP Certification Class (`A`/`B`/`C`/`D`).
- `multiAgency` — `"true"` if the cluster serves more than one agency.
- `securityRequirementsCeiling` — optional system-and-agency ceiling such as
  `cr-m_ir-m_ar-l`. It caps each resolved profile objective before PAIN is
  recalculated. Omit it to preserve profile scoring exactly; omission is not
  a warning.
- `scoring.yaml` — `nameRules` / `namespaceRules` assigning
  `securityImpactProfile` to the cloud-managed, shared-responsibility components
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
> The compositional `reasonCodes` registry is also governed built-in policy. A
> `reasonCodes` block in either the ConfigMap or `--scoring-config` is rejected;
> change the canonical policy and rebuild the plugin instead.

Workloads you control should instead carry the canonical label directly. The
value may be a direct vector (`cr-h_ir-m_ar-l`), governed decision trace, or
named archetype:

```yaml
metadata:
  labels:
    vdr.fedramp.io/security-impact-profile: regulated-data.authoritative-record.shared-critical-path
```

A CSP that starts with a scalar asset-value method must translate it to an
equal-dimension SIP value before assignment (`High` → `cr-h_ir-h_ar-h`, etc.).
There is no separate asset-value label or rule field.

## Resolution precedence

```
workload security-impact-profile label
  → namespace security-impact-profile label
  → securityImpactProfile nameRule   (ConfigMap scoring.yaml; first match wins)
  → securityImpactProfile kindRule   (ConfigMap scoring.yaml; first match wins)
  → securityImpactProfile namespaceRule (ConfigMap scoring.yaml; first match wins)
  → built-in "unclassified" default profile (H/H/H)
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

Edit the `nameRules` / `namespaceRules` to match the add-ons actually installed in
your cluster (the lists here cover the common managed components). Put specific
rules before broad globs. The authoritative CR/IR/AR derivation reasons and
the optional named-archetype examples are in
[`policy/vdr-policy.yaml`](../../policy/vdr-policy.yaml).

> **Note:** `platform-foundation` (CR:L, IR:H, AR:H) is for **metadata-only**
> foundation services the whole estate depends on — DNS, NTP, service discovery,
> plain L4 internal load balancers. Its low confidentiality requirement assumes the
> service sees only operational metadata (names, times, the call graph), not
> payload. Anything that **terminates TLS or handles request payload** (an internal
> LB doing TLS termination, a service-mesh sidecar that sees plaintext) should be
> `app-tier` or higher instead.
