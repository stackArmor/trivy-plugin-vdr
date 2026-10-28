# Kubernetes RBAC examples

[`vdr-read.yaml`](vdr-read.yaml) is the canonical read-only ClusterRole for
`trivy vdr k8s`, with a ClusterRoleBinding template. Each rule is commented with
what it is used for and whether it is optional. `TestExampleRBACCoversCollectorReads`
fails if the plugin starts reading a resource this file does not grant, so copy
it instead of maintaining a separate list.

[`vdr-image-pull-secret-reader.yaml`](vdr-image-pull-secret-reader.yaml) grants
the VDR identity `get` access to explicitly named image-pull Secrets in one
namespace. It does not grant `list` or `watch` access to Secrets.

This is the limited alternative to granting `get` on all Secrets. Customers
whose pull-secret names change frequently can instead retain the broad
`secrets/get` rule from `vdr-read.yaml`. Choose one approach;
because Kubernetes RBAC is additive, applying this Role does not narrow a broad
permission granted elsewhere.

Before applying it:

1. Set `metadata.namespace` on both objects to a namespace VDR scans.
2. Replace `resourceNames` with the `imagePullSecrets` used by workloads in that
   namespace.
3. Set the `RoleBinding` subject to the ServiceAccount, user, or group that runs
   VDR.
4. Repeat the Role and RoleBinding for each scanned namespace.

For exact-name enforcement, ensure the VDR identity is not also bound to another
role that grants broader Secret access.
