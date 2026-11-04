# Docker Swarm config example

> Requires a trivy-plugin-vdr release that includes the `swarm` source. See
> [Docker Swarm scanning](../../README.md#docker-swarm-scanning) for the scan
> command.

For a Docker Swarm cluster, `trivy-plugin-vdr` reads its cluster-wide FedRAMP
metadata, security impact profiles and internet-reachability declarations from
a Swarm config object named **`vdr-fedramp`** by default. Use
`--swarm-config-name <name>` to select another config when collecting over SSM.
It plays the same role as the
`vdr-fedramp` ConfigMap on Kubernetes ([`../configmaps`](../configmaps)).

[`vdr-fedramp.yaml`](vdr-fedramp.yaml) is a starter file for a generic SaaS
application. [`vdr-fedramp.extended.yaml`](vdr-fedramp.extended.yaml) is a larger
fictional example with 68 image rules, decision-trace profiles, and reachability
declarations. Its `example-*` image names and profile assignments are illustrative;
replace them and verify the declarations against your deployment before use.

To use the extended example under a custom Docker config name:

```sh
docker config create vdr-fedramp-example vdr-fedramp.extended.yaml
trivy vdr swarm --region us-gov-west-1 --context-name swarm/example \
  --swarm-config-name vdr-fedramp-example --output tcs-vdr.json
```

## Deploy it into the cluster, don't mount it

The config only has to exist in the swarm. Do **not** attach it to any service
(no `--config` on `docker service create`, no `configs:` under a service in a
stack file). The scanner reads it directly from a manager node with
`docker config inspect vdr-fedramp`, so no container needs a copy.

Create it on any manager node:

```sh
docker config create vdr-fedramp vdr-fedramp.yaml
```

Check it:

```sh
docker config ls --filter name=vdr-fedramp
docker config inspect vdr-fedramp --format '{{printf "%s" .Spec.Data}}'
```

## Updating it: delete and recreate

Swarm configs are immutable. There is no `docker config update`, and
`docker config create` fails if the name already exists. To change the file,
remove the config and create it again **with the same name**:

```sh
docker config rm vdr-fedramp
docker config create vdr-fedramp vdr-fedramp.yaml
```

Keep the configured name, or create a new version and select it explicitly:

```sh
docker config create vdr-fedramp-v2 vdr-fedramp.yaml
trivy vdr swarm --region us-gov-west-1 --context-name swarm/prod \
  --swarm-config-name vdr-fedramp-v2 --output tcs-vdr.json
```

This also lets scans keep using the old config until the new one exists.
`--swarm-config <file>` still overrides the collected config's contents. For
offline scans with `--services-file`, use `--swarm-config` rather than
`--swarm-config-name`.

- `docker config rm` refuses to delete a config that a service uses. Because
  `vdr-fedramp` is never mounted, removal always succeeds. If it fails with
  "config is in use", a service has it attached: detach it with
  `docker service update --config-rm vdr-fedramp <service>` and try again.
- A scan that runs between the two commands finds no config and falls back to
  the built-in defaults (Class B, single-agency, H/H/H). Run both commands
  together, outside the scan window.
- Keep `vdr-fedramp.yaml` in version control. The cluster copy can't be edited
  in place, so the repository is the source of truth.

## What goes in the file

| Key | Purpose |
|---|---|
| `class` | FedRAMP Certification Class (`A`/`B`/`C`/`D`). |
| `multiAgency` | `"true"` if the swarm serves more than one agency. |
| `securityRequirementsCeiling` | Optional system-and-agency CR/IR/AR ceiling, e.g. `cr-m_ir-m_ar-l`. Applied only with `--security-requirements-ceiling configmap`; ThreatAlert ignores it and uses the ceiling it holds for the system. |
| `scoring.yaml` | Profile rules. `imageRules` match the image repository basename (registry, tag and digest ignored); `nameRules` match `stack`/service name and win over `imageRules`. |
| `exposure.yaml` | Internet-reachability declarations by stack, service name or image. A `false` needs a `justification`. |

Profiles can be decision traces (`<disclosure>.<trustedChange>.<dependency>`
from [`policy/vdr-policy.yaml`](../../policy/vdr-policy.yaml)), direct vectors
(`CR:H/IR:M/AR:L`) or named archetypes. Services matched by no rule score at
the H/H/H failsafe so they surface for classification.

Per-service labels override the file and need no redeploy of the config:

```yaml
services:
  api-gateway:
    deploy:
      labels:
        vdr.fedramp.io/security-impact-profile: service-content.security-enforcement.shared-critical-path
        vdr.fedramp.io/internet-reachable: "true"
```

Use `deploy.labels` (service labels), not top-level `labels` (container labels):
the scanner reads the service spec.
