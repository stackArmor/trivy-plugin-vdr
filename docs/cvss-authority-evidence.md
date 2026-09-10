# CVSS authority evidence in VDR JSON

The JSON report preserves two related CVSS fields on vulnerability findings:

- `cvssVector` is the vector selected by the scanner adapter for existing VDR scoring. Its selection behavior is unchanged.
- `cvss` is an optional, source-keyed passthrough of the CVSS evidence Trivy supplied. It allows downstream systems to display additional published vectors without changing the automatic baseline.

Example:

```json
{
  "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss": {
    "nvd": {
      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "V3Score": 9.8
    },
    "redhat": {
      "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
      "V3Score": 4.2
    }
  }
}
```

Each source may contain `V2Vector`, `V2Score`, `V3Vector`, `V3Score`, `V40Vector`, and `V40Score`. Missing fields are omitted. A score belongs only to the matching source and CVSS version. CVSS v2 is retained as evidence but is not used by the plugin's VDR PAIN calculation.

The plugin is the transport for this evidence, not its authority. The map key identifies the authority reported by Trivy. `severitySource`, `dataSource`, `primaryUrl`, and general finding references must not be used to infer a different vector authority.

Consumers must continue using `cvssVector` as the selected automatic baseline. Iteration order of `cvss`, numeric score differences, or availability of an additional vendor vector must not change initial scoring. A downstream governed workflow may offer supported v3.1/v4.0 alternatives for analyst selection and approval.

Older reports without `cvss` remain valid. Older consumers must be tested to confirm that they ignore the additive field. Existing reports do not acquire alternative vectors until a new scan artifact is generated.
