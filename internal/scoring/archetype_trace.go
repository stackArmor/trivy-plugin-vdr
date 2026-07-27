package scoring

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	compositeLens               = "composite"
	maxArchetypeLabelValueBytes = 63
)

// reasonCodeCatalog is the governed mapping from the three decision-trace
// segments to their independent CR, IR, and AR requirements. It is loaded only
// from the embedded canonical policy, so a cluster ConfigMap cannot redefine a
// reason and silently change the meaning of an existing workload label.
type reasonCodeCatalog struct {
	Disclosure    map[string]string `yaml:"disclosure"`
	TrustedChange map[string]string `yaml:"trustedChange"`
	Dependency    map[string]string `yaml:"dependency"`
}

func (c reasonCodeCatalog) validate() error {
	for _, dimension := range []struct {
		name   string
		values map[string]string
	}{
		{name: "disclosure", values: c.Disclosure},
		{name: "trustedChange", values: c.TrustedChange},
		{name: "dependency", values: c.Dependency},
	} {
		if err := validateReasonDimension(dimension.name, dimension.values); err != nil {
			return err
		}
	}
	return nil
}

func validateReasonDimension(name string, values map[string]string) error {
	if len(values) == 0 {
		return fmt.Errorf("reasonCodes.%s must not be empty", name)
	}
	levels := map[string]bool{}
	for token, requirement := range values {
		if !validReasonToken(token) {
			return fmt.Errorf("reasonCodes.%s contains invalid token %q", name, token)
		}
		if requirement != "H" && requirement != "M" && requirement != "L" {
			return fmt.Errorf("reasonCodes.%s.%s has invalid requirement %q", name, token, requirement)
		}
		levels[requirement] = true
	}
	for _, requirement := range []string{"H", "M", "L"} {
		if !levels[requirement] {
			return fmt.Errorf("reasonCodes.%s has no %s requirement reason", name, requirement)
		}
	}
	return nil
}

func validReasonToken(token string) bool {
	if token == "" || token[0] == '-' || token[len(token)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, char := range token {
		if char == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func (c reasonCodeCatalog) archetype(trace string) (Archetype, bool) {
	if trace == "" || trace != strings.TrimSpace(trace) || len(trace) > maxArchetypeLabelValueBytes {
		return Archetype{}, false
	}
	parts := strings.Split(trace, ".")
	if len(parts) != 3 {
		return Archetype{}, false
	}
	cr, crOK := c.Disclosure[parts[0]]
	ir, irOK := c.TrustedChange[parts[1]]
	ar, arOK := c.Dependency[parts[2]]
	if !crOK || !irOK || !arOK {
		return Archetype{}, false
	}
	return Archetype{Lens: compositeLens, CR: cr, IR: ir, AR: ar}, true
}

// lookupArchetype resolves compositional traces natively and legacy/custom
// names from the explicit archetype catalog. Any dotted value is reserved for
// the compositional grammar and must contain three registered reasons.
func (c *Config) lookupArchetype(name string) (Archetype, bool) {
	if strings.Contains(name, ".") {
		return c.reasonCodes.archetype(name)
	}
	archetype, ok := c.Archetypes[name]
	return archetype, ok
}

func (c *Config) validateCompositeArchetypeEntries() error {
	for name, configured := range c.Archetypes {
		if !strings.Contains(name, ".") {
			continue
		}
		derived, ok := c.reasonCodes.archetype(name)
		if !ok {
			return fmt.Errorf("archetypes[%q] is not a valid compositional decision trace", name)
		}
		if strings.TrimSpace(configured.Lens) != compositeLens ||
			normalizeReq(configured.CR) != derived.CR ||
			normalizeReq(configured.IR) != derived.IR ||
			normalizeReq(configured.AR) != derived.AR {
			return fmt.Errorf(
				"archetypes[%q] conflicts with its governed decision trace: got lens=%s CR/IR/AR=%s/%s/%s, want lens=%s CR/IR/AR=%s/%s/%s",
				name,
				configured.Lens, configured.CR, configured.IR, configured.AR,
				derived.Lens, derived.CR, derived.IR, derived.AR,
			)
		}
	}
	return nil
}

func rejectReasonCodeOverride(data []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return err
	}
	if _, exists := document["reasonCodes"]; exists {
		return fmt.Errorf("reasonCodes are governed by the embedded canonical policy and cannot be overridden")
	}
	return nil
}
