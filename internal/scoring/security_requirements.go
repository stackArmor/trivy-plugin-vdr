package scoring

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	securityRequirementsWirePattern    = regexp.MustCompile(`(?i)^cr-([lmh])_ir-([lmh])_ar-([lmh])$`)
	securityRequirementsDisplayPattern = regexp.MustCompile(`(?i)^cr:([lmh])/ir:([lmh])/ar:([lmh])$`)
)

// SecurityRequirements is a CR/IR/AR objective vector used as an optional
// system-and-agency ceiling over an asset security-impact profile.
type SecurityRequirements struct {
	CR string
	IR string
	AR string
}

// ParseSecurityRequirements accepts either the transport-safe wire form
// cr-h_ir-m_ar-l or the normalized display form CR:H/IR:M/AR:L.
func ParseSecurityRequirements(value string) (SecurityRequirements, bool) {
	value = strings.TrimSpace(value)
	matches := securityRequirementsWirePattern.FindStringSubmatch(value)
	if len(matches) != 4 {
		matches = securityRequirementsDisplayPattern.FindStringSubmatch(value)
	}
	if len(matches) != 4 {
		return SecurityRequirements{}, false
	}
	return SecurityRequirements{
		CR: strings.ToUpper(matches[1]),
		IR: strings.ToUpper(matches[2]),
		AR: strings.ToUpper(matches[3]),
	}, true
}

func (r SecurityRequirements) String() string {
	return fmt.Sprintf("CR:%s/IR:%s/AR:%s", r.CR, r.IR, r.AR)
}

// WireValue returns the transport-safe representation used by ConfigMaps and
// the --security-requirements-ceiling runtime flag.
func (r SecurityRequirements) WireValue() string {
	return fmt.Sprintf(
		"cr-%s_ir-%s_ar-%s",
		strings.ToLower(r.CR),
		strings.ToLower(r.IR),
		strings.ToLower(r.AR),
	)
}

func requirementsFromArchetype(a Archetype) SecurityRequirements {
	return SecurityRequirements{
		CR: normalizeReq(a.CR),
		IR: normalizeReq(a.IR),
		AR: normalizeReq(a.AR),
	}
}

func capRequirements(requirements, ceiling SecurityRequirements) (SecurityRequirements, bool) {
	capped := SecurityRequirements{
		CR: lowerRequirement(requirements.CR, ceiling.CR),
		IR: lowerRequirement(requirements.IR, ceiling.IR),
		AR: lowerRequirement(requirements.AR, ceiling.AR),
	}
	return capped, capped != requirements
}

func lowerRequirement(value, ceiling string) string {
	if requirementRank(value) <= requirementRank(ceiling) {
		return normalizeReq(value)
	}
	return normalizeReq(ceiling)
}

func requirementRank(value string) int {
	switch normalizeReq(value) {
	case "L":
		return 1
	case "M":
		return 2
	case "H":
		return 3
	default:
		return 3
	}
}
