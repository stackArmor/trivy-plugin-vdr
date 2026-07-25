package scoring

import (
	"fmt"
	"regexp"
	"strings"
)

var securityRequirementsPattern = regexp.MustCompile(`(?i)^cr-([lmh])_ir-([lmh])_ar-([lmh])$`)

// SecurityRequirements is the raw CR/IR/AR objective vector used to weight a
// vulnerability's confidentiality, integrity, and availability impacts.
type SecurityRequirements struct {
	CR string
	IR string
	AR string
}

// ParseSecurityRequirements accepts the Kubernetes-label-safe wire form
// cr-h_ir-m_ar-l. The returned display value is always normalized to
// CR:H/IR:M/AR:L.
func ParseSecurityRequirements(value string) (SecurityRequirements, bool) {
	matches := securityRequirementsPattern.FindStringSubmatch(strings.TrimSpace(value))
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

func (r SecurityRequirements) labelValue() string {
	return fmt.Sprintf(
		"cr-%s_ir-%s_ar-%s",
		strings.ToLower(r.CR),
		strings.ToLower(r.IR),
		strings.ToLower(r.AR),
	)
}
