package diagnostics

import (
	"encoding/json"
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

var credentialText = regexp.MustCompile(`(?i)(bearer\s+|basic\s+|(?:password|token|secret|authorization|credential|signature|x-amz-signature|x-amz-security-token|x-goog-signature)["']?\s*[=:]\s*["']?(?:(?:bearer|basic)\s+)?)[^\s&;,"'<>]+`)
var urlUserinfo = regexp.MustCompile(`(https?://)[^/\s@]+@`)

func redact(value any) {
	switch obj := value.(type) {
	case []any:
		for i, item := range obj {
			if text, ok := item.(string); ok {
				obj[i] = scrubText(text)
			} else {
				redact(item)
			}
		}
	case map[string]any:
		delete(obj, "managedFields")
		for key, child := range obj {
			normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(key))
			switch {
			case key == "annotations":
				if annotations, ok := child.(map[string]any); ok {
					for name, value := range annotations {
						text, ok := value.(string)
						if !ok {
							continue
						}
						if sensitiveAnnotation(name) {
							annotations[name] = redacted
							continue
						}
						// Embedded JSON (including kubectl's last-applied manifest) needs
						// structural redaction so Secret payloads cannot bypass the filter.
						var embedded any
						if json.Unmarshal([]byte(text), &embedded) == nil {
							redact(embedded)
							if clean, err := json.Marshal(embedded); err == nil {
								annotations[name] = scrubText(string(clean))
								continue
							}
						}
						annotations[name] = scrubText(text)
					}
				}
			case key == "data" || key == "binaryData" || key == "stringData":
				if values, ok := child.(map[string]any); ok {
					for name := range values {
						values[name] = redacted
					}
				} else {
					obj[key] = redacted
				}
			case key == "command" || key == "args":
				obj[key] = []string{redacted}
			case key == "value" && obj["name"] != nil:
				obj[key] = redacted
			case sensitiveKey(normalized):
				obj[key] = redacted
			default:
				if text, ok := child.(string); ok {
					obj[key] = scrubText(text)
				} else {
					redact(child)
				}
			}
		}
	}
}
func sensitiveKey(key string) bool {
	switch key {
	case "apikey", "password", "passwd", "token", "authorization", "credential", "credentials", "clientsecret", "clientkeydata", "clientcertificatedata", "privatekey", "accesskey", "accesskeyid", "secretaccesskey", "sessiontoken", "auth", "auths", "dockerconfigjson", "dockerconfig":
		return true
	}
	return false
}
func scrubText(text string) string {
	text = urlUserinfo.ReplaceAllString(text, "${1}"+redacted+"@")
	return credentialText.ReplaceAllString(text, "${1}"+redacted)
}

func sensitiveAnnotation(name string) bool {
	// The qualified annotation's final component identifies the value, while
	// vendor prefixes and ordinary controller configuration remain intact.
	_, key, qualified := strings.Cut(name, "/")
	if !qualified {
		key = name
	}
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(key))
	return sensitiveKey(normalized)
}
