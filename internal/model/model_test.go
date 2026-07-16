package model

import (
	"encoding/json"
	"testing"
)

func TestAccessProtectionJSONUsesAuthProxyFieldNames(t *testing.T) {
	data, err := json.Marshal(AccessProtection{
		Type:    "iap",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("marshal AccessProtection: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal AccessProtection JSON: %v", err)
	}

	if got := output["authProxyType"]; got != "iap" {
		t.Fatalf("authProxyType = %#v, want %q", got, "iap")
	}
	if got := output["authProxyEnabled"]; got != true {
		t.Fatalf("authProxyEnabled = %#v, want true", got)
	}
	for _, legacyField := range []string{"type", "enabled"} {
		if _, ok := output[legacyField]; ok {
			t.Fatalf("legacy field %q is present in AccessProtection JSON: %s", legacyField, data)
		}
	}
}
