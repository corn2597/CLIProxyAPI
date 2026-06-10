package riskcontrol

import (
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestInternalBypassHeaderRequiresMarker(t *testing.T) {
	headers := http.Header{}
	if HasValidInternalBypassHeader(headers) {
		t.Fatalf("empty headers were accepted as bypass")
	}

	headers.Set(InternalBypassHeader, "1")
	if !HasValidInternalBypassHeader(headers) {
		t.Fatalf("bypass marker header was rejected")
	}

	headers.Set(InternalBypassHeader, " ")
	if HasValidInternalBypassHeader(headers) {
		t.Fatalf("blank bypass marker was accepted")
	}
}

func TestStripInternalBypassHeader(t *testing.T) {
	headers := http.Header{"X-Keep": {"1"}}
	AddInternalBypassHeader(headers)

	StripInternalBypassHeader(headers)

	if got := headers.Get(InternalBypassHeader); got != "" {
		t.Fatalf("bypass header after strip = %q, want empty", got)
	}
	if got := headers.Get("X-Keep"); got != "1" {
		t.Fatalf("X-Keep after strip = %q, want 1", got)
	}
}

func TestIsBypassedAcceptsInternalMetadata(t *testing.T) {
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{
			cliproxyexecutor.RiskControlBypassMetadataKey: "true",
		},
	}
	if !IsBypassed(opts) {
		t.Fatalf("metadata bypass was not accepted")
	}
}
