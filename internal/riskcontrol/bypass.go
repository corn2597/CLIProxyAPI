package riskcontrol

import (
	"net/http"
	"strconv"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// InternalBypassHeader marks internally generated audit requests that must not
// be audited again. It is trusted only within the deployment boundary and is
// stripped before forwarding to provider upstreams.
const InternalBypassHeader = "X-CLIProxy-Risk-Control-Bypass"

// AddInternalBypassHeader marks an HTTP request as an internal audit request.
func AddInternalBypassHeader(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Set(InternalBypassHeader, "1")
}

// StripInternalBypassHeader removes the internal bypass header before forwarding.
func StripInternalBypassHeader(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Del(InternalBypassHeader)
}

// HasValidInternalBypassHeader reports whether the internal bypass marker exists.
func HasValidInternalBypassHeader(headers http.Header) bool {
	if headers == nil {
		return false
	}
	for _, value := range headers.Values(InternalBypassHeader) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// IsBypassed reports whether risk control should be skipped for internal work.
func IsBypassed(opts cliproxyexecutor.Options) bool {
	if metadataBypass(opts.Metadata) {
		return true
	}
	return HasValidInternalBypassHeader(opts.Headers)
}

func metadataBypass(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	raw, ok := meta[cliproxyexecutor.RiskControlBypassMetadataKey]
	if !ok || raw == nil {
		return false
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(value))
		return errParse == nil && parsed
	case []byte:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(string(value)))
		return errParse == nil && parsed
	default:
		return false
	}
}
