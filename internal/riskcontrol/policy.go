package riskcontrol

import "strings"

const (
	openAIUsagePolicySource  = "openai_usage_policies"
	openAIUsagePolicyVersion = "2025-10-29"
	openAIUsagePolicyProfile = "openai_request_hard_stops_v1"
)

var openAIHardStopPolicyCodes = map[string]struct{}{
	"sexual_minors_or_grooming":                         {},
	"sexual_violence_or_nonconsensual_intimate_content": {},
	"self_harm_promotion_or_facilitation":               {},
	"violent_wrongdoing_or_terror_assistance":           {},
	"weapons_development_or_use_assistance":             {},
	"malicious_cyber_or_system_compromise":              {},
	"privacy_compromise_or_sensitive_data_abuse":        {},
	"fraud_scams_or_impersonation":                      {},
	"safeguard_circumvention":                           {},
	"unsolicited_safety_testing":                        {},
}

var openAIHardStopPolicyAliases = map[string]string{
	"none":                          "none",
	"sexual_minors":                 "sexual_minors_or_grooming",
	"minor_grooming":                "sexual_minors_or_grooming",
	"sexual_minors_or_grooming":     "sexual_minors_or_grooming",
	"sexual_violence_nonconsensual": "sexual_violence_or_nonconsensual_intimate_content",
	"sexual_violence_or_nonconsensual_intimate_content": "sexual_violence_or_nonconsensual_intimate_content",
	"self_harm_instructions":                            "self_harm_promotion_or_facilitation",
	"self_harm_promotion":                               "self_harm_promotion_or_facilitation",
	"self_harm_promotion_or_facilitation":               "self_harm_promotion_or_facilitation",
	"violent_wrongdoing_instructions":                   "violent_wrongdoing_or_terror_assistance",
	"violent_wrongdoing_or_terror_assistance":           "violent_wrongdoing_or_terror_assistance",
	"terror_assistance":                                 "violent_wrongdoing_or_terror_assistance",
	"weapons_development":                               "weapons_development_or_use_assistance",
	"weapons_use_assistance":                            "weapons_development_or_use_assistance",
	"weapons_development_or_use_assistance":             "weapons_development_or_use_assistance",
	"illicit_cyber_abuse":                               "malicious_cyber_or_system_compromise",
	"malicious_cyber":                                   "malicious_cyber_or_system_compromise",
	"malicious_cyber_or_system_compromise":              "malicious_cyber_or_system_compromise",
	"privacy_exfiltration":                              "privacy_compromise_or_sensitive_data_abuse",
	"privacy_compromise":                                "privacy_compromise_or_sensitive_data_abuse",
	"privacy_compromise_or_sensitive_data_abuse":        "privacy_compromise_or_sensitive_data_abuse",
	"fraud_or_impersonation":                            "fraud_scams_or_impersonation",
	"fraud_scams_or_impersonation":                      "fraud_scams_or_impersonation",
	"safeguard_circumvention":                           "safeguard_circumvention",
	"unsolicited_safety_testing":                        "unsolicited_safety_testing",
	"sexual_minors_or_grooming_or_exploitation":         "sexual_minors_or_grooming",
}

var moderationCategoryPolicyAliases = map[string]string{
	"sexual_minors":          "sexual_minors_or_grooming",
	"self_harm_instructions": "self_harm_promotion_or_facilitation",
	"illicit_violent":        "violent_wrongdoing_or_terror_assistance",
}

func normalizePolicyCode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.NewReplacer("-", "_", "/", "_", " ", "_").Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	value = strings.Trim(value, "_")
	if canonical, ok := openAIHardStopPolicyAliases[value]; ok {
		return canonical
	}
	return value
}

func isOpenAIHardStopPolicyCode(raw string) bool {
	_, ok := openAIHardStopPolicyCodes[normalizePolicyCode(raw)]
	return ok
}

func moderationCategoryPolicyCode(raw string) string {
	key := normalizePolicyCode(raw)
	if canonical, ok := moderationCategoryPolicyAliases[key]; ok {
		return canonical
	}
	return ""
}
