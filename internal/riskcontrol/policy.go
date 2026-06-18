package riskcontrol

import (
	_ "embed"
	"strings"
)

const (
	openAIUsagePolicySource  = "openai_usage_policies"
	openAIUsagePolicyVersion = "2025-10-29"
	openAIUsagePolicyProfile = "openai_hard_stop_v2"
)

//go:embed prompt_hard_stop_v2.txt
var embeddedAuditPrompt string

var openAIHardStopPolicyCodeValues = []string{
	"none",
	"child_sexual_abuse_or_grooming",
	"minor_endangerment",
	"nonconsensual_intimate_or_sexual_violence",
	"self_harm_facilitation",
	"threats_harassment_defamation",
	"terror_or_violent_harm",
	"weapons_assistance",
	"malicious_cyber_abuse",
	"privacy_abuse",
	"fraud_scam_impersonation",
	"illicit_goods_or_services",
	"academic_dishonesty",
	"political_manipulation",
	"real_money_gambling",
	"licensed_professional_advice_without_oversight",
	"high_stakes_automated_decision",
	"unsolicited_safety_testing",
	"safeguard_bypass_for_disallowed_content",
	"national_security_or_intelligence_unapproved",
}

var openAIHardStopSubcategoryCodeValues = []string{
	"none",
	"exploit_or_intrusion_code",
	"malware_or_evasion",
	"attack_tool_operational_guidance",
	"reverse_cracking_or_drm_bypass",
	"anti_bot_evasion_or_mass_scraping",
	"captcha_bypass_or_credential_attack",
	"bulk_account_abuse_or_spam_fraud",
	"bulk_fake_engagement_or_order_manipulation",
	"credential_theft_or_exfiltration",
	"unauthorized_third_party_access",
	"child_sexual_content",
	"sexual_violence",
	"self_harm_instruction",
	"terrorism_or_violent_attack",
	"weapon_build_or_use",
	"privacy_doxxing_or_sensitive_data_abuse",
	"phishing_or_impersonation",
	"academic_cheating",
	"political_persuasion_or_interference",
	"real_money_betting",
	"final_medical_or_legal_advice",
	"automated_high_stakes_decision",
	"safeguard_bypass",
}

var openAIHardStopPolicyCodes = map[string]struct{}{
	"child_sexual_abuse_or_grooming":                 {},
	"minor_endangerment":                             {},
	"nonconsensual_intimate_or_sexual_violence":      {},
	"self_harm_facilitation":                         {},
	"threats_harassment_defamation":                  {},
	"terror_or_violent_harm":                         {},
	"weapons_assistance":                             {},
	"malicious_cyber_abuse":                          {},
	"privacy_abuse":                                  {},
	"fraud_scam_impersonation":                       {},
	"illicit_goods_or_services":                      {},
	"academic_dishonesty":                            {},
	"political_manipulation":                         {},
	"real_money_gambling":                            {},
	"licensed_professional_advice_without_oversight": {},
	"high_stakes_automated_decision":                 {},
	"unsolicited_safety_testing":                     {},
	"safeguard_bypass_for_disallowed_content":        {},
	"national_security_or_intelligence_unapproved":   {},
}

var openAIHardStopSubcategoryCodes = map[string]struct{}{
	"exploit_or_intrusion_code":                  {},
	"malware_or_evasion":                         {},
	"attack_tool_operational_guidance":           {},
	"reverse_cracking_or_drm_bypass":             {},
	"anti_bot_evasion_or_mass_scraping":          {},
	"captcha_bypass_or_credential_attack":        {},
	"bulk_account_abuse_or_spam_fraud":           {},
	"bulk_fake_engagement_or_order_manipulation": {},
	"credential_theft_or_exfiltration":           {},
	"unauthorized_third_party_access":            {},
	"child_sexual_content":                       {},
	"sexual_violence":                            {},
	"self_harm_instruction":                      {},
	"terrorism_or_violent_attack":                {},
	"weapon_build_or_use":                        {},
	"privacy_doxxing_or_sensitive_data_abuse":    {},
	"phishing_or_impersonation":                  {},
	"academic_cheating":                          {},
	"political_persuasion_or_interference":       {},
	"real_money_betting":                         {},
	"final_medical_or_legal_advice":              {},
	"automated_high_stakes_decision":             {},
	"safeguard_bypass":                           {},
}

var openAIHardStopPolicyAliases = map[string]string{
	"none":                           "none",
	"child_sexual_abuse_or_grooming": "child_sexual_abuse_or_grooming",
	"minor_endangerment":             "minor_endangerment",
	"nonconsensual_intimate_or_sexual_violence":         "nonconsensual_intimate_or_sexual_violence",
	"self_harm_facilitation":                            "self_harm_facilitation",
	"threats_harassment_defamation":                     "threats_harassment_defamation",
	"terror_or_violent_harm":                            "terror_or_violent_harm",
	"weapons_assistance":                                "weapons_assistance",
	"malicious_cyber_abuse":                             "malicious_cyber_abuse",
	"privacy_abuse":                                     "privacy_abuse",
	"fraud_scam_impersonation":                          "fraud_scam_impersonation",
	"illicit_goods_or_services":                         "illicit_goods_or_services",
	"academic_dishonesty":                               "academic_dishonesty",
	"political_manipulation":                            "political_manipulation",
	"real_money_gambling":                               "real_money_gambling",
	"licensed_professional_advice_without_oversight":    "licensed_professional_advice_without_oversight",
	"high_stakes_automated_decision":                    "high_stakes_automated_decision",
	"unsolicited_safety_testing":                        "unsolicited_safety_testing",
	"safeguard_bypass_for_disallowed_content":           "safeguard_bypass_for_disallowed_content",
	"national_security_or_intelligence_unapproved":      "national_security_or_intelligence_unapproved",
	"sexual_minors_or_grooming":                         "child_sexual_abuse_or_grooming",
	"sexual_violence_or_nonconsensual_intimate_content": "nonconsensual_intimate_or_sexual_violence",
	"self_harm_promotion_or_facilitation":               "self_harm_facilitation",
	"violent_wrongdoing_or_terror_assistance":           "terror_or_violent_harm",
	"weapons_development_or_use_assistance":             "weapons_assistance",
	"malicious_cyber_or_system_compromise":              "malicious_cyber_abuse",
	"privacy_compromise_or_sensitive_data_abuse":        "privacy_abuse",
	"fraud_scams_or_impersonation":                      "fraud_scam_impersonation",
	"safeguard_circumvention":                           "safeguard_bypass_for_disallowed_content",
}

var openAIHardStopSubcategoryAliases = map[string]string{
	"none":                                       "none",
	"child_sexual_content":                       "child_sexual_content",
	"sexual_violence":                            "sexual_violence",
	"self_harm_instruction":                      "self_harm_instruction",
	"terrorism_or_violent_attack":                "terrorism_or_violent_attack",
	"weapon_build_or_use":                        "weapon_build_or_use",
	"privacy_doxxing_or_sensitive_data_abuse":    "privacy_doxxing_or_sensitive_data_abuse",
	"phishing_or_impersonation":                  "phishing_or_impersonation",
	"academic_cheating":                          "academic_cheating",
	"political_persuasion_or_interference":       "political_persuasion_or_interference",
	"real_money_betting":                         "real_money_betting",
	"final_medical_or_legal_advice":              "final_medical_or_legal_advice",
	"automated_high_stakes_decision":             "automated_high_stakes_decision",
	"safeguard_bypass":                           "safeguard_bypass",
	"exploit_or_intrusion_code":                  "exploit_or_intrusion_code",
	"malware_or_evasion":                         "malware_or_evasion",
	"attack_tool_operational_guidance":           "attack_tool_operational_guidance",
	"reverse_cracking_or_drm_bypass":             "reverse_cracking_or_drm_bypass",
	"anti_bot_evasion_or_mass_scraping":          "anti_bot_evasion_or_mass_scraping",
	"captcha_bypass_or_credential_attack":        "captcha_bypass_or_credential_attack",
	"bulk_account_abuse_or_spam_fraud":           "bulk_account_abuse_or_spam_fraud",
	"bulk_fake_engagement_or_order_manipulation": "bulk_fake_engagement_or_order_manipulation",
	"credential_theft_or_exfiltration":           "credential_theft_or_exfiltration",
	"unauthorized_third_party_access":            "unauthorized_third_party_access",
}

var moderationCategoryPolicyAliases = map[string]string{
	"sexual_minors":          "child_sexual_abuse_or_grooming",
	"self_harm_instructions": "self_harm_facilitation",
	"illicit_violent":        "terror_or_violent_harm",
}

func defaultAuditPrompt() string {
	return strings.TrimSpace(embeddedAuditPrompt)
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

func normalizeSubcategoryCode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.NewReplacer("-", "_", "/", "_", " ", "_").Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	value = strings.Trim(value, "_")
	if canonical, ok := openAIHardStopSubcategoryAliases[value]; ok {
		return canonical
	}
	return value
}

func isOpenAIHardStopPolicyCode(raw string) bool {
	_, ok := openAIHardStopPolicyCodes[normalizePolicyCode(raw)]
	return ok
}

func isOpenAIHardStopSubcategoryCode(raw string) bool {
	_, ok := openAIHardStopSubcategoryCodes[normalizeSubcategoryCode(raw)]
	return ok
}

func moderationCategoryPolicyCode(raw string) string {
	key := normalizePolicyCode(raw)
	if canonical, ok := moderationCategoryPolicyAliases[key]; ok {
		return canonical
	}
	return ""
}
