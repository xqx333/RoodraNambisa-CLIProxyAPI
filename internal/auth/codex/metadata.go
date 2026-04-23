package codex

import "strings"

func metadataString(metadata map[string]any, keys ...string) string {
	if len(metadata) == 0 {
		return ""
	}
	for _, key := range keys {
		if value, ok := metadata[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

// IDTokenClaimsFromMetadata parses the raw id_token found in auth metadata.
func IDTokenClaimsFromMetadata(metadata map[string]any) *JWTClaims {
	idToken := metadataString(metadata, "id_token")
	if idToken == "" {
		return nil
	}
	claims, err := ParseJWTToken(idToken)
	if err != nil || claims == nil {
		return nil
	}
	return claims
}

// EffectivePlanType returns the most current plan type from metadata, preferring the
// explicit persisted field over the stale JWT claim fallback.
func EffectivePlanType(metadata map[string]any) string {
	if planType := metadataString(metadata, "plan_type"); planType != "" {
		return planType
	}
	claims := IDTokenClaimsFromMetadata(metadata)
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
}

// EffectiveAccountID returns the persisted account ID when available and otherwise
// falls back to the id_token claim.
func EffectiveAccountID(metadata map[string]any) string {
	if accountID := metadataString(metadata, "account_id", "chatgpt_account_id"); accountID != "" {
		return accountID
	}
	claims := IDTokenClaimsFromMetadata(metadata)
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
}
