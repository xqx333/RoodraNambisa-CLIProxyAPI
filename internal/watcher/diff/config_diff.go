package diff

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

// BuildConfigChangeDetails computes a redacted, human-readable list of config changes.
// Secrets are never printed; only structural or non-sensitive fields are surfaced.
func BuildConfigChangeDetails(oldCfg, newCfg *config.Config) []string {
	changes := make([]string, 0, 16)
	if oldCfg == nil || newCfg == nil {
		return changes
	}

	// Simple scalars
	if oldCfg.Port != newCfg.Port {
		changes = append(changes, fmt.Sprintf("port: %d -> %d", oldCfg.Port, newCfg.Port))
	}
	if oldCfg.AuthDir != newCfg.AuthDir {
		changes = append(changes, fmt.Sprintf("auth-dir: %s -> %s", oldCfg.AuthDir, newCfg.AuthDir))
	}
	if oldCfg.Debug != newCfg.Debug {
		changes = append(changes, fmt.Sprintf("debug: %t -> %t", oldCfg.Debug, newCfg.Debug))
	}
	if oldCfg.Pprof.Enable != newCfg.Pprof.Enable {
		changes = append(changes, fmt.Sprintf("pprof.enable: %t -> %t", oldCfg.Pprof.Enable, newCfg.Pprof.Enable))
	}
	if strings.TrimSpace(oldCfg.Pprof.Addr) != strings.TrimSpace(newCfg.Pprof.Addr) {
		changes = append(changes, fmt.Sprintf("pprof.addr: %s -> %s", strings.TrimSpace(oldCfg.Pprof.Addr), strings.TrimSpace(newCfg.Pprof.Addr)))
	}
	if oldCfg.LoggingToFile != newCfg.LoggingToFile {
		changes = append(changes, fmt.Sprintf("logging-to-file: %t -> %t", oldCfg.LoggingToFile, newCfg.LoggingToFile))
	}
	if oldCfg.UsageStatisticsEnabled != newCfg.UsageStatisticsEnabled {
		changes = append(changes, fmt.Sprintf("usage-statistics-enabled: %t -> %t", oldCfg.UsageStatisticsEnabled, newCfg.UsageStatisticsEnabled))
	}
	if oldCfg.UsageStatisticsPersistence() != newCfg.UsageStatisticsPersistence() {
		changes = append(changes, fmt.Sprintf("usage-statistics-persistence-enabled: %t -> %t", oldCfg.UsageStatisticsPersistence(), newCfg.UsageStatisticsPersistence()))
	}
	if oldCfg.UsageStatisticsPersistIntervalSeconds != newCfg.UsageStatisticsPersistIntervalSeconds {
		changes = append(changes, fmt.Sprintf("usage-statistics-persist-interval-seconds: %d -> %d", oldCfg.UsageStatisticsPersistIntervalSeconds, newCfg.UsageStatisticsPersistIntervalSeconds))
	}
	if oldCfg.UsageStatisticsDetailRetentionDays != newCfg.UsageStatisticsDetailRetentionDays {
		changes = append(changes, fmt.Sprintf("usage-statistics-detail-retention-days: %d -> %d", oldCfg.UsageStatisticsDetailRetentionDays, newCfg.UsageStatisticsDetailRetentionDays))
	}
	if oldCfg.UsageStatisticsMaxStorageMB != newCfg.UsageStatisticsMaxStorageMB {
		changes = append(changes, fmt.Sprintf("usage-statistics-max-storage-megabytes: %d -> %d", oldCfg.UsageStatisticsMaxStorageMB, newCfg.UsageStatisticsMaxStorageMB))
	}
	if oldCfg.DisableCooling != newCfg.DisableCooling {
		changes = append(changes, fmt.Sprintf("disable-cooling: %t -> %t", oldCfg.DisableCooling, newCfg.DisableCooling))
	}
	if !reflect.DeepEqual(oldCfg.NoCooldownStatusCodes, newCfg.NoCooldownStatusCodes) {
		changes = append(changes, "no-cooldown-status-codes: updated")
	}
	if !reflect.DeepEqual(oldCfg.FixedErrorCooldowns, newCfg.FixedErrorCooldowns) {
		changes = append(changes, "fixed-error-cooldowns: updated")
	}
	if !reflect.DeepEqual(oldCfg.ErrorResponseRewrites, newCfg.ErrorResponseRewrites) {
		changes = append(changes, "error-response-rewrites: updated")
	}
	if oldCfg.RequestLog != newCfg.RequestLog {
		changes = append(changes, fmt.Sprintf("request-log: %t -> %t", oldCfg.RequestLog, newCfg.RequestLog))
	}
	if oldCfg.LogsMaxTotalSizeMB != newCfg.LogsMaxTotalSizeMB {
		changes = append(changes, fmt.Sprintf("logs-max-total-size-mb: %d -> %d", oldCfg.LogsMaxTotalSizeMB, newCfg.LogsMaxTotalSizeMB))
	}
	if oldCfg.LogsRetentionDays != newCfg.LogsRetentionDays {
		changes = append(changes, fmt.Sprintf("logs-retention-days: %d -> %d", oldCfg.LogsRetentionDays, newCfg.LogsRetentionDays))
	}
	if oldCfg.ErrorLogsMaxFiles != newCfg.ErrorLogsMaxFiles {
		changes = append(changes, fmt.Sprintf("error-logs-max-files: %d -> %d", oldCfg.ErrorLogsMaxFiles, newCfg.ErrorLogsMaxFiles))
	}
	if oldCfg.RequestRetry != newCfg.RequestRetry {
		changes = append(changes, fmt.Sprintf("request-retry: %d -> %d", oldCfg.RequestRetry, newCfg.RequestRetry))
	}
	if !reflect.DeepEqual(oldCfg.OAuthRequestScopedErrors, newCfg.OAuthRequestScopedErrors) {
		changes = append(changes, "oauth-request-scoped-errors: updated")
	}
	if oldCfg.MaxRetryCredentials != newCfg.MaxRetryCredentials {
		changes = append(changes, fmt.Sprintf("max-retry-credentials: %d -> %d", oldCfg.MaxRetryCredentials, newCfg.MaxRetryCredentials))
	}
	if oldCfg.MaxRetryInterval != newCfg.MaxRetryInterval {
		changes = append(changes, fmt.Sprintf("max-retry-interval: %d -> %d", oldCfg.MaxRetryInterval, newCfg.MaxRetryInterval))
	}
	if oldCfg.ProxyURL != newCfg.ProxyURL {
		changes = append(changes, fmt.Sprintf("proxy-url: %s -> %s", formatProxyURL(oldCfg.ProxyURL), formatProxyURL(newCfg.ProxyURL)))
	}
	if oldCfg.WebsocketAuth != newCfg.WebsocketAuth {
		changes = append(changes, fmt.Sprintf("ws-auth: %t -> %t", oldCfg.WebsocketAuth, newCfg.WebsocketAuth))
	}
	if oldCfg.ForceModelPrefix != newCfg.ForceModelPrefix {
		changes = append(changes, fmt.Sprintf("force-model-prefix: %t -> %t", oldCfg.ForceModelPrefix, newCfg.ForceModelPrefix))
	}
	if oldCfg.NonStreamKeepAliveInterval != newCfg.NonStreamKeepAliveInterval {
		changes = append(changes, fmt.Sprintf("nonstream-keepalive-interval: %d -> %d", oldCfg.NonStreamKeepAliveInterval, newCfg.NonStreamKeepAliveInterval))
	}

	// Quota-exceeded behavior
	if oldCfg.QuotaExceeded.SwitchProject != newCfg.QuotaExceeded.SwitchProject {
		changes = append(changes, fmt.Sprintf("quota-exceeded.switch-project: %t -> %t", oldCfg.QuotaExceeded.SwitchProject, newCfg.QuotaExceeded.SwitchProject))
	}
	if oldCfg.QuotaExceeded.SwitchPreviewModel != newCfg.QuotaExceeded.SwitchPreviewModel {
		changes = append(changes, fmt.Sprintf("quota-exceeded.switch-preview-model: %t -> %t", oldCfg.QuotaExceeded.SwitchPreviewModel, newCfg.QuotaExceeded.SwitchPreviewModel))
	}
	if oldCfg.QuotaExceeded.AntigravityCredits != newCfg.QuotaExceeded.AntigravityCredits {
		changes = append(changes, fmt.Sprintf("quota-exceeded.antigravity-credits: %t -> %t", oldCfg.QuotaExceeded.AntigravityCredits, newCfg.QuotaExceeded.AntigravityCredits))
	}

	if oldCfg.AuthMaintenance.Enable != newCfg.AuthMaintenance.Enable {
		changes = append(changes, fmt.Sprintf("auth-maintenance.enable: %t -> %t", oldCfg.AuthMaintenance.Enable, newCfg.AuthMaintenance.Enable))
	}
	if oldCfg.AuthMaintenance.ScanIntervalSeconds != newCfg.AuthMaintenance.ScanIntervalSeconds {
		changes = append(changes, fmt.Sprintf("auth-maintenance.scan-interval-seconds: %d -> %d", oldCfg.AuthMaintenance.ScanIntervalSeconds, newCfg.AuthMaintenance.ScanIntervalSeconds))
	}
	if oldCfg.AuthMaintenance.DeleteIntervalSeconds != newCfg.AuthMaintenance.DeleteIntervalSeconds {
		changes = append(changes, fmt.Sprintf("auth-maintenance.delete-interval-seconds: %d -> %d", oldCfg.AuthMaintenance.DeleteIntervalSeconds, newCfg.AuthMaintenance.DeleteIntervalSeconds))
	}
	if !reflect.DeepEqual(oldCfg.AuthMaintenance.DeleteStatusCodes, newCfg.AuthMaintenance.DeleteStatusCodes) {
		changes = append(changes, "auth-maintenance.delete-status-codes: updated")
	}
	if !reflect.DeepEqual(oldCfg.AuthMaintenance.DisableStatusCodes, newCfg.AuthMaintenance.DisableStatusCodes) {
		changes = append(changes, "auth-maintenance.disable-status-codes: updated")
	}
	if oldCfg.AuthMaintenance.DeleteQuotaExceeded != newCfg.AuthMaintenance.DeleteQuotaExceeded {
		changes = append(changes, fmt.Sprintf("auth-maintenance.delete-quota-exceeded: %t -> %t", oldCfg.AuthMaintenance.DeleteQuotaExceeded, newCfg.AuthMaintenance.DeleteQuotaExceeded))
	}
	if oldCfg.AuthMaintenance.QuotaStrikeThreshold != newCfg.AuthMaintenance.QuotaStrikeThreshold {
		changes = append(changes, fmt.Sprintf("auth-maintenance.quota-strike-threshold: %d -> %d", oldCfg.AuthMaintenance.QuotaStrikeThreshold, newCfg.AuthMaintenance.QuotaStrikeThreshold))
	}
	if oldCfg.AuthMaintenance.DisableQuotaExceeded != newCfg.AuthMaintenance.DisableQuotaExceeded {
		changes = append(changes, fmt.Sprintf("auth-maintenance.disable-quota-exceeded: %t -> %t", oldCfg.AuthMaintenance.DisableQuotaExceeded, newCfg.AuthMaintenance.DisableQuotaExceeded))
	}
	if oldCfg.AuthMaintenance.DisableQuotaStrikeThreshold != newCfg.AuthMaintenance.DisableQuotaStrikeThreshold {
		changes = append(changes, fmt.Sprintf("auth-maintenance.disable-quota-strike-threshold: %d -> %d", oldCfg.AuthMaintenance.DisableQuotaStrikeThreshold, newCfg.AuthMaintenance.DisableQuotaStrikeThreshold))
	}

	if oldCfg.Routing.Strategy != newCfg.Routing.Strategy {
		changes = append(changes, fmt.Sprintf("routing.strategy: %s -> %s", oldCfg.Routing.Strategy, newCfg.Routing.Strategy))
	}
	if !reflect.DeepEqual(oldCfg.Routing.PriorityOverrides, newCfg.Routing.PriorityOverrides) {
		changes = append(changes, "routing.priority-overrides: updated")
	}
	if routingSessionAffinityFailoverEnabled(oldCfg) != routingSessionAffinityFailoverEnabled(newCfg) {
		changes = append(changes, fmt.Sprintf("routing.session-affinity-failover: %t -> %t", routingSessionAffinityFailoverEnabled(oldCfg), routingSessionAffinityFailoverEnabled(newCfg)))
	}
	if oldCfg.Routing.SessionAffinityAcrossPriorities != newCfg.Routing.SessionAffinityAcrossPriorities {
		changes = append(changes, fmt.Sprintf("routing.session-affinity-across-priorities: %t -> %t", oldCfg.Routing.SessionAffinityAcrossPriorities, newCfg.Routing.SessionAffinityAcrossPriorities))
	}
	if oldCfg.Routing.SessionAffinitySubagents != newCfg.Routing.SessionAffinitySubagents {
		changes = append(changes, fmt.Sprintf("routing.session-affinity-subagents: %t -> %t", oldCfg.Routing.SessionAffinitySubagents, newCfg.Routing.SessionAffinitySubagents))
	}
	if oldCfg.Routing.SessionAffinityLCP != newCfg.Routing.SessionAffinityLCP {
		changes = append(changes, fmt.Sprintf("routing.session-affinity-lcp: %t -> %t", oldCfg.Routing.SessionAffinityLCP, newCfg.Routing.SessionAffinityLCP))
	}
	if oldCfg.Routing.SessionAffinityHistoryEnabled() != newCfg.Routing.SessionAffinityHistoryEnabled() {
		changes = append(changes, fmt.Sprintf("routing.session-affinity-use-history: %t -> %t", oldCfg.Routing.SessionAffinityHistoryEnabled(), newCfg.Routing.SessionAffinityHistoryEnabled()))
	}

	// API keys (redacted) and counts
	if len(oldCfg.APIKeys) != len(newCfg.APIKeys) {
		changes = append(changes, fmt.Sprintf("api-keys count: %d -> %d", len(oldCfg.APIKeys), len(newCfg.APIKeys)))
	} else if !reflect.DeepEqual(trimStrings(oldCfg.APIKeys), trimStrings(newCfg.APIKeys)) {
		changes = append(changes, "api-keys: values updated (count unchanged, redacted)")
	}
	if !reflect.DeepEqual(oldCfg.APIKeyGroups, newCfg.APIKeyGroups) {
		changes = append(changes, "api-key-groups: access restrictions updated (keys redacted)")
	}
	if len(oldCfg.GeminiKey) != len(newCfg.GeminiKey) {
		changes = append(changes, fmt.Sprintf("gemini-api-key count: %d -> %d", len(oldCfg.GeminiKey), len(newCfg.GeminiKey)))
	} else {
		for i := range oldCfg.GeminiKey {
			o := oldCfg.GeminiKey[i]
			n := newCfg.GeminiKey[i]
			if !reflect.DeepEqual(o.Weight, n.Weight) {
				changes = append(changes, fmt.Sprintf("gemini[%d].weight: updated", i))
			}
			if !reflect.DeepEqual(o.RequestRetry, n.RequestRetry) {
				changes = append(changes, fmt.Sprintf("gemini[%d].request-retry: updated", i))
			}
			if !reflect.DeepEqual(o.RequestScopedErrors, n.RequestScopedErrors) {
				changes = append(changes, fmt.Sprintf("gemini[%d].request-scoped-errors: updated", i))
			}
			if strings.TrimSpace(o.BaseURL) != strings.TrimSpace(n.BaseURL) {
				changes = append(changes, fmt.Sprintf("gemini[%d].base-url: %s -> %s", i, formatURL(o.BaseURL), formatURL(n.BaseURL)))
			}
			if strings.TrimSpace(o.ProxyURL) != strings.TrimSpace(n.ProxyURL) {
				changes = append(changes, fmt.Sprintf("gemini[%d].proxy-url: %s -> %s", i, formatProxyURL(o.ProxyURL), formatProxyURL(n.ProxyURL)))
			}
			if strings.TrimSpace(o.Prefix) != strings.TrimSpace(n.Prefix) {
				changes = append(changes, fmt.Sprintf("gemini[%d].prefix: %s -> %s", i, strings.TrimSpace(o.Prefix), strings.TrimSpace(n.Prefix)))
			}
			if strings.TrimSpace(o.APIKey) != strings.TrimSpace(n.APIKey) {
				changes = append(changes, fmt.Sprintf("gemini[%d].api-key: updated", i))
			}
			if !equalStringMap(o.Headers, n.Headers) {
				changes = append(changes, fmt.Sprintf("gemini[%d].headers: updated", i))
			}
			oldModels := SummarizeGeminiModels(o.Models)
			newModels := SummarizeGeminiModels(n.Models)
			if oldModels.hash != newModels.hash {
				changes = append(changes, fmt.Sprintf("gemini[%d].models: updated (%d -> %d entries)", i, oldModels.count, newModels.count))
			}
			oldExcluded := SummarizeExcludedModels(o.ExcludedModels)
			newExcluded := SummarizeExcludedModels(n.ExcludedModels)
			if oldExcluded.hash != newExcluded.hash {
				changes = append(changes, fmt.Sprintf("gemini[%d].excluded-models: updated (%d -> %d entries)", i, oldExcluded.count, newExcluded.count))
			}
		}
	}
	if len(oldCfg.InteractionsKey) != len(newCfg.InteractionsKey) {
		changes = append(changes, fmt.Sprintf("interactions-api-key count: %d -> %d", len(oldCfg.InteractionsKey), len(newCfg.InteractionsKey)))
	} else {
		for i := range oldCfg.InteractionsKey {
			o := oldCfg.InteractionsKey[i]
			n := newCfg.InteractionsKey[i]
			if !reflect.DeepEqual(o.Weight, n.Weight) {
				changes = append(changes, fmt.Sprintf("interactions[%d].weight: updated", i))
			}
			if !reflect.DeepEqual(o.RequestRetry, n.RequestRetry) {
				changes = append(changes, fmt.Sprintf("interactions[%d].request-retry: updated", i))
			}
			if !reflect.DeepEqual(o.RequestScopedErrors, n.RequestScopedErrors) {
				changes = append(changes, fmt.Sprintf("interactions[%d].request-scoped-errors: updated", i))
			}
			if strings.TrimSpace(o.BaseURL) != strings.TrimSpace(n.BaseURL) {
				changes = append(changes, fmt.Sprintf("interactions[%d].base-url: %s -> %s", i, formatURL(o.BaseURL), formatURL(n.BaseURL)))
			}
			if strings.TrimSpace(o.ProxyURL) != strings.TrimSpace(n.ProxyURL) {
				changes = append(changes, fmt.Sprintf("interactions[%d].proxy-url: %s -> %s", i, formatProxyURL(o.ProxyURL), formatProxyURL(n.ProxyURL)))
			}
			if strings.TrimSpace(o.Prefix) != strings.TrimSpace(n.Prefix) {
				changes = append(changes, fmt.Sprintf("interactions[%d].prefix: %s -> %s", i, strings.TrimSpace(o.Prefix), strings.TrimSpace(n.Prefix)))
			}
			if strings.TrimSpace(o.APIKey) != strings.TrimSpace(n.APIKey) {
				changes = append(changes, fmt.Sprintf("interactions[%d].api-key: updated", i))
			}
			if !equalStringMap(o.Headers, n.Headers) {
				changes = append(changes, fmt.Sprintf("interactions[%d].headers: updated", i))
			}
			oldModels := SummarizeGeminiModels(o.Models)
			newModels := SummarizeGeminiModels(n.Models)
			if oldModels.hash != newModels.hash {
				changes = append(changes, fmt.Sprintf("interactions[%d].models: updated (%d -> %d entries)", i, oldModels.count, newModels.count))
			}
			oldExcluded := SummarizeExcludedModels(o.ExcludedModels)
			newExcluded := SummarizeExcludedModels(n.ExcludedModels)
			if oldExcluded.hash != newExcluded.hash {
				changes = append(changes, fmt.Sprintf("interactions[%d].excluded-models: updated (%d -> %d entries)", i, oldExcluded.count, newExcluded.count))
			}
		}
	}

	// Claude keys (do not print key material)
	if len(oldCfg.ClaudeKey) != len(newCfg.ClaudeKey) {
		changes = append(changes, fmt.Sprintf("claude-api-key count: %d -> %d", len(oldCfg.ClaudeKey), len(newCfg.ClaudeKey)))
	} else {
		for i := range oldCfg.ClaudeKey {
			o := oldCfg.ClaudeKey[i]
			n := newCfg.ClaudeKey[i]
			if !reflect.DeepEqual(o.Weight, n.Weight) {
				changes = append(changes, fmt.Sprintf("claude[%d].weight: updated", i))
			}
			if !reflect.DeepEqual(o.RequestRetry, n.RequestRetry) {
				changes = append(changes, fmt.Sprintf("claude[%d].request-retry: updated", i))
			}
			if !reflect.DeepEqual(o.RequestScopedErrors, n.RequestScopedErrors) {
				changes = append(changes, fmt.Sprintf("claude[%d].request-scoped-errors: updated", i))
			}
			if strings.TrimSpace(o.BaseURL) != strings.TrimSpace(n.BaseURL) {
				changes = append(changes, fmt.Sprintf("claude[%d].base-url: %s -> %s", i, formatURL(o.BaseURL), formatURL(n.BaseURL)))
			}
			if strings.TrimSpace(o.ProxyURL) != strings.TrimSpace(n.ProxyURL) {
				changes = append(changes, fmt.Sprintf("claude[%d].proxy-url: %s -> %s", i, formatProxyURL(o.ProxyURL), formatProxyURL(n.ProxyURL)))
			}
			if strings.TrimSpace(o.Prefix) != strings.TrimSpace(n.Prefix) {
				changes = append(changes, fmt.Sprintf("claude[%d].prefix: %s -> %s", i, strings.TrimSpace(o.Prefix), strings.TrimSpace(n.Prefix)))
			}
			if strings.TrimSpace(o.APIKey) != strings.TrimSpace(n.APIKey) {
				changes = append(changes, fmt.Sprintf("claude[%d].api-key: updated", i))
			}
			if !equalStringMap(o.Headers, n.Headers) {
				changes = append(changes, fmt.Sprintf("claude[%d].headers: updated", i))
			}
			oldModels := SummarizeClaudeModels(o.Models)
			newModels := SummarizeClaudeModels(n.Models)
			if oldModels.hash != newModels.hash {
				changes = append(changes, fmt.Sprintf("claude[%d].models: updated (%d -> %d entries)", i, oldModels.count, newModels.count))
			}
			oldExcluded := SummarizeExcludedModels(o.ExcludedModels)
			newExcluded := SummarizeExcludedModels(n.ExcludedModels)
			if oldExcluded.hash != newExcluded.hash {
				changes = append(changes, fmt.Sprintf("claude[%d].excluded-models: updated (%d -> %d entries)", i, oldExcluded.count, newExcluded.count))
			}
			if o.Cloak != nil && n.Cloak != nil {
				if strings.TrimSpace(o.Cloak.Mode) != strings.TrimSpace(n.Cloak.Mode) {
					changes = append(changes, fmt.Sprintf("claude[%d].cloak.mode: %s -> %s", i, o.Cloak.Mode, n.Cloak.Mode))
				}
				if o.Cloak.StrictMode != n.Cloak.StrictMode {
					changes = append(changes, fmt.Sprintf("claude[%d].cloak.strict-mode: %t -> %t", i, o.Cloak.StrictMode, n.Cloak.StrictMode))
				}
				if len(o.Cloak.SensitiveWords) != len(n.Cloak.SensitiveWords) {
					changes = append(changes, fmt.Sprintf("claude[%d].cloak.sensitive-words: %d -> %d", i, len(o.Cloak.SensitiveWords), len(n.Cloak.SensitiveWords)))
				}
			}
		}
	}

	if !reflect.DeepEqual(oldCfg.XAI, newCfg.XAI) {
		changes = append(changes, "xai: upstream address, global headers, request defaults or identity policy changed")
	}
	if oldCfg.Codex.IdentityConfuse != newCfg.Codex.IdentityConfuse {
		changes = append(changes, fmt.Sprintf("codex.identity-confuse: %t -> %t", oldCfg.Codex.IdentityConfuse, newCfg.Codex.IdentityConfuse))
	}
	if oldCfg.Codex.LiveEnabled != newCfg.Codex.LiveEnabled {
		changes = append(changes, fmt.Sprintf("codex.live-enabled: %t -> %t", oldCfg.Codex.LiveEnabled, newCfg.Codex.LiveEnabled))
	}
	if !reflect.DeepEqual(oldCfg.Codex.LiveMediaRelay, newCfg.Codex.LiveMediaRelay) {
		changes = append(changes, "codex.live-media-relay: updated")
	}
	if oldCfg.Codex.OptimizeMultiAgentV2 != newCfg.Codex.OptimizeMultiAgentV2 {
		changes = append(changes, fmt.Sprintf("codex.optimize-multi-agent-v2: %t -> %t", oldCfg.Codex.OptimizeMultiAgentV2, newCfg.Codex.OptimizeMultiAgentV2))
	}
	if oldCfg.Codex.PassthroughPromptCacheKey != newCfg.Codex.PassthroughPromptCacheKey {
		changes = append(changes, fmt.Sprintf("codex.passthrough-prompt-cache-key: %t -> %t", oldCfg.Codex.PassthroughPromptCacheKey, newCfg.Codex.PassthroughPromptCacheKey))
	}
	if oldCfg.Codex.StreamBootstrapBuffering != newCfg.Codex.StreamBootstrapBuffering {
		changes = append(changes, fmt.Sprintf("codex.stream-bootstrap-buffering: %t -> %t", oldCfg.Codex.StreamBootstrapBuffering, newCfg.Codex.StreamBootstrapBuffering))
	}
	if oldCfg.Codex.EstimateClaudeInputTokens != newCfg.Codex.EstimateClaudeInputTokens {
		changes = append(changes, fmt.Sprintf("codex.estimate-claude-input-tokens: %t -> %t", oldCfg.Codex.EstimateClaudeInputTokens, newCfg.Codex.EstimateClaudeInputTokens))
	}
	if oldCfg.Codex.ObserveQuota != newCfg.Codex.ObserveQuota {
		changes = append(changes, fmt.Sprintf("codex.observe-quota: %t -> %t", oldCfg.Codex.ObserveQuota, newCfg.Codex.ObserveQuota))
	}
	if oldCfg.Codex.OrphanDelegationCompatibility != newCfg.Codex.OrphanDelegationCompatibility {
		changes = append(changes, fmt.Sprintf("codex.orphan-delegation-compatibility: %t -> %t", oldCfg.Codex.OrphanDelegationCompatibility, newCfg.Codex.OrphanDelegationCompatibility))
	}
	if oldCfg.Codex.SpoofSessionIdentity != newCfg.Codex.SpoofSessionIdentity {
		changes = append(changes, fmt.Sprintf("codex.spoof-session-identity: %t -> %t", oldCfg.Codex.SpoofSessionIdentity, newCfg.Codex.SpoofSessionIdentity))
	}
	if oldCfg.Codex.ResolvedTurnStatePolicy() != newCfg.Codex.ResolvedTurnStatePolicy() {
		changes = append(changes, fmt.Sprintf("codex.turn-state-policy: %s -> %s", oldCfg.Codex.ResolvedTurnStatePolicy(), newCfg.Codex.ResolvedTurnStatePolicy()))
	}
	if oldCfg.Codex.ResolvedEnforceSoftwareIdentity() != newCfg.Codex.ResolvedEnforceSoftwareIdentity() {
		changes = append(changes, fmt.Sprintf("codex.enforce-software-identity: %t -> %t", oldCfg.Codex.ResolvedEnforceSoftwareIdentity(), newCfg.Codex.ResolvedEnforceSoftwareIdentity()))
	}
	if oldCfg.CodexFingerprint.ResolvedSessionIdentityPoolSize() != newCfg.CodexFingerprint.ResolvedSessionIdentityPoolSize() {
		changes = append(changes, fmt.Sprintf(
			"codex-fingerprint.session-identity-pool-size: %d -> %d",
			oldCfg.CodexFingerprint.ResolvedSessionIdentityPoolSize(),
			newCfg.CodexFingerprint.ResolvedSessionIdentityPoolSize(),
		))
	}
	if oldCfg.ChatGPTWeb.TokenUsageEstimationEnabled() != newCfg.ChatGPTWeb.TokenUsageEstimationEnabled() {
		changes = append(changes, fmt.Sprintf("chatgpt-web.estimate-token-usage: %t -> %t", oldCfg.ChatGPTWeb.TokenUsageEstimationEnabled(), newCfg.ChatGPTWeb.TokenUsageEstimationEnabled()))
	}
	if !reflect.DeepEqual(oldCfg.ChatGPTWeb.Sentinel.GoVMCompatibility.Resolved(), newCfg.ChatGPTWeb.Sentinel.GoVMCompatibility.Resolved()) {
		changes = append(changes, "chatgpt-web.sentinel.go-vm-compatibility: updated (property values omitted)")
	}
	if oldCfg.ChatGPTWeb.Sentinel.Resolved().Mode != newCfg.ChatGPTWeb.Sentinel.Resolved().Mode || !reflect.DeepEqual(oldCfg.ChatGPTWeb.Sentinel.Remote, newCfg.ChatGPTWeb.Sentinel.Remote) {
		changes = append(changes, "chatgpt-web.sentinel.remote: updated (addresses and keys omitted)")
	}
	if !reflect.DeepEqual(oldCfg.SentinelSolver, newCfg.SentinelSolver) {
		changes = append(changes, "sentinel-solver: updated (keys and property values omitted)")
	}
	oldUsageCache := oldCfg.ChatGPTWeb.UsageCache.Resolved()
	newUsageCache := newCfg.ChatGPTWeb.UsageCache.Resolved()
	if oldUsageCache.Enabled != newUsageCache.Enabled {
		changes = append(changes, fmt.Sprintf("chatgpt-web.usage-cache.enabled: %t -> %t", oldUsageCache.Enabled, newUsageCache.Enabled))
	}
	if oldUsageCache.DiskThresholdMB != newUsageCache.DiskThresholdMB {
		changes = append(changes, fmt.Sprintf("chatgpt-web.usage-cache.disk-threshold-mb: %d -> %d", oldUsageCache.DiskThresholdMB, newUsageCache.DiskThresholdMB))
	}
	if oldUsageCache.MaxDiskSizeMB != newUsageCache.MaxDiskSizeMB {
		changes = append(changes, fmt.Sprintf("chatgpt-web.usage-cache.max-disk-size-mb: %d -> %d", oldUsageCache.MaxDiskSizeMB, newUsageCache.MaxDiskSizeMB))
	}
	if oldUsageCache.Path != newUsageCache.Path {
		changes = append(changes, fmt.Sprintf("chatgpt-web.usage-cache.path: %q -> %q", oldUsageCache.Path, newUsageCache.Path))
	}
	if oldCfg.ChatGPTWeb.ImageUsage.ResolvedAutoOutputQuality() != newCfg.ChatGPTWeb.ImageUsage.ResolvedAutoOutputQuality() {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.auto-output-quality: %s -> %s", oldCfg.ChatGPTWeb.ImageUsage.ResolvedAutoOutputQuality(), newCfg.ChatGPTWeb.ImageUsage.ResolvedAutoOutputQuality()))
	}
	oldFallbackUsage := oldCfg.ChatGPTWeb.ImageUsage.FallbackUsage.Resolved()
	newFallbackUsage := newCfg.ChatGPTWeb.ImageUsage.FallbackUsage.Resolved()
	if oldFallbackUsage.Enabled != newFallbackUsage.Enabled {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.fallback-usage.enabled: %t -> %t", oldFallbackUsage.Enabled, newFallbackUsage.Enabled))
	}
	if oldFallbackUsage.InputTextTokens != newFallbackUsage.InputTextTokens {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.fallback-usage.input-text-tokens: %d -> %d", oldFallbackUsage.InputTextTokens, newFallbackUsage.InputTextTokens))
	}
	if oldFallbackUsage.InputImageTokens != newFallbackUsage.InputImageTokens {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.fallback-usage.input-image-tokens: %d -> %d", oldFallbackUsage.InputImageTokens, newFallbackUsage.InputImageTokens))
	}
	if oldFallbackUsage.OutputTextTokens != newFallbackUsage.OutputTextTokens {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.fallback-usage.output-text-tokens: %d -> %d", oldFallbackUsage.OutputTextTokens, newFallbackUsage.OutputTextTokens))
	}
	if oldFallbackUsage.OutputImageTokens != newFallbackUsage.OutputImageTokens {
		changes = append(changes, fmt.Sprintf("chatgpt-web.image-usage.fallback-usage.output-image-tokens: %d -> %d", oldFallbackUsage.OutputImageTokens, newFallbackUsage.OutputImageTokens))
	}
	oldLoginProxy := oldCfg.ChatGPTWeb.LoginProxy.Resolved()
	newLoginProxy := newCfg.ChatGPTWeb.LoginProxy.Resolved()
	if oldLoginProxy.Enabled != newLoginProxy.Enabled {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.enabled: %t -> %t", oldLoginProxy.Enabled, newLoginProxy.Enabled))
	}
	if (oldLoginProxy.URLTemplate != "") != (newLoginProxy.URLTemplate != "") {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.url-template-configured: %t -> %t", oldLoginProxy.URLTemplate != "", newLoginProxy.URLTemplate != ""))
	} else if oldLoginProxy.URLTemplate != newLoginProxy.URLTemplate {
		changes = append(changes, "chatgpt-web.login-proxy.url-template: changed")
	}
	if oldLoginProxy.PlaceholderCharset != newLoginProxy.PlaceholderCharset {
		changes = append(changes, "chatgpt-web.login-proxy.placeholder-charset: changed")
	}
	if oldLoginProxy.RotateOnRetry != newLoginProxy.RotateOnRetry {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.rotate-on-retry: %t -> %t", oldLoginProxy.RotateOnRetry, newLoginProxy.RotateOnRetry))
	}
	if oldLoginProxy.RequestAttempts != newLoginProxy.RequestAttempts {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.request-attempts: %d -> %d", oldLoginProxy.RequestAttempts, newLoginProxy.RequestAttempts))
	}
	if oldLoginProxy.FlowAttempts != newLoginProxy.FlowAttempts {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.flow-attempts: %d -> %d", oldLoginProxy.FlowAttempts, newLoginProxy.FlowAttempts))
	}
	if oldLoginProxy.RetryDelayMilliseconds != newLoginProxy.RetryDelayMilliseconds {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.retry-delay-milliseconds: %d -> %d", oldLoginProxy.RetryDelayMilliseconds, newLoginProxy.RetryDelayMilliseconds))
	}
	if oldLoginProxy.AcquisitionTimeoutSeconds != newLoginProxy.AcquisitionTimeoutSeconds {
		changes = append(changes, fmt.Sprintf("chatgpt-web.login-proxy.acquisition-timeout-seconds: %d -> %d", oldLoginProxy.AcquisitionTimeoutSeconds, newLoginProxy.AcquisitionTimeoutSeconds))
	}
	if oldCfg.Images.ChatGPTWeb.ResolvedUpstreamModel() != newCfg.Images.ChatGPTWeb.ResolvedUpstreamModel() {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.upstream-model: %s -> %s", oldCfg.Images.ChatGPTWeb.ResolvedUpstreamModel(), newCfg.Images.ChatGPTWeb.ResolvedUpstreamModel()))
	}
	if strings.Join(oldCfg.Images.ResolvedImageModels(), "\x00") != strings.Join(newCfg.Images.ResolvedImageModels(), "\x00") {
		changes = append(changes, fmt.Sprintf("images.image-models: %v -> %v", oldCfg.Images.ResolvedImageModels(), newCfg.Images.ResolvedImageModels()))
	}
	if strings.Join(oldCfg.Images.ResolvedChatGPTWebImageModels(), "\x00") != strings.Join(newCfg.Images.ResolvedChatGPTWebImageModels(), "\x00") {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.image-models: %v -> %v", oldCfg.Images.ResolvedChatGPTWebImageModels(), newCfg.Images.ResolvedChatGPTWebImageModels()))
	}
	if oldCfg.Images.ChatGPTWeb.IgnoreUnsupportedParams != newCfg.Images.ChatGPTWeb.IgnoreUnsupportedParams {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.ignore-unsupported-params: %t -> %t", oldCfg.Images.ChatGPTWeb.IgnoreUnsupportedParams, newCfg.Images.ChatGPTWeb.IgnoreUnsupportedParams))
	}
	oldImageRuntime := oldCfg.Images.ChatGPTWeb.Resolved()
	newImageRuntime := newCfg.Images.ChatGPTWeb.Resolved()
	if oldImageRuntime.NormalizeMismatchedImageMIME != newImageRuntime.NormalizeMismatchedImageMIME {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.normalize-mismatched-image-mime: %t -> %t", oldImageRuntime.NormalizeMismatchedImageMIME, newImageRuntime.NormalizeMismatchedImageMIME))
	}
	if oldImageRuntime.NormalizeRemoteImageMIME != newImageRuntime.NormalizeRemoteImageMIME {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.normalize-remote-image-mime: %t -> %t", oldImageRuntime.NormalizeRemoteImageMIME, newImageRuntime.NormalizeRemoteImageMIME))
	}
	if oldImageRuntime.SanitizeErrorResponses != newImageRuntime.SanitizeErrorResponses {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.sanitize-error-responses: %t -> %t", oldImageRuntime.SanitizeErrorResponses, newImageRuntime.SanitizeErrorResponses))
	}
	if oldImageRuntime.AutoCleanupLibraryOnFull != newImageRuntime.AutoCleanupLibraryOnFull {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.auto-cleanup-library-on-full: %t -> %t", oldImageRuntime.AutoCleanupLibraryOnFull, newImageRuntime.AutoCleanupLibraryOnFull))
	}
	if oldImageRuntime.PollStallBreakerEnabled != newImageRuntime.PollStallBreakerEnabled {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.poll-stall-breaker-enabled: %t -> %t", oldImageRuntime.PollStallBreakerEnabled, newImageRuntime.PollStallBreakerEnabled))
	}
	if oldCfg.Images.CodexRequestTimeoutSeconds != newCfg.Images.CodexRequestTimeoutSeconds {
		changes = append(changes, fmt.Sprintf("images.codex-request-timeout-seconds: %d -> %d", oldCfg.Images.CodexRequestTimeoutSeconds, newCfg.Images.CodexRequestTimeoutSeconds))
	}
	if oldCfg.Images.ChatGPTWeb.BootstrapTimeoutSeconds != newCfg.Images.ChatGPTWeb.BootstrapTimeoutSeconds {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.bootstrap-timeout-seconds: %d -> %d", oldCfg.Images.ChatGPTWeb.BootstrapTimeoutSeconds, newCfg.Images.ChatGPTWeb.BootstrapTimeoutSeconds))
	}
	if oldCfg.Images.ChatGPTWeb.BootstrapRetries != newCfg.Images.ChatGPTWeb.BootstrapRetries {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.bootstrap-retries: %d -> %d", oldCfg.Images.ChatGPTWeb.BootstrapRetries, newCfg.Images.ChatGPTWeb.BootstrapRetries))
	}
	if oldCfg.Images.ChatGPTWeb.RequestTimeoutSeconds != newCfg.Images.ChatGPTWeb.RequestTimeoutSeconds {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.request-timeout-seconds: %d -> %d", oldCfg.Images.ChatGPTWeb.RequestTimeoutSeconds, newCfg.Images.ChatGPTWeb.RequestTimeoutSeconds))
	}
	if oldImageRuntime.PollStallSeconds != newImageRuntime.PollStallSeconds {
		changes = append(changes, fmt.Sprintf("images.chatgpt-web.poll-stall-seconds: %d -> %d", oldImageRuntime.PollStallSeconds, newImageRuntime.PollStallSeconds))
	}

	if !reflect.DeepEqual(oldCfg.XAIKey, newCfg.XAIKey) {
		changes = append(changes, "xai-api-key: updated")
	}
	// Codex keys (do not print key material)
	if len(oldCfg.CodexKey) != len(newCfg.CodexKey) {
		changes = append(changes, fmt.Sprintf("codex-api-key count: %d -> %d", len(oldCfg.CodexKey), len(newCfg.CodexKey)))
	} else {
		for i := range oldCfg.CodexKey {
			o := oldCfg.CodexKey[i]
			n := newCfg.CodexKey[i]
			if !reflect.DeepEqual(o.Weight, n.Weight) {
				changes = append(changes, fmt.Sprintf("codex[%d].weight: updated", i))
			}
			if !reflect.DeepEqual(o.RequestRetry, n.RequestRetry) {
				changes = append(changes, fmt.Sprintf("codex[%d].request-retry: updated", i))
			}
			if !reflect.DeepEqual(o.RequestScopedErrors, n.RequestScopedErrors) {
				changes = append(changes, fmt.Sprintf("codex[%d].request-scoped-errors: updated", i))
			}
			if strings.TrimSpace(o.BaseURL) != strings.TrimSpace(n.BaseURL) {
				changes = append(changes, fmt.Sprintf("codex[%d].base-url: %s -> %s", i, formatURL(o.BaseURL), formatURL(n.BaseURL)))
			}
			if strings.TrimSpace(o.ProxyURL) != strings.TrimSpace(n.ProxyURL) {
				changes = append(changes, fmt.Sprintf("codex[%d].proxy-url: %s -> %s", i, formatProxyURL(o.ProxyURL), formatProxyURL(n.ProxyURL)))
			}
			if strings.TrimSpace(o.Prefix) != strings.TrimSpace(n.Prefix) {
				changes = append(changes, fmt.Sprintf("codex[%d].prefix: %s -> %s", i, strings.TrimSpace(o.Prefix), strings.TrimSpace(n.Prefix)))
			}
			if o.Websockets != n.Websockets {
				changes = append(changes, fmt.Sprintf("codex[%d].websockets: %t -> %t", i, o.Websockets, n.Websockets))
			}
			if o.AlphaSearch != n.AlphaSearch {
				changes = append(changes, fmt.Sprintf("codex[%d].alpha-search: %t -> %t", i, o.AlphaSearch, n.AlphaSearch))
			}
			if strings.TrimSpace(o.APIKey) != strings.TrimSpace(n.APIKey) {
				changes = append(changes, fmt.Sprintf("codex[%d].api-key: updated", i))
			}
			if !equalStringMap(o.Headers, n.Headers) {
				changes = append(changes, fmt.Sprintf("codex[%d].headers: updated", i))
			}
			oldModels := SummarizeCodexModels(o.Models)
			newModels := SummarizeCodexModels(n.Models)
			if oldModels.hash != newModels.hash {
				changes = append(changes, fmt.Sprintf("codex[%d].models: updated (%d -> %d entries)", i, oldModels.count, newModels.count))
			}
			oldExcluded := SummarizeExcludedModels(o.ExcludedModels)
			newExcluded := SummarizeExcludedModels(n.ExcludedModels)
			if oldExcluded.hash != newExcluded.hash {
				changes = append(changes, fmt.Sprintf("codex[%d].excluded-models: updated (%d -> %d entries)", i, oldExcluded.count, newExcluded.count))
			}
		}
	}

	if entries, _ := DiffOAuthExcludedModelChanges(oldCfg.OAuthExcludedModels, newCfg.OAuthExcludedModels); len(entries) > 0 {
		changes = append(changes, entries...)
	}
	if entries, _ := DiffOAuthModelAliasChanges(oldCfg.OAuthModelAlias, newCfg.OAuthModelAlias); len(entries) > 0 {
		changes = append(changes, entries...)
	}

	// Remote management (never print the key)
	if oldCfg.RemoteManagement.AllowRemote != newCfg.RemoteManagement.AllowRemote {
		changes = append(changes, fmt.Sprintf("remote-management.allow-remote: %t -> %t", oldCfg.RemoteManagement.AllowRemote, newCfg.RemoteManagement.AllowRemote))
	}
	if oldCfg.RemoteManagement.DisableControlPanel != newCfg.RemoteManagement.DisableControlPanel {
		changes = append(changes, fmt.Sprintf("remote-management.disable-control-panel: %t -> %t", oldCfg.RemoteManagement.DisableControlPanel, newCfg.RemoteManagement.DisableControlPanel))
	}
	if oldCfg.RemoteManagement.DisableAutoUpdatePanel != newCfg.RemoteManagement.DisableAutoUpdatePanel {
		changes = append(changes, fmt.Sprintf("remote-management.disable-auto-update-panel: %t -> %t", oldCfg.RemoteManagement.DisableAutoUpdatePanel, newCfg.RemoteManagement.DisableAutoUpdatePanel))
	}
	oldAccessPath := strings.TrimSpace(oldCfg.RemoteManagement.AccessPath)
	newAccessPath := strings.TrimSpace(newCfg.RemoteManagement.AccessPath)
	if oldAccessPath != newAccessPath {
		switch {
		case oldAccessPath == "" && newAccessPath != "":
			changes = append(changes, "remote-management.access-path: created")
		case oldAccessPath != "" && newAccessPath == "":
			changes = append(changes, "remote-management.access-path: deleted")
		default:
			changes = append(changes, "remote-management.access-path: updated")
		}
	}
	oldPanelRepo := strings.TrimSpace(oldCfg.RemoteManagement.PanelGitHubRepository)
	newPanelRepo := strings.TrimSpace(newCfg.RemoteManagement.PanelGitHubRepository)
	if oldPanelRepo != newPanelRepo {
		changes = append(changes, fmt.Sprintf("remote-management.panel-github-repository: %s -> %s", formatURL(oldPanelRepo), formatURL(newPanelRepo)))
	}
	if oldCfg.RemoteManagement.SecretKey != newCfg.RemoteManagement.SecretKey {
		switch {
		case oldCfg.RemoteManagement.SecretKey == "" && newCfg.RemoteManagement.SecretKey != "":
			changes = append(changes, "remote-management.secret-key: created")
		case oldCfg.RemoteManagement.SecretKey != "" && newCfg.RemoteManagement.SecretKey == "":
			changes = append(changes, "remote-management.secret-key: deleted")
		default:
			changes = append(changes, "remote-management.secret-key: updated")
		}
	}

	// OpenAI compatibility providers (summarized)
	if compat := DiffOpenAICompatibility(oldCfg.OpenAICompatibility, newCfg.OpenAICompatibility); len(compat) > 0 {
		changes = append(changes, "openai-compatibility:")
		for _, c := range compat {
			changes = append(changes, "  "+c)
		}
	}

	// Vertex-compatible API keys
	if len(oldCfg.VertexCompatAPIKey) != len(newCfg.VertexCompatAPIKey) {
		changes = append(changes, fmt.Sprintf("vertex-api-key count: %d -> %d", len(oldCfg.VertexCompatAPIKey), len(newCfg.VertexCompatAPIKey)))
	} else {
		for i := range oldCfg.VertexCompatAPIKey {
			o := oldCfg.VertexCompatAPIKey[i]
			n := newCfg.VertexCompatAPIKey[i]
			if !reflect.DeepEqual(o.Weight, n.Weight) {
				changes = append(changes, fmt.Sprintf("vertex[%d].weight: updated", i))
			}
			if !reflect.DeepEqual(o.RequestRetry, n.RequestRetry) {
				changes = append(changes, fmt.Sprintf("vertex[%d].request-retry: updated", i))
			}
			if !reflect.DeepEqual(o.RequestScopedErrors, n.RequestScopedErrors) {
				changes = append(changes, fmt.Sprintf("vertex[%d].request-scoped-errors: updated", i))
			}
			if strings.TrimSpace(o.BaseURL) != strings.TrimSpace(n.BaseURL) {
				changes = append(changes, fmt.Sprintf("vertex[%d].base-url: %s -> %s", i, formatURL(o.BaseURL), formatURL(n.BaseURL)))
			}
			if strings.TrimSpace(o.ProxyURL) != strings.TrimSpace(n.ProxyURL) {
				changes = append(changes, fmt.Sprintf("vertex[%d].proxy-url: %s -> %s", i, formatProxyURL(o.ProxyURL), formatProxyURL(n.ProxyURL)))
			}
			if strings.TrimSpace(o.Prefix) != strings.TrimSpace(n.Prefix) {
				changes = append(changes, fmt.Sprintf("vertex[%d].prefix: %s -> %s", i, strings.TrimSpace(o.Prefix), strings.TrimSpace(n.Prefix)))
			}
			if strings.TrimSpace(o.APIKey) != strings.TrimSpace(n.APIKey) {
				changes = append(changes, fmt.Sprintf("vertex[%d].api-key: updated", i))
			}
			oldModels := SummarizeVertexModels(o.Models)
			newModels := SummarizeVertexModels(n.Models)
			if oldModels.hash != newModels.hash {
				changes = append(changes, fmt.Sprintf("vertex[%d].models: updated (%d -> %d entries)", i, oldModels.count, newModels.count))
			}
			oldExcluded := SummarizeExcludedModels(o.ExcludedModels)
			newExcluded := SummarizeExcludedModels(n.ExcludedModels)
			if oldExcluded.hash != newExcluded.hash {
				changes = append(changes, fmt.Sprintf("vertex[%d].excluded-models: updated (%d -> %d entries)", i, oldExcluded.count, newExcluded.count))
			}
			if !equalStringMap(o.Headers, n.Headers) {
				changes = append(changes, fmt.Sprintf("vertex[%d].headers: updated", i))
			}
		}
	}

	return changes
}

func trimStrings(in []string) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = strings.TrimSpace(in[i])
	}
	return out
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func formatProxyURL(raw string) string {
	return formatURL(raw)
}

func formatURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "<none>"
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "<redacted>"
	}
	host := strings.TrimSpace(parsed.Host)
	scheme := strings.TrimSpace(parsed.Scheme)
	if host == "" {
		// Allow host:port style without scheme.
		parsed2, err2 := url.Parse("http://" + trimmed)
		if err2 == nil {
			host = strings.TrimSpace(parsed2.Host)
		}
		scheme = ""
	}
	if host == "" {
		return "<redacted>"
	}
	if scheme == "" {
		return host
	}
	return scheme + "://" + host
}

func routingSessionAffinityFailoverEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.Routing.SessionAffinityFailover == nil {
		return true
	}
	return *cfg.Routing.SessionAffinityFailover
}
