package config

import "testing"

func TestSanitizeOAuthModelAlias_PreservesForkFlag(t *testing.T) {
	cfg := &Config{
		OAuthModelAlias: map[string][]OAuthModelAlias{
			" CoDeX ": {
				{Name: " gpt-5 ", Alias: " g5 ", Fork: true},
				{Name: "gpt-6", Alias: "g6"},
			},
		},
	}

	cfg.SanitizeOAuthModelAlias()

	aliases := cfg.OAuthModelAlias["codex"]
	if len(aliases) != 2 {
		t.Fatalf("expected 2 sanitized aliases, got %d", len(aliases))
	}
	if aliases[0].Name != "gpt-5" || aliases[0].Alias != "g5" || !aliases[0].Fork {
		t.Fatalf("expected first alias to be gpt-5->g5 fork=true, got name=%q alias=%q fork=%v", aliases[0].Name, aliases[0].Alias, aliases[0].Fork)
	}
	if aliases[1].Name != "gpt-6" || aliases[1].Alias != "g6" || aliases[1].Fork {
		t.Fatalf("expected second alias to be gpt-6->g6 fork=false, got name=%q alias=%q fork=%v", aliases[1].Name, aliases[1].Alias, aliases[1].Fork)
	}
}

func TestSanitizeOAuthModelAlias_AllowsMultipleAliasesForSameName(t *testing.T) {
	cfg := &Config{
		OAuthModelAlias: map[string][]OAuthModelAlias{
			"antigravity": {
				{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5-20251101", Fork: true},
				{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5-20251101-thinking", Fork: true},
				{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5", Fork: true},
			},
		},
	}

	cfg.SanitizeOAuthModelAlias()

	aliases := cfg.OAuthModelAlias["antigravity"]
	expected := []OAuthModelAlias{
		{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5-20251101", Fork: true},
		{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5-20251101-thinking", Fork: true},
		{Name: "gemini-claude-opus-4-5-thinking", Alias: "claude-opus-4-5", Fork: true},
	}
	if len(aliases) != len(expected) {
		t.Fatalf("expected %d sanitized aliases, got %d", len(expected), len(aliases))
	}
	for i, exp := range expected {
		if aliases[i].Name != exp.Name || aliases[i].Alias != exp.Alias || aliases[i].Fork != exp.Fork {
			t.Fatalf("expected alias %d to be name=%q alias=%q fork=%v, got name=%q alias=%q fork=%v", i, exp.Name, exp.Alias, exp.Fork, aliases[i].Name, aliases[i].Alias, aliases[i].Fork)
		}
	}
}

func TestSanitizeCodexCustomModels(t *testing.T) {
	cfg := &Config{
		CodexCustomModels: []CodexCustomModel{
			{ID: " ", DisplayName: "missing id", Groups: []string{"plus"}},
			{ID: "gpt-empty-groups", Groups: []string{"unknown"}},
			{ID: " gpt-5.5-codex ", DisplayName: " GPT 5.5 Codex ", Groups: []string{" Pro ", "plus", "PLUS", "unknown"}},
			{ID: "GPT-5.5-CODEX", DisplayName: "ignored duplicate", Groups: []string{"team", "go"}},
			{ID: "gpt-5.5-mini-codex", Groups: []string{"business", "free"}},
		},
	}

	cfg.SanitizeCodexCustomModels()

	if len(cfg.CodexCustomModels) != 2 {
		t.Fatalf("expected 2 sanitized custom models, got %d", len(cfg.CodexCustomModels))
	}

	first := cfg.CodexCustomModels[0]
	if first.ID != "gpt-5.5-codex" || first.DisplayName != "GPT 5.5 Codex" {
		t.Fatalf("unexpected first custom model: %+v", first)
	}
	expectedFirstGroups := []string{"plus", "pro", "team", "go"}
	if len(first.Groups) != len(expectedFirstGroups) {
		t.Fatalf("first groups = %v, want %v", first.Groups, expectedFirstGroups)
	}
	for i, group := range expectedFirstGroups {
		if first.Groups[i] != group {
			t.Fatalf("first groups = %v, want %v", first.Groups, expectedFirstGroups)
		}
	}

	second := cfg.CodexCustomModels[1]
	if second.ID != "gpt-5.5-mini-codex" || second.DisplayName != "gpt-5.5-mini-codex" {
		t.Fatalf("unexpected second custom model: %+v", second)
	}
	expectedSecondGroups := []string{"free", "business"}
	if len(second.Groups) != len(expectedSecondGroups) {
		t.Fatalf("second groups = %v, want %v", second.Groups, expectedSecondGroups)
	}
	for i, group := range expectedSecondGroups {
		if second.Groups[i] != group {
			t.Fatalf("second groups = %v, want %v", second.Groups, expectedSecondGroups)
		}
	}
}
