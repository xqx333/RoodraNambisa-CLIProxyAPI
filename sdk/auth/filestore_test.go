package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/vertex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		expected string
	}{
		{
			"antigravity top-level access_token",
			map[string]any{"access_token": "tok-abc"},
			"tok-abc",
		},
		{
			"gemini nested token.access_token",
			map[string]any{
				"token": map[string]any{"access_token": "tok-nested"},
			},
			"tok-nested",
		},
		{
			"top-level takes precedence over nested",
			map[string]any{
				"access_token": "tok-top",
				"token":        map[string]any{"access_token": "tok-nested"},
			},
			"tok-top",
		},
		{
			"empty metadata",
			map[string]any{},
			"",
		},
		{
			"whitespace-only access_token",
			map[string]any{"access_token": "   "},
			"",
		},
		{
			"wrong type access_token",
			map[string]any{"access_token": 12345},
			"",
		},
		{
			"token is not a map",
			map[string]any{"token": "not-a-map"},
			"",
		},
		{
			"nested whitespace-only",
			map[string]any{
				"token": map[string]any{"access_token": "  "},
			},
			"",
		},
		{
			"fallback to nested when top-level empty",
			map[string]any{
				"access_token": "",
				"token":        map[string]any{"access_token": "tok-fallback"},
			},
			"tok-fallback",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractAccessToken(tt.metadata)
			if got != tt.expected {
				t.Errorf("extractAccessToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileTokenStoreReadAuthFileSetsCanonicalSourceHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	data := []byte(`{"type":"claude","email":"reader@example.com"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	store := NewFileTokenStore()
	auth, err := store.readAuthFile(path, dir)
	if err != nil {
		t.Fatalf("readAuthFile returned error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected auth to be loaded")
	}
	wantRaw, err := cliproxyauth.CanonicalMetadataBytes(auth)
	if err != nil {
		t.Fatalf("CanonicalMetadataBytes() error = %v", err)
	}
	if got, want := auth.Attributes[cliproxyauth.SourceHashAttributeKey], cliproxyauth.SourceHashFromBytes(wantRaw); got != want {
		t.Fatalf("source hash = %q, want %q", got, want)
	}
	if rawHash := cliproxyauth.SourceHashFromBytes(data); rawHash == auth.Attributes[cliproxyauth.SourceHashAttributeKey] {
		t.Fatal("expected canonical source hash to differ from raw file hash")
	}
}

func TestFileTokenStoreReadAuthFilePrefersMetadataPlanTypeForCodex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	data := []byte(`{"type":"codex","email":"reader@example.com","plan_type":"team","id_token":"` + testCodexIDToken("acct-1", "pro") + `"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	store := NewFileTokenStore()
	auth, err := store.readAuthFile(path, dir)
	if err != nil {
		t.Fatalf("readAuthFile returned error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected auth to be loaded")
	}
	if got := auth.Attributes["plan_type"]; got != "team" {
		t.Fatalf("plan_type = %q, want %q", got, "team")
	}
}

func TestFileTokenStoreSaveStorageBackedAuthSetsCanonicalSourceHash(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	auth := &cliproxyauth.Auth{
		ID:       "auth.json",
		FileName: "auth.json",
		Provider: "gemini",
		Storage:  &testTokenStorage{},
		Metadata: map[string]any{
			"type":                 "gemini",
			"email":                "writer@example.com",
			"tool_prefix_disabled": true,
		},
	}

	path, err := store.Save(nil, auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if got, ok := auth.Metadata["access_token"].(string); !ok || got != "tok-storage" {
		t.Fatalf("metadata access_token = %#v, want %q", auth.Metadata["access_token"], "tok-storage")
	}
	if got, ok := auth.Metadata["refresh_token"].(string); !ok || got != "refresh-storage" {
		t.Fatalf("metadata refresh_token = %#v, want %q", auth.Metadata["refresh_token"], "refresh-storage")
	}
	if got, ok := auth.Metadata["tool_prefix_disabled"].(bool); !ok || !got {
		t.Fatalf("metadata tool_prefix_disabled = %#v, want true", auth.Metadata["tool_prefix_disabled"])
	}

	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	wantRaw, err := cliproxyauth.CanonicalMetadataBytes(auth)
	if err != nil {
		t.Fatalf("CanonicalMetadataBytes() error = %v", err)
	}
	wantHash := cliproxyauth.SourceHashFromBytes(wantRaw)
	if got := auth.Attributes[cliproxyauth.SourceHashAttributeKey]; got != wantHash {
		t.Fatalf("source hash = %q, want %q", got, wantHash)
	}
	if got, ok := auth.Metadata["disabled"].(bool); !ok || got {
		t.Fatalf("metadata disabled = %#v, want false", auth.Metadata["disabled"])
	}
	if !json.Valid(rawFile) {
		t.Fatalf("persisted file is not valid JSON: %s", rawFile)
	}
	if rawHash := cliproxyauth.SourceHashFromBytes(rawFile); rawHash != wantHash {
		t.Fatalf("raw storage file hash = %q, want %q", rawHash, wantHash)
	}
}

func TestFileTokenStoreSaveVertexStorageBackedAuthPreservesMetadataOnlyFields(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	auth := &cliproxyauth.Auth{
		ID:       "vertex.json",
		FileName: "vertex.json",
		Provider: "vertex",
		Storage: &vertex.VertexCredentialStorage{
			ServiceAccount: map[string]any{
				"type":         "service_account",
				"project_id":   "vertex-project",
				"client_email": "vertex@example.com",
			},
			ProjectID: "vertex-project",
			Email:     "vertex@example.com",
			Location:  "us-central1",
		},
		Metadata: map[string]any{
			"type":                 "vertex",
			"email":                "vertex@example.com",
			"label":                "vertex-label",
			"tool_prefix_disabled": true,
		},
	}

	path, err := store.Save(nil, auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if got, ok := auth.Metadata["label"].(string); !ok || got != "vertex-label" {
		t.Fatalf("metadata label = %#v, want %q", auth.Metadata["label"], "vertex-label")
	}
	if got, ok := auth.Metadata["tool_prefix_disabled"].(bool); !ok || !got {
		t.Fatalf("metadata tool_prefix_disabled = %#v, want true", auth.Metadata["tool_prefix_disabled"])
	}
	if _, ok := auth.Metadata["service_account"].(map[string]any); !ok {
		t.Fatalf("metadata service_account = %#v, want object", auth.Metadata["service_account"])
	}

	rawFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawFile, &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got, ok := payload["label"].(string); !ok || got != "vertex-label" {
		t.Fatalf("persisted label = %#v, want %q", payload["label"], "vertex-label")
	}
	wantRaw, err := cliproxyauth.CanonicalMetadataBytes(auth)
	if err != nil {
		t.Fatalf("CanonicalMetadataBytes() error = %v", err)
	}
	wantHash := cliproxyauth.SourceHashFromBytes(wantRaw)
	if got := auth.Attributes[cliproxyauth.SourceHashAttributeKey]; got != wantHash {
		t.Fatalf("source hash = %q, want %q", got, wantHash)
	}
}

type testTokenStorage struct {
	metadata map[string]any
}

func testCodexIDToken(accountID string, planType string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  planType,
		},
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func (s *testTokenStorage) SetMetadata(meta map[string]any) {
	if meta == nil {
		s.metadata = nil
		return
	}
	cloned := make(map[string]any, len(meta))
	for key, value := range meta {
		cloned[key] = value
	}
	s.metadata = cloned
}

func (s *testTokenStorage) SaveTokenToFile(authFilePath string) error {
	payload := map[string]any{
		"access_token":  "tok-storage",
		"refresh_token": "refresh-storage",
	}
	for key, value := range s.metadata {
		payload[key] = value
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(authFilePath, raw, 0o600)
}
