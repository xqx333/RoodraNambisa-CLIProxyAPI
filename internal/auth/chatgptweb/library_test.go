package chatgptweb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const libraryUsageFixture = `{"used_bytes":50,"allowed_bytes":100,"remaining_bytes":50,"is_over_limit":false}`

func TestLibraryCleanupInventoryBeforeDeleteAndPerFileResults(t *testing.T) {
	pages, batches, usage := 0, 0, 0
	progress, err := CleanupLibrary(t.Context(), func(ctx context.Context, method, path string, body any) ([]byte, error) {
		switch path {
		case "/backend-api/files/library/storage/usage":
			if method != http.MethodGet || body != nil {
				t.Fatal("invalid usage request")
			}
			usage++
			return []byte(libraryUsageFixture), nil
		case "/backend-api/files/library":
			if batches != 0 {
				t.Fatal("deletion began before inventory finished")
			}
			pages++
			if pages == 1 {
				return []byte(`{"items":[{"id":"libfile_a","file_id":"file_a","access_kind":"owned","directory_id":"folder_a","file_name":"a.png"},{"id":"external","access_kind":"shared"}],"cursor":"next"}`), nil
			}
			return []byte(`{"items":[{"id":"libfile_a","file_id":"file_a","access_kind":"owned"},{"id":"libfile_b","file_id":"file_b","access_kind":"owned"}],"cursor":null}`), nil
		case "/backend-api/files/library/files/delete-batch":
			batches++
			payload, _ := json.Marshal(body)
			if !strings.Contains(string(payload), `"parent_directory_id":"folder_a"`) || !strings.Contains(string(payload), `"library_file_id":"libfile_b"`) {
				t.Fatalf("payload = %s", payload)
			}
			return []byte(`{"files":[{"library_file_id":"libfile_b","success":false,"code":"permission_denied"},{"library_file_id":"libfile_a","success":true}]}`), nil
		default:
			t.Fatalf("unexpected request %s", path)
			return nil, nil
		}
	}, nil)
	if err == nil || progress.Total != 2 || progress.Deleted != 1 || progress.Failed != 1 || progress.Skipped != 1 || pages != 2 || batches != 1 || usage != 2 || progress.After == nil {
		t.Fatalf("progress=%+v error=%v", progress, err)
	}
}

func TestLibraryCleanupRejectsUnsafeInventoryBeforeDeleting(t *testing.T) {
	for _, fixture := range []string{`{}`, `{"items":null}`, `{"items":[{"id":"../wrong","access_kind":"owned"}]}`, `{"items":[],"cursor":"loop"}`} {
		t.Run(fixture, func(t *testing.T) {
			_, err := CleanupLibrary(t.Context(), func(_ context.Context, _ string, path string, _ any) ([]byte, error) {
				if strings.HasSuffix(path, "usage") {
					return []byte(libraryUsageFixture), nil
				}
				if strings.HasSuffix(path, "delete-batch") {
					t.Fatal("unsafe inventory deleted")
				}
				return []byte(fixture), nil
			}, nil)
			if err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

func TestLibraryCleanupDoesNotReplayUnconfirmedDeletion(t *testing.T) {
	for _, fixture := range []string{`{}`, `{"files":[]}`, `{"files":[{"library_file_id":"other","success":true}]}`, `{"files":[{"library_file_id":"libfile_a"}]}`} {
		t.Run(fixture, func(t *testing.T) {
			calls := 0
			_, err := CleanupLibrary(t.Context(), func(_ context.Context, _ string, path string, _ any) ([]byte, error) {
				if strings.HasSuffix(path, "usage") {
					return []byte(libraryUsageFixture), nil
				}
				if strings.HasSuffix(path, "delete-batch") {
					calls++
					return []byte(fixture), nil
				}
				return []byte(`{"items":[{"id":"libfile_a","file_id":"file_a","access_kind":"owned"}],"cursor":null}`), nil
			}, nil)
			if err == nil || calls != 1 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
		})
	}
}

func TestLibraryDeletionFailureReasonsAreSafeCategories(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"permission", `{"code":"forbidden"}`, "permission_denied"},
		{"missing", `{"reason":"file_not_found"}`, "not_found"},
		{"busy", `{"message":"file is still processing"}`, "conflict_or_in_progress"},
		{"rate", `{"error_code":"rate_limit_exceeded"}`, "rate_limited"},
		{"invalid", `{"error":"invalid library file"}`, "invalid_request"},
		{"unknown", `{"detail":"opaque upstream value"}`, "upstream_rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.body), &fields); err != nil {
				t.Fatal(err)
			}
			if got := classifyLibraryDeletionFailure(fields); got != test.want {
				t.Fatalf("category = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLibraryCleanupCancellationAndExternalFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := CleanupLibrary(ctx, func(context.Context, string, string, any) ([]byte, error) {
		t.Fatal("canceled request executed")
		return nil, nil
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	p, err := CleanupLibrary(t.Context(), func(_ context.Context, _ string, path string, _ any) ([]byte, error) {
		if strings.HasSuffix(path, "usage") {
			return []byte(libraryUsageFixture), nil
		}
		if strings.HasSuffix(path, "delete-batch") {
			t.Fatal("external or trashed file deleted")
		}
		return []byte(`{"items":[{"id":"one","access_kind":"owned","library_provider":"google_drive"},{"id":"two","access_kind":"owned","trashed_at":"2026-09-01"},{"id":"three","access_kind":"owned","kind":"folder"},{"id":"four"}],"cursor":null}`), nil
	}, nil)
	if err != nil || p.Total != 0 || p.Skipped != 4 {
		t.Fatalf("%+v %v", p, err)
	}
}
