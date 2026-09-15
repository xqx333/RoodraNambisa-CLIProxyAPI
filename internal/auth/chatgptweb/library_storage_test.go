package chatgptweb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLibraryStorageRejectionOnlyExplicitCodes(t *testing.T) {
	for _, body := range []string{`{"detail":{"code":"library_storage_limit_exceeded"}}`, `{"error":{"code":"over_user_quota"}}`, `{"error_code":"library_storage_limit_exceeded"}`} {
		if !LibraryStorageRejection([]byte(body)) {
			t.Fatalf("missed %s", body)
		}
	}
	for _, body := range []string{`{"detail":{}}`, `{"code":"throttled"}`, `{"code":"rate_limit_exceeded"}`, `{"message":"over_user_quota"}`, `{"code":"insufficient_quota"}`, `not JSON`} {
		if LibraryStorageRejection([]byte(body)) {
			t.Fatalf("unsafe match %s", body)
		}
	}
}

func TestLibraryAutoCleanupRechecksCapacity(t *testing.T) {
	for _, tt := range []struct {
		remaining int64
		over      bool
		size      int64
		listing   bool
	}{{50, false, 10, false}, {50, false, 50, false}, {50, false, 51, true}, {0, false, 1, true}, {50, true, 1, true}} {
		calls, listings := 0, 0
		_, err := CleanupLibraryWhenFull(t.Context(), func(_ context.Context, _ string, path string, _ any) ([]byte, error) {
			calls++
			if strings.HasSuffix(path, "usage") {
				return []byte(fmt.Sprintf(`{"used_bytes":50,"allowed_bytes":100,"remaining_bytes":%d,"is_over_limit":%t}`, tt.remaining, tt.over)), nil
			}
			listings++
			return []byte(`{"items":[],"cursor":null}`), nil
		}, tt.size, nil)
		if err != nil || (listings > 0) != tt.listing || (!tt.listing && calls != 1) {
			t.Fatalf("case=%+v calls=%d listing=%d err=%v", tt, calls, listings, err)
		}
	}
}

func TestLibraryCleanupRetriesOnlyExplicitFailedItems(t *testing.T) {
	calls := 0
	var saved []LibraryCleanupProgress
	p, err := CleanupLibrary(t.Context(), func(_ context.Context, _ string, path string, body any) ([]byte, error) {
		if strings.HasSuffix(path, "usage") {
			return []byte(libraryUsageFixture), nil
		}
		if strings.HasSuffix(path, "delete-batch") {
			calls++
			if calls == 1 {
				return []byte(`{"files":[{"library_file_id":"libfile_a","success":true},{"library_file_id":"libfile_b","success":false}]}`), nil
			}
			raw, _ := json.Marshal(body)
			if strings.Contains(string(raw), "libfile_a") {
				t.Fatal("successful deletion replayed")
			}
			return []byte(`{"files":[{"library_file_id":"libfile_b","success":true}]}`), nil
		}
		return []byte(`{"items":[{"id":"libfile_a","access_kind":"owned"},{"id":"libfile_b","access_kind":"owned"}]}`), nil
	}, func(p LibraryCleanupProgress) { saved = append(saved, p) })
	if err != nil || p.Deleted != 2 || p.Failed != 0 || p.Retried != 1 || calls != 2 {
		t.Fatalf("progress=%+v err=%v calls=%d", p, err, calls)
	}
	if saved[0].Deleted != 0 {
		t.Fatal("mutable observer result")
	}
}

func TestLibraryProgressCloneDoesNotAliasFailureReasons(t *testing.T) {
	p := LibraryCleanupProgress{FailureReasons: map[string]int{"permission_denied": 1}, Before: &LibraryUsage{UsedBytes: 10}}
	copy := p.Clone()
	copy.FailureReasons["permission_denied"] = 99
	copy.Before.UsedBytes = 99
	if p.FailureReasons["permission_denied"] != 1 || p.Before.UsedBytes != 10 {
		t.Fatal("snapshot aliases live progress")
	}
}
