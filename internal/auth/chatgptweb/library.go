package chatgptweb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"
)

const (
	libraryPageSize          = 100
	libraryDeleteBatchSize   = 20
	libraryMaxPages          = 1000
	libraryMaxInventoryBytes = 8 << 20
)

type LibraryUsage struct {
	UsedBytes      int64 `json:"used_bytes"`
	AllowedBytes   int64 `json:"allowed_bytes"`
	RemainingBytes int64 `json:"remaining_bytes"`
	IsOverLimit    bool  `json:"is_over_limit"`
}

type LibraryCleanupProgress struct {
	Stage          string         `json:"stage"`
	Scanned        int            `json:"scanned"`
	Total          int            `json:"total_files"`
	Deleted        int            `json:"deleted_files"`
	Failed         int            `json:"failed_files"`
	Skipped        int            `json:"skipped_files"`
	Retried        int            `json:"retried_files"`
	FailureReasons map[string]int `json:"failure_reasons,omitempty"`
	Before         *LibraryUsage  `json:"before,omitempty"`
	After          *LibraryUsage  `json:"after,omitempty"`
}

func (p LibraryCleanupProgress) Clone() LibraryCleanupProgress {
	p.FailureReasons = maps.Clone(p.FailureReasons)
	if p.Before != nil {
		before := *p.Before
		p.Before = &before
	}
	if p.After != nil {
		after := *p.After
		p.After = &after
	}
	return p
}

type LibraryRequest func(context.Context, string, string, any) ([]byte, error)

type libraryDeleteFile struct {
	LibraryFileID     string `json:"library_file_id"`
	FileID            string `json:"file_id,omitempty"`
	ParentDirectoryID string `json:"parent_directory_id,omitempty"`
	Name              string `json:"file_name,omitempty"`
}

func readLibraryUsage(ctx context.Context, request LibraryRequest) (*LibraryUsage, error) {
	body, err := request(ctx, http.MethodGet, "/backend-api/files/library/storage/usage", nil)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Used      *int64 `json:"used_bytes"`
		Allowed   *int64 `json:"allowed_bytes"`
		Remaining *int64 `json:"remaining_bytes"`
		Over      *bool  `json:"is_over_limit"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Used == nil || wire.Allowed == nil || wire.Remaining == nil || wire.Over == nil || *wire.Used < 0 || *wire.Allowed < 0 {
		return nil, errors.New("invalid library storage response")
	}
	return &LibraryUsage{UsedBytes: *wire.Used, AllowedBytes: *wire.Allowed, RemainingBytes: *wire.Remaining, IsOverLimit: *wire.Over}, nil
}

func validLibraryID(id string) bool {
	return id != "" && len(id) <= 256 && !strings.ContainsAny(id, "/\\?#\r\n\t\x00")
}

// CleanupLibrary inventories owned first-party files before deleting anything.
// A frozen inventory avoids pagination shifts and does not include later uploads.
// It neither deletes chats nor empties existing trash or mounted third-party files.
func CleanupLibrary(ctx context.Context, request LibraryRequest, observe func(LibraryCleanupProgress)) (LibraryCleanupProgress, error) {
	return cleanupLibrary(ctx, request, observe, nil)
}

// CleanupLibraryWhenFull rechecks authoritative capacity after in-flight work drains.
// A quota-like upload error alone never authorizes automatic deletion.
func CleanupLibraryWhenFull(ctx context.Context, request LibraryRequest, requiredBytes int64, observe func(LibraryCleanupProgress)) (LibraryCleanupProgress, error) {
	return cleanupLibrary(ctx, request, observe, &requiredBytes)
}

func cleanupLibrary(ctx context.Context, request LibraryRequest, observe func(LibraryCleanupProgress), requiredBytes *int64) (LibraryCleanupProgress, error) {
	p := LibraryCleanupProgress{Stage: "inspecting"}
	emit := func() {
		if observe != nil {
			observe(p.Clone())
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request == nil {
		return p, errors.New("library client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	emit()
	before, err := readLibraryUsage(ctx, request)
	if err != nil {
		return p, err
	}
	p.Before = before
	if requiredBytes != nil && !before.IsOverLimit && before.RemainingBytes > 0 && *requiredBytes <= before.RemainingBytes {
		p.After = before
		return p, nil
	}
	p.Stage = "listing"
	emit()
	var files []libraryDeleteFile
	seenFiles, seenCursors := map[string]bool{}, map[string]bool{}
	var cursor *string
	inventoryBytes := 0
	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		if page >= libraryMaxPages {
			return p, errors.New("library inventory page limit exceeded; nothing was deleted")
		}
		body, err := request(ctx, http.MethodPost, "/backend-api/files/library", map[string]any{"limit": libraryPageSize, "cursor": cursor, "include_hidden_files": true})
		if err != nil {
			return p, err
		}
		var wire struct {
			Items *[]struct {
				ID          string  `json:"id"`
				FileID      string  `json:"file_id"`
				Name        string  `json:"file_name"`
				DirectoryID string  `json:"directory_id"`
				AccessKind  string  `json:"access_kind"`
				Provider    string  `json:"library_provider"`
				Kind        string  `json:"kind"`
				TrashedAt   *string `json:"trashed_at"`
			} `json:"items"`
			Cursor *string `json:"cursor"`
		}
		if json.Unmarshal(body, &wire) != nil || wire.Items == nil {
			return p, errors.New("invalid library inventory response; nothing was deleted")
		}
		for _, item := range *wire.Items {
			p.Scanned++
			if item.AccessKind != "owned" || (item.Kind != "" && item.Kind != "file") || item.TrashedAt != nil || (item.Provider != "" && item.Provider != "chatgpt" && item.Provider != "openai") || (item.FileID != "" && !strings.HasPrefix(item.FileID, "file_") && !strings.HasPrefix(item.FileID, "file-")) {
				p.Skipped++
				continue
			}
			if !validLibraryID(item.ID) || (item.FileID != "" && !validLibraryID(item.FileID)) || (item.DirectoryID != "" && !validLibraryID(item.DirectoryID)) || len(item.Name) > 1024 {
				return p, errors.New("invalid library file identity; nothing was deleted")
			}
			if !strings.HasPrefix(item.ID, "libfile_") {
				p.Skipped++
				continue
			}
			if seenFiles[item.ID] {
				continue
			}
			seenFiles[item.ID] = true
			inventoryBytes += len(item.ID) + len(item.FileID) + len(item.DirectoryID) + len(item.Name) + 128
			if inventoryBytes > libraryMaxInventoryBytes {
				return p, errors.New("library inventory size limit exceeded; nothing was deleted")
			}
			files = append(files, libraryDeleteFile{LibraryFileID: item.ID, FileID: item.FileID, ParentDirectoryID: item.DirectoryID, Name: item.Name})
		}
		p.Total = len(files)
		emit()
		if wire.Cursor == nil || *wire.Cursor == "" {
			break
		}
		if len(*wire.Cursor) > 8192 || seenCursors[*wire.Cursor] {
			return p, errors.New("invalid library pagination cursor; nothing was deleted")
		}
		seenCursors[*wire.Cursor] = true
		cursor = wire.Cursor
	}
	p.Stage = "deleting"
	emit()
	for start := 0; start < len(files); start += libraryDeleteBatchSize {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		batch := files[start:min(start+libraryDeleteBatchSize, len(files))]
		for attempt := 0; len(batch) > 0; attempt++ {
			if attempt > 0 {
				timer := time.NewTimer(time.Duration(attempt) * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return p, ctx.Err()
				case <-timer.C:
				}
				p.Retried += len(batch)
			}
			results, err := deleteLibraryBatch(ctx, request, batch)
			if err != nil {
				return p, err
			}
			var retry []libraryDeleteFile
			for _, file := range batch {
				reason := results[file.LibraryFileID]
				if reason == "" {
					p.Deleted++
					continue
				}
				if attempt < 2 && (reason == "upstream_rejected" || reason == "conflict_or_in_progress" || reason == "rate_limited") {
					retry = append(retry, file)
					continue
				}
				p.Failed++
				if p.FailureReasons == nil {
					p.FailureReasons = make(map[string]int)
				}
				p.FailureReasons[reason]++
			}
			emit()
			batch = retry
		}
	}
	p.Stage = "verifying"
	emit()
	after, err := readLibraryUsage(ctx, request)
	if err != nil {
		return p, err
	}
	p.After = after
	emit()
	if p.Failed > 0 {
		p.Stage = "deleting"
		return p, fmt.Errorf("%d library files could not be deleted", p.Failed)
	}
	return p, nil
}

// Only explicit per-file failures can be retried. An uncertain HTTP outcome,
// missing result, or malformed response never replays a deletion batch.
func deleteLibraryBatch(ctx context.Context, request LibraryRequest, batch []libraryDeleteFile) (map[string]string, error) {
	body, err := request(ctx, http.MethodPost, "/backend-api/files/library/files/delete-batch", map[string]any{"files": batch})
	if err != nil {
		return nil, err
	}
	var wire struct {
		Files *[]json.RawMessage `json:"files"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Files == nil {
		return nil, errors.New("library deletion result is unconfirmed")
	}
	pending := make(map[string]bool, len(batch))
	for _, file := range batch {
		pending[file.LibraryFileID] = true
	}
	results := make(map[string]string, len(batch))
	for _, raw := range *wire.Files {
		var result struct {
			ID      string `json:"library_file_id"`
			Success *bool  `json:"success"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &result) != nil || json.Unmarshal(raw, &fields) != nil || !pending[result.ID] || result.Success == nil {
			return nil, errors.New("invalid library deletion result")
		}
		delete(pending, result.ID)
		if *result.Success {
			results[result.ID] = ""
		} else {
			results[result.ID] = classifyLibraryDeletionFailure(fields)
		}
	}
	if len(pending) != 0 {
		return nil, errors.New("library deletion result is incomplete")
	}
	return results, nil
}

func classifyLibraryDeletionFailure(fields map[string]json.RawMessage) string {
	var status int
	_ = json.Unmarshal(fields["status_code"], &status)
	switch {
	case status == 401:
		return "authentication_failed"
	case status == 403:
		return "permission_denied"
	case status == 404:
		return "not_found"
	case status == 409:
		return "conflict_or_in_progress"
	case status == 429:
		return "rate_limited"
	case status == 451:
		return "access_restricted"
	case status >= 500 && status <= 599:
		return "upstream_rejected"
	case status >= 400 && status <= 499:
		return "invalid_request"
	}
	var values []string
	for _, key := range []string{"error_code", "code", "reason", "error", "message", "status"} {
		if raw, ok := fields[key]; ok {
			var value string
			if json.Unmarshal(raw, &value) == nil {
				values = append(values, strings.ToLower(value))
			}
		}
	}
	value := strings.Join(values, " ")
	switch {
	case strings.Contains(value, "permission"), strings.Contains(value, "forbidden"), strings.Contains(value, "access"):
		return "permission_denied"
	case strings.Contains(value, "not_found"), strings.Contains(value, "not found"), strings.Contains(value, "missing"):
		return "not_found"
	case strings.Contains(value, "conflict"), strings.Contains(value, "processing"), strings.Contains(value, "busy"):
		return "conflict_or_in_progress"
	case strings.Contains(value, "rate"), strings.Contains(value, "limit"):
		return "rate_limited"
	case strings.Contains(value, "invalid"), strings.Contains(value, "argument"):
		return "invalid_request"
	default:
		return "upstream_rejected"
	}
}
