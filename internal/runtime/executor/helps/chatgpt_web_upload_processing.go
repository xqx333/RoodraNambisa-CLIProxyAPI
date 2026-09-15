package helps

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	chatgptweb "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
)

const maxUploadProcessingBytes = 4 << 20

type UploadProcessingError struct{ StorageRejected bool }

func (e *UploadProcessingError) Error() string { return "upload processing failed" }

// ConsumeChatGPTWebUploadProcessing accepts the website's line-delimited JSON
// and SSE framing. HTTP 200 and file_ready alone do not prove completion.
func ConsumeChatGPTWebUploadProcessing(ctx context.Context, reader io.Reader, fileID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if reader == nil || strings.TrimSpace(fileID) == "" {
		return errors.New("invalid upload processing input")
	}
	limited := &io.LimitedReader{R: reader, N: maxUploadProcessingBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var data []string
	var eventName string
	consume := func(payload string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if strings.TrimSpace(payload) == "[DONE]" {
			return false, nil
		}
		var event struct {
			FileID string `json:"file_id"`
			Event  string `json:"event"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return false, errors.New("invalid upload processing event")
		}
		if event.Event == "" {
			event.Event = eventName
		}
		if event.Event == "" {
			return false, nil
		}
		if event.FileID != fileID {
			return false, errors.New("upload processing file identity mismatch")
		}
		switch event.Event {
		case "file.processing.completed":
			return true, nil
		case "file.processing.error", "file.processing.failed", "file.processing.cancelled", "file.processing.canceled":
			return false, &UploadProcessingError{StorageRejected: chatgptweb.LibraryStorageRejection([]byte(payload))}
		default:
			return false, nil
		}
	}
	flush := func() (bool, error) {
		if len(data) == 0 {
			return false, nil
		}
		payload := strings.Join(data, "\n")
		data = nil
		complete, err := consume(payload)
		eventName = ""
		return complete, err
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if limited.N <= 0 {
			return errors.New("upload processing response exceeds limit")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if complete, err := flush(); complete || err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "id:") || strings.HasPrefix(line, "retry:") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
		if len(data) > 0 {
			return errors.New("mixed upload processing framing")
		}
		if complete, err := consume(line); complete || err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if limited.N <= 0 {
		return errors.New("upload processing response exceeds limit")
	}
	if complete, err := flush(); complete || err != nil {
		return err
	}
	return errors.New("upload processing ended without completion")
}
