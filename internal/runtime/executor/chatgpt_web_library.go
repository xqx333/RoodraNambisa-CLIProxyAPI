package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// CleanupLibrary is invoked by a credential maintenance task.
// Its errors do not pass through model usage accounting or credential cooling.
func (e *ChatGPTWebExecutor) CleanupLibrary(ctx context.Context, auth *coreauth.Auth, observe func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error) {
	request, closeClient, err := e.libraryRequestClient(ctx, auth)
	if err != nil {
		return chatgptwebauth.LibraryCleanupProgress{}, err
	}
	defer closeClient()
	return chatgptwebauth.CleanupLibrary(ctx, request, observe)
}

func (e *ChatGPTWebExecutor) CleanupLibraryWhenFull(ctx context.Context, auth *coreauth.Auth, requiredBytes int64, observe func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error) {
	request, closeClient, err := e.libraryRequestClient(ctx, auth)
	if err != nil {
		return chatgptwebauth.LibraryCleanupProgress{}, err
	}
	defer closeClient()
	return chatgptwebauth.CleanupLibraryWhenFull(ctx, request, requiredBytes, observe)
}

func chatGPTWebLibraryUploadSize(err error, size int) error {
	if storage, ok := err.(chatGPTWebHTTPError); ok {
		storage.libraryUploadBytes = int64(size)
		return storage
	}
	return err
}

func (e *ChatGPTWebExecutor) scheduleChatGPTWebLibraryCleanup(ctx context.Context, auth *coreauth.Auth, prepared *chatGPTWebPreparedRequest, err error) {
	if e.manager == nil || prepared == nil || prepared.request.Image == nil || !prepared.imageConfigSnapshot.AutoCleanupLibraryOnFull || ctx.Err() != nil {
		return
	}
	var storage chatGPTWebHTTPError
	if errors.As(err, &storage) && storage.libraryStorageRejected {
		e.manager.LibraryCleanup().ScheduleAutomatic(auth, storage.libraryUploadBytes, e.manager)
	}
}

func (e *ChatGPTWebExecutor) libraryRequestClient(ctx context.Context, auth *coreauth.Auth) (chatgptwebauth.LibraryRequest, func(), error) {
	client, credential, err := e.newRuntimeClientForAcquisition(auth, false, ctx)
	if err != nil {
		return nil, nil, err
	}
	request := func(ctx context.Context, method, path string, body any) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		headers := e.chatGPTWebHeaders(credential, path, map[string]string{"accept": "application/json", "content-type": "application/json"})
		response, err := client.DoJSONStream(ctx, method, e.chatGPTWebBaseURL()+path, headers, body)
		if err != nil {
			return nil, chatGPTWebTransportDiagnosticError(err, path)
		}
		data, err := readChatGPTWebResponseBody(response, 4<<20)
		if err != nil {
			return nil, chatGPTWebTransportDiagnosticError(err, path)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, newChatGPTWebStatusError(response.StatusCode, path, data, response.Header)
		}
		if !json.Valid(data) {
			return nil, chatGPTWebLocalProtocolError(http.StatusBadGateway, "invalid library response")
		}
		return data, nil
	}
	return request, func() { client.CloseActiveAcquisitionConnections(); client.CloseIdleConnections() }, nil
}
