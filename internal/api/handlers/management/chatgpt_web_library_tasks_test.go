package management

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type libraryTaskTestExecutor struct {
	*accountInfoControllerTestExecutor
	cleanup func(context.Context, *coreauth.Auth, func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error)
}

func (e *libraryTaskTestExecutor) CleanupLibrary(ctx context.Context, a *coreauth.Auth, progress func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error) {
	return e.cleanup(ctx, a, progress)
}

func TestLibraryCleanupTaskConcurrencyCancelAndNoAccountCooling(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	entered := make(chan struct{}, 3)
	var calls atomic.Int32
	executor := &libraryTaskTestExecutor{accountInfoControllerTestExecutor: &accountInfoControllerTestExecutor{}}
	executor.cleanup = func(ctx context.Context, _ *coreauth.Auth, observe func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error) {
		calls.Add(1)
		entered <- struct{}{}
		p := chatgptwebauth.LibraryCleanupProgress{Stage: "deleting", Total: 5, Deleted: 2}
		observe(p)
		<-ctx.Done()
		return p, ctx.Err()
	}
	manager.RegisterExecutor(executor)
	var targets []libraryCleanupTarget
	for _, id := range []string{"one", "two", "three"} {
		a, err := manager.Register(t.Context(), &coreauth.Auth{ID: id, FileName: id, Provider: chatgptwebauth.Provider, Status: coreauth.StatusActive})
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, libraryCleanupTarget{Name: id, AuthID: a.ID, InstanceID: a.RuntimeInstanceID()})
	}
	tasks := &libraryCleanupTaskManager{}
	task, err := tasks.Start(targets, 2, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := tasks.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("worker limit exceeded")
	}
	if _, err := tasks.Start(targets, 2, manager); !errors.Is(err, coreauth.ErrAuthMaintenanceBusy) {
		t.Fatalf("overlap=%v", err)
	}
	snapshot := tasks.Snapshot()
	snapshot.Results[0].Name = "changed"
	if tasks.Snapshot().Results[0].Name == "changed" {
		t.Fatal("snapshot aliases mutable state")
	}
	if _, ok := tasks.Cancel("wrong-id"); ok {
		t.Fatal("canceled different task")
	}
	if _, ok := tasks.Cancel(task.ID); !ok {
		t.Fatal("task missing")
	}
	select {
	case <-tasks.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("cancel failed")
	}
	final := tasks.Snapshot()
	if final.State != "canceled" || calls.Load() != 2 {
		t.Fatalf("task=%+v calls=%d", final, calls.Load())
	}
	for _, target := range targets {
		a, _ := manager.GetByID(target.AuthID)
		if manager.AuthMaintenanceActive(a.ID) || a.Disabled || a.LastError != nil || a.Unavailable {
			t.Fatalf("account state polluted: %+v", a)
		}
	}
}

func TestLibraryCleanupTaskWaitsForExistingRequest(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	called := make(chan struct{}, 1)
	executor := &libraryTaskTestExecutor{accountInfoControllerTestExecutor: &accountInfoControllerTestExecutor{}, cleanup: func(context.Context, *coreauth.Auth, func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error) {
		called <- struct{}{}
		return chatgptwebauth.LibraryCleanupProgress{Deleted: 1, Total: 1}, nil
	}}
	manager.RegisterExecutor(executor)
	a, err := manager.Register(t.Context(), &coreauth.Auth{ID: "one", Provider: chatgptwebauth.Provider, Status: coreauth.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, active := a.BeginRuntimeExecution(t.Context())
	if !active {
		t.Fatal("request rejected")
	}
	defer release()
	tasks := &libraryCleanupTaskManager{}
	_, err = tasks.Start([]libraryCleanupTarget{{Name: "one", AuthID: a.ID, InstanceID: a.RuntimeInstanceID()}}, 1, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tasks.Shutdown(t.Context()) }()
	deadline := time.After(3 * time.Second)
	for !manager.AuthMaintenanceActive(a.ID) {
		select {
		case <-deadline:
			t.Fatal("not reserved")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-called:
		t.Fatal("deleted during active request")
	default:
	}
	if ctx.Err() != nil {
		t.Fatal("request canceled")
	}
	release()
	select {
	case <-tasks.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("did not finish")
	}
	if tasks.Snapshot().State != "completed" {
		t.Fatalf("%+v", tasks.Snapshot())
	}
}

func TestLibraryCleanupHandlerRejectsMissingConfirmationAndInvalidConcurrency(t *testing.T) {
	h := &Handler{authManager: coreauth.NewManager(nil, nil, nil)}
	for _, body := range []string{
		`{"all":true,"concurrency":4}`,
		`{"all":true,"confirm_delete_all_files":true,"concurrency":0}`,
		`{"all":true,"confirm_delete_all_files":true,"concurrency":33}`,
		`{"all":true,"confirm_delete_all_files":true,"concurrency":1.5}`,
		`{"all":true,"names":["x"],"confirm_delete_all_files":true,"concurrency":4}`,
		`{"names":["missing"],"confirm_delete_all_files":true,"concurrency":4}`,
		`{"all":true,"confirm_delete_all_files":true,"concurrency":4,"url":"https://untrusted"}`,
	} {
		c, r := newChatGPTWebAccountInfoRequest(http.MethodPost, body)
		h.StartChatGPTWebLibraryCleanup(c)
		if r.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", body, r.Code)
		}
	}
}
