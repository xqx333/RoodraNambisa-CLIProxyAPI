package auth

import (
	"context"
	"testing"
	"time"

	chatgptweb "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
)

type automaticLibraryTestExecutor struct {
	ProviderExecutor
	called chan int64
}

func (e *automaticLibraryTestExecutor) Identifier() string { return "chatgpt-web" }
func (e *automaticLibraryTestExecutor) CleanupLibrary(context.Context, *Auth, func(chatgptweb.LibraryCleanupProgress)) (chatgptweb.LibraryCleanupProgress, error) {
	return chatgptweb.LibraryCleanupProgress{}, nil
}
func (e *automaticLibraryTestExecutor) CleanupLibraryWhenFull(_ context.Context, _ *Auth, bytes int64, _ func(chatgptweb.LibraryCleanupProgress)) (chatgptweb.LibraryCleanupProgress, error) {
	e.called <- bytes
	return chatgptweb.LibraryCleanupProgress{}, nil
}

func TestAutomaticLibraryCleanupSharesDrainAndDeduplicates(t *testing.T) {
	m := NewManager(nil, nil, nil)
	e := &automaticLibraryTestExecutor{called: make(chan int64, 1)}
	m.RegisterExecutor(e)
	a, err := m.Register(t.Context(), &Auth{ID: "automatic-library", Provider: "chatgpt-web", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	ctx, release, ok := a.BeginRuntimeExecution(t.Context())
	if !ok {
		t.Fatal("lease failed")
	}
	defer release()
	jobs := m.LibraryCleanup()
	defer func() { _ = jobs.Shutdown(context.Background()) }()
	if !jobs.ScheduleAutomatic(a, 200, m) {
		t.Fatal("not scheduled")
	}
	awaitMaintenance(t, m, a.ID)
	if ctx.Err() != nil {
		t.Fatal("original request canceled")
	}
	select {
	case <-e.called:
		t.Fatal("ran before drain")
	default:
	}
	if jobs.ScheduleAutomatic(a, 200, m) {
		t.Fatal("duplicate automatic cleanup")
	}
	if _, err := jobs.Start([]LibraryCleanupTarget{{AuthID: a.ID}}, 1, m); err == nil {
		t.Fatal("manual cleanup overlapped")
	}
	release()
	select {
	case bytes := <-e.called:
		if bytes != 200 {
			t.Fatal("lost rejected upload size")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not start")
	}
	<-jobs.Done()
	if jobs.Snapshot().Source != "automatic" || jobs.Snapshot().State != "completed" || m.AuthMaintenanceActive(a.ID) {
		t.Fatal("bad final state")
	}
	if jobs.ScheduleAutomatic(a, 200, m) {
		t.Fatal("cooldown ignored")
	}
	current, _ := m.GetByID(a.ID)
	if current.Disabled {
		t.Fatal("persisted disabled flag changed")
	}
}

func TestLibraryCleanupPublicProgressPagination(t *testing.T) {
	m := &LibraryCleanupManager{task: &LibraryCleanupTask{ID: "large-job", State: "running", Results: make([]LibraryCleanupResult, 100)}}
	for i := range m.task.Results {
		m.task.Results[i].Stage = "completed"
		m.task.Results[i].Deleted = i
	}
	page := m.publicSnapshotLocked(2)
	if page.Page != 2 || len(page.Results) != 25 || page.Results[0].Deleted != 25 || page.TotalCredentials != 100 || page.ProcessedCredentials != 100 || page.DeletedFiles != 4950 {
		t.Fatalf("invalid page: %+v", page)
	}
	page.Results[0].Stage = "mutated"
	if m.task.Results[25].Stage != "completed" {
		t.Fatal("page aliases task state")
	}
	if got := m.publicSnapshotLocked(100); got.Page != 4 || len(got.Results) != 25 {
		t.Fatal("out-of-range page did not clamp")
	}
}
