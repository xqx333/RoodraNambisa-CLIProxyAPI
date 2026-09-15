package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	chatgptwebauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/chatgptweb"
)

const LibraryCleanupMaxTargets = 50000

type LibraryCleanupExecutor interface {
	CleanupLibrary(context.Context, *Auth, func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error)
}

type AutomaticLibraryCleanupExecutor interface {
	CleanupLibraryWhenFull(context.Context, *Auth, int64, func(chatgptwebauth.LibraryCleanupProgress)) (chatgptwebauth.LibraryCleanupProgress, error)
}

type LibraryCleanupTarget struct {
	Name          string
	AuthID        string
	InstanceID    string
	requiredBytes *int64
}

type LibraryCleanupResult struct {
	Name string `json:"name"`
	chatgptwebauth.LibraryCleanupProgress
	ErrorCode    string `json:"error_code,omitempty"`
	FailureStage string `json:"failure_stage,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
}

type LibraryCleanupTask struct {
	ID                   string                 `json:"id"`
	State                string                 `json:"state"`
	Source               string                 `json:"source"`
	Concurrency          int                    `json:"concurrency"`
	StartedAt            time.Time              `json:"started_at"`
	FinishedAt           *time.Time             `json:"finished_at,omitempty"`
	Results              []LibraryCleanupResult `json:"results"`
	TotalCredentials     int                    `json:"total_credentials"`
	ProcessedCredentials int                    `json:"processed_credentials"`
	DeletedFiles         int                    `json:"deleted_files"`
	Page                 int                    `json:"page"`
}

type LibraryCleanupManager struct {
	mu        sync.Mutex
	closed    bool
	task      *LibraryCleanupTask
	cancel    context.CancelFunc
	done      chan struct{}
	automatic map[string]time.Time
}

func (m *LibraryCleanupManager) snapshotLocked() *LibraryCleanupTask {
	if m.task == nil {
		return nil
	}
	copy := *m.task
	copy.Results = append([]LibraryCleanupResult(nil), m.task.Results...)
	for i := range copy.Results {
		copy.Results[i].LibraryCleanupProgress = copy.Results[i].LibraryCleanupProgress.Clone()
	}
	return &copy
}

func (m *LibraryCleanupManager) Snapshot() *LibraryCleanupTask {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

// Public counts cover the whole job, while details are paginated.
func (m *LibraryCleanupManager) publicSnapshotLocked(page int) *LibraryCleanupTask {
	if m.task == nil {
		return nil
	}
	result := *m.task
	result.TotalCredentials = len(m.task.Results)
	result.ProcessedCredentials, result.DeletedFiles = 0, 0
	for _, item := range m.task.Results {
		if item.Stage == "completed" || item.Stage == "failed" || item.Stage == "canceled" {
			result.ProcessedCredentials++
		}
		result.DeletedFiles += item.Deleted
	}
	page = max(1, min(page, (result.TotalCredentials+24)/25))
	start := min((page-1)*25, result.TotalCredentials)
	result.Page = page
	result.Results = append([]LibraryCleanupResult(nil), m.task.Results[start:min(start+25, result.TotalCredentials)]...)
	for i := range result.Results {
		result.Results[i].LibraryCleanupProgress = result.Results[i].LibraryCleanupProgress.Clone()
	}
	return &result
}

func (m *LibraryCleanupManager) Start(targets []LibraryCleanupTarget, concurrency int, manager *Manager) (*LibraryCleanupTask, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked(targets, concurrency, manager, "manual")
}

func (m *LibraryCleanupManager) startLocked(targets []LibraryCleanupTarget, concurrency int, manager *Manager, source string) (*LibraryCleanupTask, error) {
	if manager == nil || len(targets) == 0 || len(targets) > LibraryCleanupMaxTargets || concurrency < 1 || concurrency > 32 {
		return nil, errors.New("invalid library cleanup task")
	}
	if m.closed {
		return nil, errors.New("library cleanup is shutting down")
	}
	if m.cancel != nil {
		return nil, ErrAuthMaintenanceBusy
	}
	targets = append([]LibraryCleanupTarget(nil), targets...)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.done = cancel, make(chan struct{})
	m.task = &LibraryCleanupTask{ID: uuid.NewString(), State: "running", Source: source, Concurrency: concurrency, StartedAt: time.Now(), Results: make([]LibraryCleanupResult, len(targets))}
	for i, target := range targets {
		m.task.Results[i] = LibraryCleanupResult{Name: target.Name, LibraryCleanupProgress: chatgptwebauth.LibraryCleanupProgress{Stage: "queued"}}
	}
	go m.run(ctx, targets, concurrency, manager)
	return m.publicSnapshotLocked(1), nil
}

// ScheduleAutomatic never waits on the current execution lease, replays a request,
// or builds an unbounded queue. Manual and automatic jobs share the same gate.
func (m *LibraryCleanupManager) ScheduleAutomatic(auth *Auth, requiredBytes int64, manager *Manager) bool {
	if auth == nil || auth.Provider != "chatgpt-web" || auth.RuntimeInstanceID() == "" || requiredBytes < 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	identity := ChatGPTWebCredentialIdentity(auth)
	if identity == "" {
		identity = auth.ID
	}
	for id, until := range m.automatic {
		if !now.Before(until) {
			delete(m.automatic, id)
		}
	}
	if _, exists := m.automatic[identity]; exists || len(m.automatic) >= 1024 {
		return false
	}
	name := auth.FileName
	if name == "" {
		name = auth.ID
	}
	_, err := m.startLocked([]LibraryCleanupTarget{{Name: name, AuthID: auth.ID, InstanceID: auth.RuntimeInstanceID(), requiredBytes: &requiredBytes}}, 1, manager, "automatic")
	if err != nil {
		return false
	}
	if m.automatic == nil {
		m.automatic = make(map[string]time.Time)
	}
	m.automatic[identity] = now.Add(10 * time.Minute)
	return true
}

func (m *LibraryCleanupManager) run(ctx context.Context, targets []LibraryCleanupTarget, concurrency int, manager *Manager) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		state := "completed"
		for i := range m.task.Results {
			result := &m.task.Results[i]
			if result.Stage == "queued" {
				result.Stage = "canceled"
			}
			if result.Stage == "failed" {
				state = "completed_with_errors"
			}
		}
		if ctx.Err() != nil {
			state = "canceled"
		}
		m.task.State = state
		finished := time.Now()
		m.task.FinishedAt = &finished
		m.cancel()
		m.cancel = nil
		close(m.done)
	}()
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(concurrency, len(targets)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					continue
				}
				target := targets[index]
				update := func(progress chatgptwebauth.LibraryCleanupProgress) {
					m.mu.Lock()
					m.task.Results[index].LibraryCleanupProgress = progress.Clone()
					m.mu.Unlock()
				}
				progress := chatgptwebauth.LibraryCleanupProgress{Stage: "waiting"}
				update(progress)
				err := manager.RunAuthMaintenance(ctx, target.AuthID, func(ctx context.Context, auth *Auth, executor ProviderExecutor) error {
					if auth.RuntimeInstanceID() != target.InstanceID {
						return errors.New("credential changed before cleanup")
					}
					cleaner, ok := executor.(LibraryCleanupExecutor)
					if !ok {
						return errors.New("library cleanup is not supported")
					}
					var errCleanup error
					if target.requiredBytes != nil {
						automatic, ok := executor.(AutomaticLibraryCleanupExecutor)
						if !ok {
							return errors.New("automatic library cleanup is not supported")
						}
						progress, errCleanup = automatic.CleanupLibraryWhenFull(ctx, auth, *target.requiredBytes, update)
					} else {
						progress, errCleanup = cleaner.CleanupLibrary(ctx, auth, update)
					}
					return errCleanup
				})
				failureStage := ""
				lastStage := progress.Stage
				progress.Stage = "completed"
				code, status := "", 0
				if err != nil {
					failureStage = lastStage
					progress.Stage = "failed"
					code, status = LibraryCleanupError(err)
					if errors.Is(err, context.Canceled) || ctx.Err() != nil {
						progress.Stage = "canceled"
					}
				}
				m.mu.Lock()
				m.task.Results[index] = LibraryCleanupResult{Name: target.Name, LibraryCleanupProgress: progress.Clone(), ErrorCode: code, FailureStage: failureStage, HTTPStatus: status}
				m.mu.Unlock()
			}
		}()
	}
	for index := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
}

func LibraryCleanupError(err error) (string, int) {
	if errors.Is(err, context.Canceled) {
		return "request_canceled", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "network_timeout", 0
	}
	if errors.Is(err, ErrAuthMaintenanceBusy) {
		return "maintenance_busy", 0
	}
	var coder interface{ StatusCode() int }
	if errors.As(err, &coder) {
		status := coder.StatusCode()
		category := "request_failed"
		switch {
		case status == 401:
			category = "authentication_failed"
		case status == 403:
			category = "permission_denied"
		case status == 404:
			category = "not_found"
		case status == 429:
			category = "rate_limited"
		case status == 451:
			category = "access_restricted"
		case status >= 500:
			category = "upstream_error"
		case status >= 400:
			category = "request_rejected"
		}
		return category, status
	}
	return "library_cleanup_failed", 0
}

func (m *LibraryCleanupManager) Cancel(id string) (*LibraryCleanupTask, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.task == nil || m.task.ID != id {
		return nil, false
	}
	if m.cancel != nil {
		m.task.State = "canceling"
		m.cancel()
	}
	return m.publicSnapshotLocked(1), true
}

func (m *LibraryCleanupManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	done := m.done
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) LibraryCleanup() *LibraryCleanupManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.libraryCleanup == nil {
		m.libraryCleanup = &LibraryCleanupManager{}
	}
	return m.libraryCleanup
}

func (m *LibraryCleanupManager) PublicSnapshot(page int) *LibraryCleanupTask {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publicSnapshotLocked(page)
}

func (m *LibraryCleanupManager) Done() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.done
}
