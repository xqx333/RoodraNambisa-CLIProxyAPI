package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type maintenanceTestExecutor struct{ ProviderExecutor }

func (maintenanceTestExecutor) Identifier() string { return "maintenance-test" }

func maintenanceFixture(t *testing.T) (*Manager, *Auth, ProviderExecutor) {
	t.Helper()
	m := NewManager(nil, nil, nil)
	executor := maintenanceTestExecutor{}
	m.RegisterExecutor(executor)
	a, err := m.Register(t.Context(), &Auth{ID: t.Name(), Provider: executor.Identifier(), Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	return m, a, executor
}

func awaitMaintenance(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for !m.AuthMaintenanceActive(id) {
		select {
		case <-deadline:
			t.Fatal("maintenance was not reserved")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestAuthMaintenanceDrainsWithoutCancelingAndRestoresLatestState(t *testing.T) {
	m, a, executor := maintenanceFixture(t)
	requestCtx, release, ok := m.beginCurrentAuthExecution(t.Context(), a, executor)
	if !ok {
		t.Fatal("initial lease rejected")
	}
	defer release()
	started, unblock, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer close(unblock)
	go func() {
		done <- m.RunAuthMaintenance(t.Context(), a.ID, func(ctx context.Context, _ *Auth, _ ProviderExecutor) error {
			close(started)
			select {
			case <-unblock:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	awaitMaintenance(t, m, a.ID)
	if requestCtx.Err() != nil {
		t.Fatal("maintenance canceled an in-flight request")
	}
	if _, finish, active := m.beginCurrentAuthExecution(requestCtx, a, executor); !active {
		t.Fatal("nested manager work for an in-flight request was rejected")
	} else {
		finish()
	}
	select {
	case <-started:
		t.Fatal("cleanup began before drain")
	default:
	}
	if _, finish, active := m.beginCurrentAuthExecution(t.Context(), a, executor); active {
		finish()
		t.Fatal("new manager lease admitted")
	}
	if _, finish, active := a.BeginRuntimeExecution(t.Context()); active {
		finish()
		t.Fatal("background lease admitted")
	}
	if _, finish, active := a.BeginRuntimeExecution(requestCtx); !active {
		t.Fatal("nested in-flight work rejected")
	} else {
		finish()
	}
	if err := m.RunAuthMaintenance(t.Context(), a.ID, func(context.Context, *Auth, ProviderExecutor) error { return nil }); !errors.Is(err, ErrAuthMaintenanceBusy) {
		t.Fatalf("overlap = %v", err)
	}
	release()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not start after drain")
	}
	// An operator edit is authoritative when the transient gate is released.
	m.mu.Lock()
	m.auths[a.ID].Disabled = true
	m.auths[a.ID].Status = StatusDisabled
	m.mu.Unlock()
	unblock <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current, _ := m.GetByID(a.ID)
	if m.AuthMaintenanceActive(a.ID) || !current.Disabled || current.Status != StatusDisabled {
		t.Fatal("maintenance restored stale administrative state")
	}
}

func TestAuthMaintenanceCancelDuringDrainReleasesGate(t *testing.T) {
	m, a, executor := maintenanceFixture(t)
	requestCtx, release, _ := m.beginCurrentAuthExecution(t.Context(), a, executor)
	defer release()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- m.RunAuthMaintenance(ctx, a.ID, func(context.Context, *Auth, ProviderExecutor) error { t.Error("canceled cleanup ran"); return nil })
	}()
	awaitMaintenance(t, m, a.ID)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if m.AuthMaintenanceActive(a.ID) || requestCtx.Err() != nil {
		t.Fatal("cancel leaked gate or canceled user request")
	}
	if _, finish, active := a.BeginRuntimeExecution(t.Context()); !active {
		t.Fatal("gate remained closed")
	} else {
		finish()
	}
}

func TestAuthMaintenanceRemovalCancelsOperation(t *testing.T) {
	m, a, _ := maintenanceFixture(t)
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- m.RunAuthMaintenance(t.Context(), a.ID, func(ctx context.Context, _ *Auth, _ ProviderExecutor) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	<-started
	m.mu.Lock()
	current := m.auths[a.ID]
	delete(m.auths, a.ID)
	m.mu.Unlock()
	current.retireInstance()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retirement did not cancel cleanup")
	}
	if m.AuthMaintenanceActive(a.ID) {
		t.Fatal("retired gate leaked")
	}
}
