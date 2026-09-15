package auth

import (
	"context"
	"errors"
	"sort"
	"strings"
)

var ErrAuthMaintenanceBusy = errors.New("credential is already in maintenance")

type authMaintenanceState struct{ active bool }
type authMaintenanceContextKey struct{}

type AuthMaintenanceTarget struct {
	ID         string
	Name       string
	InstanceID string
}

// SnapshotMaintenanceTargets retains no credential secrets for queued work.
// A nil ID list selects all runtime credentials for the provider.
func (m *Manager) SnapshotMaintenanceTargets(provider string, ids []string) []AuthMaintenanceTarget {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ids == nil {
		ids = make([]string, 0, len(m.auths))
		for id, a := range m.auths {
			if a != nil && strings.EqualFold(a.Provider, provider) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
	}
	seen := map[string]bool{}
	var result []AuthMaintenanceTarget
	for _, id := range ids {
		a := m.auths[id]
		if a == nil || seen[id] || !strings.EqualFold(a.Provider, provider) {
			continue
		}
		for _, member := range m.maintenanceGroupLocked(a) {
			seen[member.ID] = true
		}
		name := a.FileName
		if name == "" {
			name = id
		}
		result = append(result, AuthMaintenanceTarget{ID: id, Name: name, InstanceID: a.instanceID})
	}
	return result
}

func (m *Manager) maintenanceGroupLocked(current *Auth) []*Auth {
	group := []*Auth{current}
	seen := map[string]bool{current.ID: true}
	for _, key := range m.chatGPTWebIdentityKeysByID[current.ID] {
		for id := range m.chatGPTWebIdentityIDs[key] {
			if seen[id] {
				continue
			}
			seen[id] = true
			if candidate := m.auths[id]; candidate != nil && ChatGPTWebCredentialIdentityConflict(current, candidate) {
				group = append(group, candidate)
			}
		}
	}
	return group
}

func (m *Manager) authSelectionBlockedLocked(id string) bool {
	return m.sessionCleanupPendingLocked(id) || m.maintenanceAuths[id] != nil
}

// An already-admitted request may finish nested work such as a 401 refresh.
// Maintenance must block new work, not turn an existing request into a failure.
func (m *Manager) authExecutionBlockedLocked(ctx context.Context, auth *Auth) bool {
	if m.sessionCleanupPendingLocked(auth.ID) {
		return true
	}
	if m.maintenanceAuths[auth.ID] == nil {
		return false
	}
	return ctx == nil || ctx.Err() != nil || auth.instanceState == nil || ctx.Value(runtimeAuthInstanceContextKey{}) != auth.instanceState
}

// AuthMaintenanceActive exposes only the transient scheduling gate, never a
// persisted disabled flag. Existing execution results must still be recorded.
func (m *Manager) AuthMaintenanceActive(id string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maintenanceAuths[id] != nil
}

// RunAuthMaintenance blocks new selections atomically, drains existing leases,
// then runs one operation using the same runtime instance and proxy binding.
// Removal or replacement cancels the operation. Completion never re-enables a
// credential that an operator disabled while maintenance was running.
func (m *Manager) RunAuthMaintenance(ctx context.Context, id string, run func(context.Context, *Auth, ProviderExecutor) error) error {
	if m == nil || run == nil {
		return errors.New("maintenance is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	current := m.auths[id]
	if current == nil || current.RuntimeInstanceRetired() || m.sessionCleanupPendingLocked(id) {
		m.mu.Unlock()
		return runtimeAuthInstanceRetiredError()
	}
	group := m.maintenanceGroupLocked(current)
	for i, member := range group {
		group[i] = member.Clone()
	}
	for _, member := range group {
		if m.maintenanceAuths[member.ID] != nil || m.sessionCleanupPendingLocked(member.ID) {
			m.mu.Unlock()
			return ErrAuthMaintenanceBusy
		}
	}
	if m.maintenanceAuths == nil {
		m.maintenanceAuths = make(map[string]*authMaintenanceState)
	}
	reservation := &authMaintenanceState{active: true}
	for _, member := range group {
		m.maintenanceAuths[member.ID] = reservation
		if state := member.instanceState; state != nil {
			state.mu.Lock()
			state.maintenance = true
			state.mu.Unlock()
		}
		if m.scheduler != nil {
			m.scheduler.blockAuth(member.ID)
		}
	}
	auth := current.Clone()
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		for _, member := range group {
			if state := member.instanceState; state != nil {
				state.mu.Lock()
				state.maintenance = false
				state.mu.Unlock()
			}
			if m.maintenanceAuths[member.ID] != reservation {
				continue
			}
			delete(m.maintenanceAuths, member.ID)
			if m.scheduler != nil && !m.sessionCleanupPendingLocked(member.ID) {
				var latest *Auth
				if a := m.auths[member.ID]; a != nil {
					latest = a.Clone()
				}
				m.scheduler.unblockAuth(member.ID, latest)
			}
		}
		m.mu.Unlock()
		for _, member := range group {
			m.queueRefreshReschedule(member.ID)
		}
	}()
	for _, member := range group {
		if state := member.instanceState; state != nil {
			state.mu.Lock()
			idle := state.executionsIdle
			state.mu.Unlock()
			if idle != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-idle:
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	current = m.auths[id]
	if current == nil || current.instanceState != auth.instanceState || current.instanceID != auth.instanceID || current.RuntimeInstanceRetired() || m.sessionCleanupPendingLocked(id) {
		m.mu.RUnlock()
		return runtimeAuthInstanceRetiredError()
	}
	auth = current.Clone()
	executor := m.executors[executorKeyFromAuth(auth)]
	if executor == nil {
		m.mu.RUnlock()
		return errors.New("maintenance executor is unavailable")
	}
	leaseCtx, release, active := auth.BeginRuntimeExecution(context.WithValue(ctx, authMaintenanceContextKey{}, auth.instanceState))
	m.mu.RUnlock()
	if !active {
		return runtimeAuthInstanceRetiredError()
	}
	defer release()
	resolved, err := m.ResolveProxyAuth(leaseCtx, auth)
	if err != nil {
		return err
	}
	return run(leaseCtx, resolved, executor)
}
