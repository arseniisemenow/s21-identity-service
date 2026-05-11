package s21

import (
	"context"
	"sync"
)

// Mock is a test-only s21 Client. Configure with SetUser / SetAdminPassword.
type Mock struct {
	mu             sync.Mutex
	Profiles       map[string]Profile // login → Profile
	AuthPasswords  map[string]string  // login → password (Authenticate)
	AdminPasswords map[string]string  // adminLogin → password (LookupByLogin)
	Failures       map[string]error   // one-shot per-method failure injection
}

// NewMock returns an empty Mock.
func NewMock() *Mock {
	return &Mock{
		Profiles:       map[string]Profile{},
		AuthPasswords:  map[string]string{},
		AdminPasswords: map[string]string{},
		Failures:       map[string]error{},
	}
}

// SetUser configures the mock so login + password authenticates and
// resolves to profile.
func (m *Mock) SetUser(login, password string, profile Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if profile.Login == "" {
		profile.Login = login
	}
	m.Profiles[login] = profile
	m.AuthPasswords[login] = password
}

// SetAdminPassword sets the password expected on LookupByLogin for that admin.
func (m *Mock) SetAdminPassword(login, password string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AdminPasswords[login] = password
}

// FailNext injects a one-shot failure for the next call to `method`.
func (m *Mock) FailNext(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Failures[method] = err
}

func (m *Mock) tryFail(method string) error {
	if err, ok := m.Failures[method]; ok {
		delete(m.Failures, method)
		return err
	}
	return nil
}

// Authenticate validates credentials.
func (m *Mock) Authenticate(_ context.Context, login, password string) (Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.tryFail("Authenticate"); err != nil {
		return Profile{}, err
	}
	if want, ok := m.AuthPasswords[login]; !ok || want != password {
		return Profile{}, ErrInvalidCredentials
	}
	return m.Profiles[login], nil
}

// LookupByLogin resolves a profile using admin creds.
func (m *Mock) LookupByLogin(_ context.Context, adminLogin, adminPassword, targetLogin string) (Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.tryFail("LookupByLogin"); err != nil {
		return Profile{}, err
	}
	if want, ok := m.AdminPasswords[adminLogin]; !ok || want != adminPassword {
		return Profile{}, ErrInvalidCredentials
	}
	p, ok := m.Profiles[targetLogin]
	if !ok {
		return Profile{}, ErrNotFound
	}
	return p, nil
}
