package config

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mockSettingsStore implements SettingsStore in-memory for testing.
type mockSettingsStore struct {
	mu       sync.Mutex
	saved    *AdminSettingsPayload
	saveErr  error
	loadErr  error
	saveHits int
	loadHits int
}

func (m *mockSettingsStore) SaveAdminSettings(ctx context.Context, settings *AdminSettingsPayload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveHits++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = settings
	return nil
}

func (m *mockSettingsStore) GetAdminSettings(ctx context.Context) (*AdminSettingsPayload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadHits++
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.saved == nil {
		return nil, errors.New("record not found")
	}
	return m.saved, nil
}

func testBaselineConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 18080,
		},
		SAML: SAMLConfig{
			EntityID:         "https://192.168.0.178:18080",
			SSOURL:           "https://192.168.0.178:18080/login",
			SLOURL:           "https://192.168.0.178:18080/logout",
			MetadataURL:      "https://192.168.0.178:18080/metadata",
			AllowedAudiences: []string{"https://192.168.0.178:18080", "https://192.168.0.119"},
			EnabledIdPs:      []string{"simulator"},
			ActiveIdP:        "simulator",
		},
		ITA: ITAConfig{
			APIURL:      "https://192.168.0.119/api/current",
			APIUsername: "apc",
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			Path:   "./data/test.db",
		},
	}
}

func TestManager_InitializationAndAuthoritativeOverlay(t *testing.T) {
	baseline := testBaselineConfig()
	store := &mockSettingsStore{
		saved: &AdminSettingsPayload{
			EntityID:  "https://configured-in-sqlite.local:18080",
			SSOURL:    "https://configured-in-sqlite.local:18080/login",
			ActiveIdP: "simulator",
		},
	}

	mgr, err := NewManager(baseline, store)
	if err != nil {
		t.Fatalf("failed to initialize manager: %v", err)
	}

	cfg := mgr.GetConfig()
	if cfg.SAML.EntityID != "https://configured-in-sqlite.local:18080" {
		t.Fatalf("expected SQLite authoritative overlay 'https://configured-in-sqlite.local:18080', got %s", cfg.SAML.EntityID)
	}
	if store.loadHits != 1 {
		t.Fatalf("expected 1 load from store on init, got %d", store.loadHits)
	}
}

func TestManager_SnapshotIsolation(t *testing.T) {
	baseline := testBaselineConfig()
	mgr, err := NewManager(baseline, nil)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	snapshot1 := mgr.GetConfig()
	snapshot1.SAML.EntityID = "https://mutated-externally.local"
	snapshot1.SAML.AllowedAudiences = append(snapshot1.SAML.AllowedAudiences, "https://hacker.com")

	snapshot2 := mgr.GetConfig()
	if snapshot2.SAML.EntityID == "https://mutated-externally.local" {
		t.Fatal("mutating snapshot leaked into active configuration (snapshot is not isolated)")
	}
	if len(snapshot2.SAML.AllowedAudiences) != len(baseline.SAML.AllowedAudiences) {
		t.Fatal("mutating snapshot slice leaked into active configuration slice")
	}
}

func TestManager_UpdateAdminSettingsAtomic(t *testing.T) {
	baseline := testBaselineConfig()
	store := &mockSettingsStore{}

	mgr, err := NewManager(baseline, store)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	var listenerNotified sync.WaitGroup
	listenerNotified.Add(1)

	mgr.RegisterListener(func(oldCfg, newCfg *Config) {
		if newCfg.SAML.EntityID == "https://192.168.0.222:18080" {
			listenerNotified.Done()
		}
	})

	payload := &AdminSettingsPayload{
		EntityID:  "https://192.168.0.222:18080",
		SSOURL:    "https://192.168.0.222:18080/login",
		ActiveIdP: "simulator",
	}

	updated, err := mgr.UpdateAdminSettings(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error updating admin settings: %v", err)
	}

	if updated.SAML.EntityID != "https://192.168.0.222:18080" {
		t.Fatalf("expected updated entity_id, got %s", updated.SAML.EntityID)
	}
	if store.saveHits != 1 {
		t.Fatalf("expected 1 save hit to SQLite, got %d", store.saveHits)
	}
	if store.saved.EntityID != "https://192.168.0.222:18080" {
		t.Fatalf("expected persisted entity_id in store, got %s", store.saved.EntityID)
	}

	// Verify listener was called
	listenerNotified.Wait()
}

func TestManager_UpdateRollbackOnValidationError(t *testing.T) {
	baseline := testBaselineConfig()
	store := &mockSettingsStore{}

	mgr, err := NewManager(baseline, store)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	initialEntityID := mgr.GetConfig().SAML.EntityID

	// Attempt update with invalid configuration (AutoTLS enabled without domains fails validation)
	invalidPayload := &AdminSettingsPayload{
		TLSSubmitted:   true,
		TLSEnabled:     true,
		AutoTLSEnabled: true,
		AutoTLSDomains: []string{}, // triggers: tls.auto_tls.domains is required when automatic Let's Encrypt TLS is enabled
	}

	_, err = mgr.UpdateAdminSettings(context.Background(), invalidPayload)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	// Active configuration must remain pristine
	current := mgr.GetConfig()
	if current.SAML.EntityID != initialEntityID {
		t.Fatalf("active configuration was corrupted on validation error; expected %s, got %s", initialEntityID, current.SAML.EntityID)
	}
	if store.saveHits != 0 {
		t.Fatalf("invalid configuration was erroneously persisted to store (saveHits = %d)", store.saveHits)
	}
}

func TestManager_UpdateDynamicEndpoints(t *testing.T) {
	baseline := testBaselineConfig()
	store := &mockSettingsStore{}

	mgr, err := NewManager(baseline, store)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Simulate automatic host IP shift from 192.168.0.178 to 192.168.0.205
	newIP := "192.168.0.205"
	newBase := fmt.Sprintf("https://%s:18080", newIP)

	updated, err := mgr.UpdateDynamicEndpoints(
		context.Background(),
		newBase,
		newBase+"/login",
		newBase+"/logout",
		newBase+"/metadata",
		[]string{newBase, "https://192.168.0.119"},
		[]string{newBase},
	)
	if err != nil {
		t.Fatalf("failed to update dynamic endpoints: %v", err)
	}

	if updated.SAML.EntityID != newBase {
		t.Fatalf("expected EntityID %s, got %s", newBase, updated.SAML.EntityID)
	}
	if updated.SAML.SSOURL != newBase+"/login" {
		t.Fatalf("expected SSOURL %s/login, got %s", newBase, updated.SAML.SSOURL)
	}
	// Verify ITA API URL was completely untouched
	if updated.ITA.APIURL != baseline.ITA.APIURL {
		t.Fatalf("ITA API URL was modified unexpectedly: %s", updated.ITA.APIURL)
	}
	// Verify SQLite persistence received the update
	if store.saveHits != 1 {
		t.Fatalf("expected 1 save hit to SQLite, got %d", store.saveHits)
	}
}

func TestManager_ConcurrentReadWriteSafety(t *testing.T) {
	baseline := testBaselineConfig()
	store := &mockSettingsStore{}

	mgr, err := NewManager(baseline, store)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Readers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cfg := mgr.GetConfig()
				if cfg.Server.Port <= 0 {
					t.Errorf("corrupted read: invalid port %d", cfg.Server.Port)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Writers
	for i := 0; i < goroutines; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				newIP := fmt.Sprintf("192.168.%d.%d", workerID, j+1)
				newBase := fmt.Sprintf("https://%s:18080", newIP)

				_, err := mgr.UpdateDynamicEndpoints(
					context.Background(),
					newBase,
					newBase+"/login",
					newBase+"/logout",
					newBase+"/metadata",
					[]string{newBase},
					nil,
				)
				if err != nil {
					t.Errorf("concurrent update failed: %v", err)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
}
