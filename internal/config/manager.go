package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrNilConfig indicates an operation was attempted on an uninitialized configuration.
var ErrNilConfig = errors.New("configuration cannot be nil")

// SettingsStore defines the persistence interface required by the ConfigurationManager.
// This interface matches mfa.Storage methods without introducing circular package dependencies.
type SettingsStore interface {
	SaveAdminSettings(ctx context.Context, settings *AdminSettingsPayload) error
	GetAdminSettings(ctx context.Context) (*AdminSettingsPayload, error)
}

// ConfigChangeListener is called whenever a new configuration version is applied.
type ConfigChangeListener func(oldCfg, newCfg *Config)

// Manager coordinates thread-safe, authoritative runtime configuration management.
//
// Architecture & Precedence:
//  1. SQLite (gateway_settings table) is the authoritative source for administrator runtime settings.
//  2. Environment variables (SAMLGUARD_*) and config.yaml serve as the bootstrap baseline defaults.
//  3. Dynamic IP and runtime endpoint updates persist directly to SQLite and update in-memory state;
//     they intentionally NEVER rewrite config.yaml, ensuring deployment immutability.
type Manager struct {
	mu        sync.RWMutex
	activeCfg *Config
	store     SettingsStore
	listeners []ConfigChangeListener
}

// NewManager creates a thread-safe ConfigurationManager initialized from bootstrap configuration.
// If store is provided and contains saved admin settings, those settings are immediately overlaid,
// establishing SQLite as the authoritative runtime source of truth.
func NewManager(baselineCfg *Config, store SettingsStore) (*Manager, error) {
	if baselineCfg == nil {
		return nil, ErrNilConfig
	}

	m := &Manager{
		activeCfg: baselineCfg.Clone(),
		store:     store,
	}

	// Load authoritative runtime configuration from SQLite if available
	if store != nil {
		saved, err := store.GetAdminSettings(context.Background())
		if err == nil && saved != nil {
			ApplyAdminSettings(m.activeCfg, saved)
		} else if err != nil && !isNotFoundError(err) {
			return nil, fmt.Errorf("loading authoritative settings from database: %w", err)
		}
	}

	// Validate the composite configuration
	if err := m.activeCfg.Validate(); err != nil {
		return nil, fmt.Errorf("initial configuration validation failed: %w", err)
	}

	return m, nil
}

// GetConfig returns an isolated, immutable deep-copy snapshot of the active runtime configuration.
// Callers can read the returned snapshot freely without holding locks or risking data races.
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeCfg.Clone()
}

// RegisterListener registers a callback to be notified whenever configuration changes.
func (m *Manager) RegisterListener(listener ConfigChangeListener) {
	if listener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// UpdateAdminSettings validates and atomically applies an AdminSettingsPayload.
// On success:
//  1. The payload is persisted to SQLite gateway_settings (with credential encryption).
//  2. The in-memory active configuration is atomically swapped.
//  3. Registered listeners are notified of the change.
//
// Crucially, config.yaml on disk is NOT modified.
func (m *Manager) UpdateAdminSettings(ctx context.Context, payload *AdminSettingsPayload) (*Config, error) {
	if payload == nil {
		return nil, errors.New("admin settings payload cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Create candidate copy
	candidate := m.activeCfg.Clone()
	ApplyAdminSettings(candidate, payload)

	// 2. Validate proposed settings
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// 3. Persist to authoritative SQLite database
	if m.store != nil {
		if err := m.store.SaveAdminSettings(ctx, payload); err != nil {
			return nil, fmt.Errorf("persisting settings to database: %w", err)
		}
	}

	// 4. Atomically commit to in-memory state
	oldCfg := m.activeCfg
	m.activeCfg = candidate

	// 5. Notify listeners asynchronously or outside critical path
	listeners := append([]ConfigChangeListener(nil), m.listeners...)
	go func() {
		for _, l := range listeners {
			l(oldCfg, candidate)
		}
	}()

	return candidate.Clone(), nil
}

// UpdateDynamicEndpoints atomically updates SAMLGuard's self-identifying SAML endpoints
// (EntityID, SSOURL, SLOURL, MetadataURL) and allowed audiences/origins when the host IP changes,
// without altering downstream ITA configuration or rewriting config.yaml.
func (m *Manager) UpdateDynamicEndpoints(ctx context.Context, entityID, ssoURL, sloURL, metadataURL string, audiences, origins []string) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	candidate := m.activeCfg.Clone()

	if v := strings.TrimSpace(entityID); v != "" {
		candidate.SAML.EntityID = v
	}
	if v := strings.TrimSpace(ssoURL); v != "" {
		candidate.SAML.SSOURL = v
	}
	if v := strings.TrimSpace(sloURL); v != "" {
		candidate.SAML.SLOURL = v
	}
	if v := strings.TrimSpace(metadataURL); v != "" {
		candidate.SAML.MetadataURL = v
	}
	if len(audiences) > 0 {
		candidate.SAML.AllowedAudiences = deduplicateStrings(audiences)
	}
	if len(origins) > 0 {
		candidate.Security.CORSAllowedOrigins = deduplicateStrings(origins)
	}

	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("validating dynamic endpoints: %w", err)
	}

	// Persist the updated configuration snapshot to SQLite
	if m.store != nil {
		payload := ExtractPayloadFromConfig(candidate)
		if err := m.store.SaveAdminSettings(ctx, payload); err != nil {
			return nil, fmt.Errorf("persisting dynamic endpoints to database: %w", err)
		}
	}

	oldCfg := m.activeCfg
	m.activeCfg = candidate

	listeners := append([]ConfigChangeListener(nil), m.listeners...)
	go func() {
		for _, l := range listeners {
			l(oldCfg, candidate)
		}
	}()

	return candidate.Clone(), nil
}

// ExtractPayloadFromConfig converts a Config instance into an AdminSettingsPayload for persistence.
func ExtractPayloadFromConfig(cfg *Config) *AdminSettingsPayload {
	if cfg == nil {
		return nil
	}

	mfaDefault := cfg.MFA.EffectiveDefaultProvider()
	if cfg.MFA.IsMethodSelectDefault() {
		mfaDefault = "select"
	}

	profiles := make(map[string]UpstreamIdPProfile, len(cfg.SAML.IdPProfiles))
	for k, v := range cfg.SAML.IdPProfiles {
		profiles[k] = v
	}

	smsProfiles := make(map[string]SMSGatewayProfile, len(cfg.SMS.Profiles))
	for k, v := range cfg.SMS.Profiles {
		smsProfiles[k] = v
	}

	brandingProfiles := make(map[string]ThemeProfile, len(cfg.Branding.Profiles))
	for k, v := range cfg.Branding.Profiles {
		brandingProfiles[k] = v
	}

	return &AdminSettingsPayload{
		ActiveIdP:                 cfg.SAML.EffectiveActiveIdP(),
		EnabledIdPs:               cfg.SAML.ActiveIdPs(),
		IdPProfiles:               profiles,
		IdPEntityID:               cfg.SAML.IdPEntityID,
		IdPSSOURL:                 cfg.SAML.IdPSSOURL,
		IdPMetadataURL:            cfg.SAML.IdPMetadataURL,
		IdPCertFile:               cfg.SAML.IdPCertFile,
		EntityID:                  cfg.SAML.EntityID,
		ACSURL:                    cfg.SAML.ACSURL,
		GatewayACSURL:             cfg.SAML.GatewayACSURL,
		SSOURL:                    cfg.SAML.SSOURL,
		SLOURL:                    cfg.SAML.SLOURL,
		NetworkMode:               cfg.Server.NetworkMode,
		ManualPublicURL:           cfg.Server.PublicURL,
		PreferredNetworkInterface: cfg.Server.PreferredInterface,
		SelectedNetworkInterface:  cfg.Server.SelectedInterface,
		SelectedNetworkIP:         cfg.Server.SelectedIP,
		PublicPort:                cfg.Server.Port,
		AllowedAudiences:          append([]string(nil), cfg.SAML.AllowedAudiences...),
		GroupMapping:              cfg.SAML.GroupMapping,
		CustomerTenants:           append([]CustomerTenant(nil), cfg.SAML.CustomerTenants...),
		MFAEnabledProviders:       cfg.MFA.ActiveProviders(),
		MFADefaultProvider:        mfaDefault,
		MFAIssuer:                 cfg.MFA.Issuer,
		OTPExpiry:                 cfg.MFA.OTPExpiry,
		ResendCooldown:            cfg.MFA.ResendCooldown,
		AllowDummyOTP:             cfg.MFA.AllowDummyOTP,
		SMTPHost:                  cfg.SMTP.Host,
		SMTPPort:                  cfg.SMTP.Port,
		SMTPUsername:              cfg.SMTP.Username,
		SMTPFrom:                  cfg.SMTP.From,
		SMTPFromName:              cfg.SMTP.FromName,
		SMTPEncryption:            cfg.SMTP.Encryption,
		SMSProvider:               cfg.SMS.EffectiveProvider(),
		SMSAPIURL:                 cfg.SMS.APIURL,
		SMSAccountID:              cfg.SMS.AccountID,
		SMSSenderID:               cfg.SMS.SenderID,
		SMSHTTPMethod:             cfg.SMS.HTTPMethod,
		SMSMessageTemplate:        cfg.SMS.MessageTemplate,
		SMSProfiles:               smsProfiles,
		ITAAPIURL:                 cfg.ITA.APIURL,
		ITAAPIUsername:            cfg.ITA.APIUsername,
		ITAEnforceWhitelist:       cfg.ITA.EnforceUserWhitelist,
		ITAManualAllowedUsers:     append([]string(nil), cfg.ITA.ManualAllowedUsers...),
		BrandingActiveProfile:     cfg.Branding.EffectiveActiveProfile(),
		BrandingProfiles:          brandingProfiles,
		TLSEnabled:                cfg.TLS.Enabled,
		AutoTLSEnabled:            cfg.TLS.AutoTLS.Enabled,
		AutoTLSDomains:            append([]string(nil), cfg.TLS.AutoTLS.Domains...),
		AutoTLSEmail:              cfg.TLS.AutoTLS.Email,
		AutoTLSCacheDir:           cfg.TLS.AutoTLS.EffectiveCacheDir(),
		AutoTLSHTTPChallengeAddr:  cfg.TLS.AutoTLS.EffectiveHTTPChallengeAddr(),
	}
}

func deduplicateStrings(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	var out []string
	for _, item := range input {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no rows")
}
