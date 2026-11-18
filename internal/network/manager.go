package network

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// SAMLEndpoints holds all canonical URLs generated for SAMLGuard and its service providers.
type SAMLEndpoints struct {
	BaseURL        string `json:"base_url"`
	EntityID       string `json:"entity_id"`
	SSOURL         string `json:"sso_url"`
	SLOURL         string `json:"slo_url"`
	GatewayACSURL  string `json:"gateway_acs_url"`
	SPMetadataURL  string `json:"sp_metadata_url"`
	IdPMetadataURL string `json:"idp_metadata_url"`
	MetadataURL    string `json:"metadata_url"`
	DownstreamACS  string `json:"downstream_acs_url"`
}

// PublicURLResolver interface for canonical SAML endpoint resolution.
type PublicURLResolver interface {
	BaseURL() string
	EntityID() string
	SSOURL() string
	SLOURL() string
	GatewayACSURL() string
	SPMetadataURL() string
	IdPMetadataURL() string
	MetadataURL() string
	AllowedAudiences() []string
	AllowedOrigins() []string
	ActiveHost() string
	ActivePort() int
	IsManualOverride() bool
}

// ResolverOptions provides compatibility constructor options.
type ResolverOptions struct {
	SelectedIP       string
	Port             int
	TLSEnabled       bool
	EntityIDOverride string
	ManualPublicURL  string
	DownstreamACSURL string
	ExtraAudiences   []string
	ExtraOrigins     []string
}

// NewPublicURLResolver creates a new Manager configured for public URL resolution.
func NewPublicURLResolver(opts ResolverOptions) *Manager {
	return NewManager(ManagerOptions{
		SelectedIP:       opts.SelectedIP,
		Port:             opts.Port,
		TLSEnabled:       opts.TLSEnabled,
		CustomEntityID:   opts.EntityIDOverride,
		ManualPublicURL:  opts.ManualPublicURL,
		DownstreamACSURL: opts.DownstreamACSURL,
		ExtraAudiences:   opts.ExtraAudiences,
		ExtraOrigins:     opts.ExtraOrigins,
	})
}

// ManagerOptions configures the NetworkManager.
type ManagerOptions struct {
	SelectedInterface string
	SelectedIP        string
	Port              int
	TLSEnabled        bool
	CustomEntityID    string
	ManualPublicURL   string
	DownstreamACSURL  string
	ExtraAudiences    []string
	ExtraOrigins      []string
}

// Manager provides simplified, explicit host network selection and endpoint generation.
type Manager struct {
	mu                sync.RWMutex
	selectedInterface string
	selectedIP        string
	port              int
	tlsEnabled        bool
	customEntityID    string
	manualPublicURL   string
	downstreamACSURL  string
	extraAudiences    []string
	extraOrigins      []string
}

// NewManager constructs a new NetworkManager with the given options.
func NewManager(opts ManagerOptions) *Manager {
	port := opts.Port
	if port <= 0 {
		port = 18080
	}

	return &Manager{
		selectedInterface: strings.TrimSpace(opts.SelectedInterface),
		selectedIP:        strings.TrimSpace(opts.SelectedIP),
		port:              port,
		tlsEnabled:        opts.TLSEnabled,
		customEntityID:    strings.TrimSpace(opts.CustomEntityID),
		manualPublicURL:   cleanURL(opts.ManualPublicURL),
		downstreamACSURL:  strings.TrimSpace(opts.DownstreamACSURL),
		extraAudiences:    opts.ExtraAudiences,
		extraOrigins:      opts.ExtraOrigins,
	}
}

// SelectedInterface returns the currently configured interface name (e.g. "eth0").
func (m *Manager) SelectedInterface() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.selectedInterface
}

// SelectedIP returns the currently configured host IPv4 address (e.g. "192.168.0.178").
func (m *Manager) SelectedIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.selectedIP
}

// IsIPAvailable verifies whether the configured selected IP currently exists on an active host interface.
func (m *Manager) IsIPAvailable() bool {
	m.mu.RLock()
	ip := m.selectedIP
	m.mu.RUnlock()

	if ip == "" {
		return false
	}
	_, found := FindInterfaceByIP(ip, true)
	return found
}

// SelectInterface explicitly updates the selected network interface and IPv4 address.
func (m *Manager) SelectInterface(ifaceName, ipStr string, customEntityID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.selectedInterface = strings.TrimSpace(ifaceName)
	m.selectedIP = strings.TrimSpace(ipStr)
	if customEntityID != "" {
		m.customEntityID = strings.TrimSpace(customEntityID)
	}
}

// UpdateSettings atomically updates network interface, IP, custom entity ID, manual public URL, and port.
func (m *Manager) UpdateSettings(ifaceName, ipStr, customEntityID, manualPublicURL string, port int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ifaceName != "" {
		m.selectedInterface = strings.TrimSpace(ifaceName)
	}
	if ipStr != "" {
		m.selectedIP = strings.TrimSpace(ipStr)
	}
	if customEntityID != "" {
		m.customEntityID = strings.TrimSpace(customEntityID)
	}
	m.manualPublicURL = cleanURL(manualPublicURL)
	if port > 0 {
		m.port = port
	}
}

// SetPort updates the configured service port.
func (m *Manager) SetPort(port int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if port > 0 {
		m.port = port
	}
}

// SetManualPublicURL sets or clears a manual public URL override.
func (m *Manager) SetManualPublicURL(override string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.manualPublicURL = cleanURL(override)
}

// IsManualOverride reports whether a manual URL override is configured.
func (m *Manager) IsManualOverride() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.manualPublicURL != ""
}

// ActiveHost returns the effective hostname or IP.
func (m *Manager) ActiveHost() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.manualPublicURL != "" {
		if u, err := url.Parse(m.manualPublicURL); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if m.selectedIP != "" {
		return m.selectedIP
	}
	return "localhost"
}

// ActivePort returns the effective port number.
func (m *Manager) ActivePort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.manualPublicURL != "" {
		if u, err := url.Parse(m.manualPublicURL); err == nil && u.Port() != "" {
			if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
				return p
			}
		}
		if strings.HasPrefix(strings.ToLower(m.manualPublicURL), "https://") {
			return 443
		}
		return 80
	}
	return m.port
}

// BaseURL returns the canonical public root URL.
func (m *Manager) BaseURL() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.manualPublicURL != "" {
		return m.manualPublicURL
	}

	scheme := "http"
	if m.tlsEnabled {
		scheme = "https"
	}

	host := m.selectedIP
	if host == "" {
		host = "localhost"
	}

	// Omit default ports
	if (scheme == "https" && m.port == 443) || (scheme == "http" && m.port == 80) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}

	if m.port > 0 {
		return fmt.Sprintf("%s://%s:%d", scheme, host, m.port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// EntityID returns the canonical SAML Entity ID.
func (m *Manager) EntityID() string {
	m.mu.RLock()
	custom := m.customEntityID
	m.mu.RUnlock()

	if custom != "" {
		return custom
	}
	return m.BaseURL()
}

// SSOURL returns the gateway Single Sign-On endpoint.
func (m *Manager) SSOURL() string {
	return m.BaseURL() + "/login"
}

// SLOURL returns the gateway Single Logout endpoint.
func (m *Manager) SLOURL() string {
	return m.BaseURL() + "/logout"
}

// GatewayACSURL returns the SAMLGuard Assertion Consumer Service callback endpoint.
func (m *Manager) GatewayACSURL() string {
	return m.BaseURL() + "/saml/acs"
}

// SPMetadataURL returns the upstream SP metadata endpoint.
func (m *Manager) SPMetadataURL() string {
	return m.BaseURL() + "/saml/metadata/sp"
}

// IdPMetadataURL returns the downstream IdP metadata endpoint.
func (m *Manager) IdPMetadataURL() string {
	return m.BaseURL() + "/saml/metadata/idp"
}

// MetadataURL returns the combined metadata endpoint.
func (m *Manager) MetadataURL() string {
	return m.BaseURL() + "/metadata"
}

// AllowedAudiences returns default permitted SAML audiences.
func (m *Manager) AllowedAudiences() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	audiences := []string{m.EntityID(), m.BaseURL()}
	if m.downstreamACSURL != "" {
		if u, err := url.Parse(m.downstreamACSURL); err == nil && u.Host != "" {
			audiences = append(audiences, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
		}
	}
	for _, a := range m.extraAudiences {
		if strings.TrimSpace(a) != "" {
			audiences = append(audiences, strings.TrimSpace(a))
		}
	}
	return deduplicate(audiences)
}

// AllowedOrigins returns permitted CORS / postMessage origins.
func (m *Manager) AllowedOrigins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	origins := []string{m.BaseURL()}
	if m.downstreamACSURL != "" {
		if u, err := url.Parse(m.downstreamACSURL); err == nil && u.Host != "" {
			origins = append(origins, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
		}
	}
	for _, o := range m.extraOrigins {
		if strings.TrimSpace(o) != "" {
			origins = append(origins, strings.TrimSpace(o))
		}
	}
	return deduplicate(origins)
}

// Endpoints returns a complete snapshot of all generated SAML endpoints.
func (m *Manager) Endpoints() SAMLEndpoints {
	m.mu.RLock()
	downstream := m.downstreamACSURL
	m.mu.RUnlock()

	return SAMLEndpoints{
		BaseURL:        m.BaseURL(),
		EntityID:       m.EntityID(),
		SSOURL:         m.SSOURL(),
		SLOURL:         m.SLOURL(),
		GatewayACSURL:  m.GatewayACSURL(),
		SPMetadataURL:  m.SPMetadataURL(),
		IdPMetadataURL: m.IdPMetadataURL(),
		MetadataURL:    m.MetadataURL(),
		DownstreamACS:  downstream,
	}
}

// cleanURL trims whitespace and trailing slashes.
func cleanURL(raw string) string {
	c := strings.TrimSpace(raw)
	return strings.TrimRight(c, "/")
}

// deduplicate removes duplicate and empty strings while preserving order.
func deduplicate(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	var out []string
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}
