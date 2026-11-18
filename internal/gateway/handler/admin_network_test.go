package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/internal/network"
	"go.uber.org/zap"
)

func setupNetworkTestHandler(t *testing.T) (*gin.Engine, *SAMLHandler, *network.Manager, *config.Manager) {
	gin.SetMode(gin.TestMode)

	// Mock host network interfaces for deterministic testing
	network.SetTestProviders(
		func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 1, Name: "Ethernet0", Flags: net.FlagUp | net.FlagBroadcast},
				{Index: 2, Name: "eth1", Flags: net.FlagUp | net.FlagBroadcast},
			}, nil
		},
		func(ifi *net.Interface) ([]net.Addr, error) {
			if ifi.Name == "Ethernet0" {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.0.178"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			if ifi.Name == "eth1" {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("10.10.10.20"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			return nil, nil
		},
	)
	t.Cleanup(func() { network.ResetTestProviders() })

	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
  network_mode: "auto"
  selected_interface: "Ethernet0"
  selected_ip: "192.168.0.178"
saml:
  entity_id: "https://192.168.0.178:18080"
  acs_url: "https://192.168.0.119/auth/saml/acs"
  gateway_acs_url: "https://192.168.0.178:18080/saml/acs"
  sso_url: "https://192.168.0.178:18080/login"
  slo_url: "https://192.168.0.178:18080/logout"
  allowed_audiences:
    - "https://192.168.0.119"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed writing test config: %v", err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("failed loading test config: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed creating sqlite storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	cfgManager, err := config.NewManager(cfg, storage)
	if err != nil {
		t.Fatalf("failed creating config manager: %v", err)
	}

	netManager := network.NewManager(network.ManagerOptions{
		SelectedInterface: "Ethernet0",
		SelectedIP:        "192.168.0.178",
		TLSEnabled:        true,
		Port:              18080,
		CustomEntityID:    cfg.SAML.EntityID,
		DownstreamACSURL:  cfg.SAML.ACSURL,
	})

	h := &SAMLHandler{
		cfg:         cfg,
		logger:      zap.NewNop(),
		auditLogger: zap.NewNop(),
	}
	h.SetNetworkManager(netManager, cfgManager)

	r := gin.New()
	r.GET("/admin/network/status", h.HandleAdminNetworkStatusGet)
	r.POST("/admin/network/configuration", h.HandleAdminNetworkConfigurationPost)

	return r, h, netManager, cfgManager
}

func TestAdminNetworkStatus_Get(t *testing.T) {
	r, _, _, _ := setupNetworkTestHandler(t)

	req := httptest.NewRequest("GET", "/admin/network/status", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp["selected_ip"] != "192.168.0.178" {
		t.Errorf("expected selected_ip 192.168.0.178, got %v", resp["selected_ip"])
	}
	if resp["selected_interface"] != "Ethernet0" {
		t.Errorf("expected selected_interface Ethernet0, got %v", resp["selected_interface"])
	}
	if resp["is_ip_available"] != true {
		t.Errorf("expected is_ip_available true, got %v", resp["is_ip_available"])
	}
	if resp["public_url_mode"] != "auto" {
		t.Errorf("expected public_url_mode auto, got %v", resp["public_url_mode"])
	}

	// Verify available interfaces list
	availableIfaces, ok := resp["available_interfaces"].([]interface{})
	if !ok || len(availableIfaces) == 0 {
		t.Errorf("expected available_interfaces to be non-empty, got %v", resp["available_interfaces"])
	}

	endpoints, ok := resp["endpoints"].(map[string]interface{})
	if !ok {
		t.Fatalf("endpoints field missing or not a map")
	}

	// Verify Downstream ITA ACS is independent of Gateway ACS
	downstreamACS := endpoints["downstream_acs_url"]
	gatewayACS := endpoints["gateway_acs_url"]
	if downstreamACS != "https://192.168.0.119/auth/saml/acs" {
		t.Errorf("expected downstream ACS https://192.168.0.119/auth/saml/acs, got %v", downstreamACS)
	}
	if gatewayACS != "https://192.168.0.178:18080/saml/acs" {
		t.Errorf("expected gateway ACS https://192.168.0.178:18080/saml/acs, got %v", gatewayACS)
	}
}

func TestAdminNetworkConfiguration_PostManualOverride(t *testing.T) {
	r, h, netManager, _ := setupNetworkTestHandler(t)

	payload := map[string]interface{}{
		"mode":              "manual",
		"manual_public_url": "https://samlguard.example.com:8443",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed decoding response: %v", err)
	}

	if resp["public_url_mode"] != "manual" {
		t.Errorf("expected mode manual, got %v", resp["public_url_mode"])
	}
	if resp["public_base_url"] != "https://samlguard.example.com:8443" {
		t.Errorf("expected public_base_url https://samlguard.example.com:8443, got %v", resp["public_base_url"])
	}
	if !netManager.IsManualOverride() {
		t.Errorf("expected netManager.IsManualOverride() == true")
	}
	if h.cfg.Server.NetworkMode != "manual" {
		t.Errorf("expected cfg.Server.NetworkMode == 'manual', got %s", h.cfg.Server.NetworkMode)
	}
}

func TestAdminNetworkConfiguration_SelectInterface(t *testing.T) {
	r, h, netManager, _ := setupNetworkTestHandler(t)

	payload := map[string]interface{}{
		"mode":           "auto",
		"interface_name": "eth1",
		"ip_address":     "10.10.10.20",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed decoding response: %v", err)
	}

	if resp["selected_interface"] != "eth1" {
		t.Errorf("expected selected_interface eth1, got %v", resp["selected_interface"])
	}
	if resp["selected_ip"] != "10.10.10.20" {
		t.Errorf("expected selected_ip 10.10.10.20, got %v", resp["selected_ip"])
	}
	if resp["public_base_url"] != "https://10.10.10.20:18080" {
		t.Errorf("expected public_base_url https://10.10.10.20:18080, got %v", resp["public_base_url"])
	}
	if netManager.SelectedInterface() != "eth1" {
		t.Errorf("expected netManager.SelectedInterface() == eth1, got %s", netManager.SelectedInterface())
	}
	if netManager.SelectedIP() != "10.10.10.20" {
		t.Errorf("expected netManager.SelectedIP() == 10.10.10.20, got %s", netManager.SelectedIP())
	}
	if h.cfg.Server.SelectedInterface != "eth1" {
		t.Errorf("expected cfg.Server.SelectedInterface == eth1, got %s", h.cfg.Server.SelectedInterface)
	}
	if h.cfg.Server.SelectedIP != "10.10.10.20" {
		t.Errorf("expected cfg.Server.SelectedIP == 10.10.10.20, got %s", h.cfg.Server.SelectedIP)
	}
}

func TestAdminNetworkConfiguration_InvalidInputs(t *testing.T) {
	r, _, _, _ := setupNetworkTestHandler(t)

	// 1. Invalid mode
	badModePayload, _ := json.Marshal(map[string]interface{}{"mode": "unsupported"})
	req := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(badModePayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad mode, got %d", w.Code)
	}

	// 2. Empty manual public url in manual mode
	emptyURLPayload, _ := json.Marshal(map[string]interface{}{"mode": "manual", "manual_public_url": ""})
	req2 := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(emptyURLPayload))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty manual url, got %d", w2.Code)
	}

	// 3. Invalid port
	badPortPayload, _ := json.Marshal(map[string]interface{}{"mode": "auto", "public_port": 99999})
	req3 := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(badPortPayload))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid port, got %d", w3.Code)
	}

	// 4. Invalid IP (loopback or invalid)
	badIPPayload, _ := json.Marshal(map[string]interface{}{"mode": "auto", "ip_address": "127.0.0.1"})
	req4 := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(badIPPayload))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for loopback IP, got %d", w4.Code)
	}
}

func TestAdminNetworkConfiguration_AutoModeReversion(t *testing.T) {
	r, h, netManager, _ := setupNetworkTestHandler(t)

	// First set to manual
	setManual, _ := json.Marshal(map[string]interface{}{
		"mode":              "manual",
		"manual_public_url": "https://samlguard.corp.internal:8443",
	})
	req := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(setManual))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	// Now revert to auto
	setAuto, _ := json.Marshal(map[string]interface{}{
		"mode": "auto",
	})
	req2 := httptest.NewRequest("POST", "/admin/network/configuration", bytes.NewReader(setAuto))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w2.Code)
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp["public_url_mode"] != "auto" {
		t.Errorf("expected auto mode after reversion, got %v", resp["public_url_mode"])
	}
	if netManager.IsManualOverride() {
		t.Errorf("expected netManager manual override to be false")
	}
	if h.cfg.Server.NetworkMode != "auto" {
		t.Errorf("expected cfg.Server.NetworkMode == 'auto', got %s", h.cfg.Server.NetworkMode)
	}
}

func TestGatewayACSArchitectureSeparation(t *testing.T) {
	_, h, netManager, _ := setupNetworkTestHandler(t)

	// 1. Check Gateway ACS URL
	gatewayACS := h.getGatewayACSLocation()
	expectedGatewayACS := netManager.GatewayACSURL()
	if gatewayACS != expectedGatewayACS {
		t.Fatalf("expected gateway ACS %s, got %s", expectedGatewayACS, gatewayACS)
	}

	// 2. Downstream ITA ACS must remain untouched
	downstreamACS := h.cfg.SAML.ACSURL
	if downstreamACS != "https://192.168.0.119/auth/saml/acs" {
		t.Fatalf("expected downstream ITA ACS to be https://192.168.0.119/auth/saml/acs, got %s", downstreamACS)
	}

	// 3. Outbound AuthnRequest must use Gateway ACS as its AssertionConsumerServiceURL
	reqXML := h.buildOutboundAuthnRequest("REQ_12345", "https://login.microsoftonline.com/saml2")
	if !strings.Contains(reqXML, `AssertionConsumerServiceURL="`+gatewayACS+`"`) {
		t.Errorf("expected outbound AuthnRequest to contain Gateway ACS %s, got: %s", gatewayACS, reqXML)
	}
	if strings.Contains(reqXML, downstreamACS) {
		t.Errorf("outbound AuthnRequest must NOT leak downstream ITA ACS %s", downstreamACS)
	}
}

func TestTLSCertValidForCurrentIP(t *testing.T) {
	// Create cert with IP SAN 192.168.0.178 and DNS SAN sso.example.com
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "samlguard.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("192.168.0.178")},
		DNSNames:              []string{"sso.example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}

	certFile := filepath.Join(t.TempDir(), "test-san.crt")
	f, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = f.Close()

	// 1. IP SAN matches
	if !checkTLSCertValidForCurrentIP(certFile, "192.168.0.178") {
		t.Errorf("expected 192.168.0.178 to match IP SAN")
	}

	// 2. IP SAN mismatch
	if checkTLSCertValidForCurrentIP(certFile, "10.0.0.1") {
		t.Errorf("expected 10.0.0.1 to NOT match IP SAN")
	}

	// 3. DNS SAN matches
	if !checkTLSCertValidForCurrentIP(certFile, "sso.example.com") {
		t.Errorf("expected sso.example.com to match DNS SAN")
	}

	// 4. CommonName matches
	if !checkTLSCertValidForCurrentIP(certFile, "samlguard.local") {
		t.Errorf("expected samlguard.local to match CommonName")
	}

	// 5. Empty inputs
	if checkTLSCertValidForCurrentIP("", "192.168.0.178") {
		t.Errorf("expected false for empty cert path")
	}
	if checkTLSCertValidForCurrentIP(certFile, "") {
		t.Errorf("expected false for empty host")
	}
}
