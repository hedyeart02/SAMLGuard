package network

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoverInterfaces_FiltersLoopbackAndVirtual(t *testing.T) {
	// Mock interfaces: loopback, physical LAN, virtual docker bridge
	SetTestProviders(
		func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
				{Index: 2, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
				{Index: 3, Name: "docker0", Flags: net.FlagUp | net.FlagBroadcast},
				{Index: 4, Name: "veth1234", Flags: net.FlagUp | net.FlagBroadcast},
				{Index: 5, Name: "down0", Flags: net.FlagBroadcast}, // Not UP
			}, nil
		},
		func(ifi *net.Interface) ([]net.Addr, error) {
			switch ifi.Name {
			case "lo":
				return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}}, nil
			case "eth0":
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("192.168.1.50"), Mask: net.CIDRMask(24, 32)},
					&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}, // IPv6 should be ignored
				}, nil
			case "docker0":
				return []net.Addr{&net.IPNet{IP: net.ParseIP("172.17.0.1"), Mask: net.CIDRMask(16, 32)}}, nil
			case "veth1234":
				return []net.Addr{&net.IPNet{IP: net.ParseIP("172.17.0.2"), Mask: net.CIDRMask(16, 32)}}, nil
			case "down0":
				return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			return nil, nil
		},
	)
	defer ResetTestProviders()

	// 1. Discover without virtual interfaces
	physicalIfaces, err := DiscoverInterfaces(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(physicalIfaces) != 1 {
		t.Fatalf("expected 1 physical interface, got %d", len(physicalIfaces))
	}
	if physicalIfaces[0].Name != "eth0" {
		t.Errorf("expected eth0, got %s", physicalIfaces[0].Name)
	}
	if physicalIfaces[0].PrimaryIP != "192.168.1.50" {
		t.Errorf("expected 192.168.1.50, got %s", physicalIfaces[0].PrimaryIP)
	}

	// 2. Discover with virtual interfaces included
	allIfaces, err := DiscoverInterfaces(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have eth0, docker0, veth1234 (loopback and down0 excluded)
	if len(allIfaces) != 3 {
		t.Fatalf("expected 3 interfaces when includeVirtual=true, got %d", len(allIfaces))
	}

	names := make(map[string]bool)
	for _, iface := range allIfaces {
		names[iface.Name] = true
	}
	if !names["eth0"] || !names["docker0"] || !names["veth1234"] {
		t.Errorf("expected eth0, docker0, veth1234; got %v", names)
	}
	if names["lo"] {
		t.Errorf("loopback interface 'lo' must never be included")
	}
}

func TestManager_EndpointGenerationAndITAIndependence(t *testing.T) {
	mgr := NewManager(ManagerOptions{
		SelectedInterface: "eth0",
		SelectedIP:        "192.168.0.178",
		Port:              18080,
		TLSEnabled:        true,
		DownstreamACSURL:  "https://192.168.0.119/auth/saml/acs",
		ExtraAudiences:    []string{"https://192.168.0.119"},
	})

	// Check Base URL
	expectedBaseURL := "https://192.168.0.178:18080"
	if mgr.BaseURL() != expectedBaseURL {
		t.Errorf("expected base URL %s, got %s", expectedBaseURL, mgr.BaseURL())
	}

	// Check Entity ID (defaults to BaseURL)
	if mgr.EntityID() != expectedBaseURL {
		t.Errorf("expected entity ID %s, got %s", expectedBaseURL, mgr.EntityID())
	}

	// Check SSO & SLO URLs
	if mgr.SSOURL() != expectedBaseURL+"/login" {
		t.Errorf("expected SSO URL %s/login, got %s", expectedBaseURL, mgr.SSOURL())
	}
	if mgr.SLOURL() != expectedBaseURL+"/logout" {
		t.Errorf("expected SLO URL %s/logout, got %s", expectedBaseURL, mgr.SLOURL())
	}

	// Check Gateway ACS URL
	expectedGatewayACS := expectedBaseURL + "/saml/acs"
	if mgr.GatewayACSURL() != expectedGatewayACS {
		t.Errorf("expected Gateway ACS %s, got %s", expectedGatewayACS, mgr.GatewayACSURL())
	}

	// Check Downstream ITA ACS independence
	endpoints := mgr.Endpoints()
	if endpoints.GatewayACSURL != expectedGatewayACS {
		t.Errorf("endpoints.GatewayACSURL mismatch: %s", endpoints.GatewayACSURL)
	}
	if endpoints.DownstreamACS != "https://192.168.0.119/auth/saml/acs" {
		t.Errorf("Downstream ITA ACS must remain https://192.168.0.119/auth/saml/acs, got %s", endpoints.DownstreamACS)
	}
	if endpoints.DownstreamACS == endpoints.GatewayACSURL {
		t.Fatalf("Downstream ACS and Gateway ACS must never be equal!")
	}
}

func TestManager_CustomEntityID(t *testing.T) {
	mgr := NewManager(ManagerOptions{
		SelectedInterface: "eth0",
		SelectedIP:        "192.168.0.178",
		Port:              18080,
		TLSEnabled:        true,
		CustomEntityID:    "urn:samlguard:gateway",
	})

	if mgr.EntityID() != "urn:samlguard:gateway" {
		t.Errorf("expected custom entity ID urn:samlguard:gateway, got %s", mgr.EntityID())
	}
	if mgr.BaseURL() != "https://192.168.0.178:18080" {
		t.Errorf("BaseURL should still be derived from IP: %s", mgr.BaseURL())
	}
}

func TestManager_ManualPublicURLOverride(t *testing.T) {
	mgr := NewManager(ManagerOptions{
		SelectedInterface: "eth0",
		SelectedIP:        "192.168.0.178",
		Port:              18080,
		TLSEnabled:        true,
		ManualPublicURL:   "https://sso.mycorp.com:8443",
	})

	if !mgr.IsManualOverride() {
		t.Errorf("expected IsManualOverride() to be true")
	}
	if mgr.BaseURL() != "https://sso.mycorp.com:8443" {
		t.Errorf("expected manual URL https://sso.mycorp.com:8443, got %s", mgr.BaseURL())
	}
	if mgr.GatewayACSURL() != "https://sso.mycorp.com:8443/saml/acs" {
		t.Errorf("expected Gateway ACS https://sso.mycorp.com:8443/saml/acs, got %s", mgr.GatewayACSURL())
	}

	// Revert to auto
	mgr.SetManualPublicURL("")
	if mgr.IsManualOverride() {
		t.Errorf("expected IsManualOverride() to be false after clearing")
	}
	if mgr.BaseURL() != "https://192.168.0.178:18080" {
		t.Errorf("expected reverted URL https://192.168.0.178:18080, got %s", mgr.BaseURL())
	}
}

func TestManager_SelectInterfaceAndDisappearingIP(t *testing.T) {
	SetTestProviders(
		func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 1, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
				{Index: 2, Name: "eth1", Flags: net.FlagUp | net.FlagBroadcast},
			}, nil
		},
		func(ifi *net.Interface) ([]net.Addr, error) {
			if ifi.Name == "eth0" {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.0.178"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			if ifi.Name == "eth1" {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.25"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			return nil, nil
		},
	)
	defer ResetTestProviders()

	mgr := NewManager(ManagerOptions{
		SelectedInterface: "eth0",
		SelectedIP:        "192.168.0.178",
		Port:              18080,
		TLSEnabled:        true,
	})

	// Initial verification
	if !mgr.IsIPAvailable() {
		t.Fatalf("expected 192.168.0.178 to be available on host")
	}

	// Change selected interface manually
	mgr.SelectInterface("eth1", "10.0.0.25", "")
	if mgr.SelectedInterface() != "eth1" {
		t.Errorf("expected eth1, got %s", mgr.SelectedInterface())
	}
	if mgr.SelectedIP() != "10.0.0.25" {
		t.Errorf("expected 10.0.0.25, got %s", mgr.SelectedIP())
	}
	if !mgr.IsIPAvailable() {
		t.Fatalf("expected 10.0.0.25 to be available on host")
	}
	if mgr.BaseURL() != "https://10.0.0.25:18080" {
		t.Errorf("expected https://10.0.0.25:18080, got %s", mgr.BaseURL())
	}

	// Simulate host network reconfiguration: eth1 disappears or changes IP
	SetTestProviders(
		func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 1, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
			}, nil
		},
		func(ifi *net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.0.178"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	)

	// Manager should detect IP is missing, but MUST NOT silently change its selected IP!
	if mgr.IsIPAvailable() {
		t.Errorf("expected 10.0.0.25 to be NOT available on host after eth1 dropped")
	}
	if mgr.SelectedIP() != "10.0.0.25" {
		t.Errorf("manager must not silently change selected IP: expected 10.0.0.25, got %s", mgr.SelectedIP())
	}
	if mgr.SelectedInterface() != "eth1" {
		t.Errorf("manager must not silently change selected interface: expected eth1, got %s", mgr.SelectedInterface())
	}
}

func generateTestCert(t *testing.T, ipSANs []net.IP, dnsSANs []string, commonName string) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ipSANs,
		DNSNames:              dnsSANs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "test-cert.crt")
	certOut, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("writing cert PEM: %v", err)
	}
	return tmpFile
}
