# SAMLGuard – Phase 2.7: Network Configuration Simplification Report

## Executive Summary

As part of Phase 2.7, SAMLGuard's host network architecture has been dramatically simplified. The previous over-engineered design—which relied on a 15-second background polling timer, complex goroutine orchestration, OS network change subscriptions, and automatic/silent interface switching—has been replaced with a clean, lightweight, **administrator-driven explicit selection model**.

Administrators can now inspect all available host network interfaces (with their IPv4 addresses, operational status, and virtual/physical classifications) directly in **Admin Settings → Service Providers**, select the exact interface SAMLGuard should bind to, and click **Save Configuration**.

---

## 1. Architectural Comparison: Previous vs. Simplified

| Dimension | Previous Design (Phases 2.1–2.5) | Simplified Design (Phase 2.7) |
| :--- | :--- | :--- |
| **Interface Selection** | Automatic detection via OS interface ranking and scoring | Explicit administrator selection from dropdown list |
| **Drift Monitoring** | Continuous 15s background polling goroutine (`netDetector.Start`) | On-demand discovery on startup and manual "Refresh Interfaces" button |
| **Missing Interface Behavior** | Unpredictable / Silent switching to another interface | Retains selection, alerts admin with warning banner, **zero silent switching** |
| **Goroutines & Timers** | Background ticker, cancel contexts, and change callback channels | Zero background goroutines, zero timers, zero channels |
| **Frontend Sync** | 10s automatic polling timer (`setInterval(pollNetworkStatus, 10000)`) | Server-side rendered on load; updated on-demand via UI actions |
| **Component Count** | 5 files (`detector.go`, `detector_test.go`, `resolver.go`, `resolver_test.go`, etc.) | 2 streamlined files (`interfaces.go`, `manager.go`) |
| **Concurrency Model** | Complex nested mutex locks across detector, resolver, and listeners | Single read-write mutex in `network.Manager` |

---

## 2. Components Retained vs. Removed

### Components Removed
1. `internal/network/detector.go`: Removed 15-second polling loop, interface scoring heuristics, and change notification channels.
2. `internal/network/detector_test.go`: Removed detector background loop tests.
3. `internal/network/resolver.go`: Merged public URL resolution and endpoint generation into `network.Manager`.
4. `internal/network/resolver_test.go`: Replaced with streamlined `network_test.go`.
5. Frontend `setInterval(pollNetworkStatus, 10000)`: Removed continuous HTTP polling from the browser.

### Components Created & Retained
1. [`internal/network/interfaces.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/network/interfaces.go):
   - Standard Go `net` package enumeration.
   - `InterfaceInfo` model (`Name`, `DisplayName`, `IPs`, `PrimaryIP`, `IsUp`, `IsVirtual`).
   - Strict filtering of loopback (`127.0.0.1`), link-local (`169.254.x.x`), multicast, and down/inactive interfaces.
   - Virtual interface filtering (Docker, WSL, Hyper-V, veth, bridge, tun/tap) by default, toggleable via `includeVirtual`.
   - `SetTestProviders` and `ResetTestProviders` hooks for deterministic unit testing.
2. [`internal/network/manager.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/network/manager.go):
   - Lightweight `Manager` maintaining selected interface, selected IP, port, TLS state, and optional overrides.
   - Generates canonical `BaseURL`, `EntityID`, `GatewayACSURL`, `SSOURL`, `SLOURL`, `MetadataURL`, `SPMetadataURL`, and `IdPMetadataURL`.
   - `IsIPAvailable()` verifies whether the selected IP currently exists on an active host interface.
   - `UpdateSettings` and `SelectInterface` provide atomic runtime configuration updates.
3. [`internal/config/config.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/config.go) & [`manager.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/manager.go):
   - Retained `SelectedInterface` and `SelectedIP` in `ServerConfig` and `AdminSettingsPayload`.
   - SQLite `gateway_settings` table acts as the authoritative source of truth for administrative changes.
   - `config.yaml` is preserved as bootstrap deployment defaults and is **never modified at runtime**.

---

## 3. Admin UI Changes (Service Providers Tab)

The Service Providers tab (`web/templates/admin_settings.html`) has been redesigned:

1. **🌐 SAMLGuard Host Network Interface & Endpoints Card**:
   - **Interface Dropdown (`#netInterfaceSelect`)**: Displays available interfaces and IPv4 addresses formatted as `Ethernet (eth0) – 192.168.0.178`.
   - **Manual Refresh Button (`🔄 Refresh Interfaces`)**: Triggers an on-demand rescan of host interfaces without reloading the page.
   - **Virtual Interface Checkbox**: Toggle to view or hide virtual and container bridges (WSL, Docker, Hyper-V).
   - **Missing IP Alert Banner (`#netMissingIPBanner`)**: Highlights when the configured IP is no longer present on the machine, prompting the administrator to pick an active interface.
   - **Save Configuration Button (`💾 Save Configuration`)**: Atomically persists the selection to SQLite and recalculates all runtime endpoints.
2. **Endpoint Display (Read-Only)**:
   - Selected SAMLGuard IP (e.g. `192.168.0.178`).
   - Canonical Public Base URL (e.g. `https://192.168.0.178:18080`).
   - SAMLGuard Gateway ACS URL (`https://192.168.0.178:18080/saml/acs`).
   - SAMLGuard Metadata URL (`https://192.168.0.178:18080/metadata`).
   - Status badges: IP Active/Missing, Selected Interface Name, Interface Bound / Manual Override, and TLS SAN status.
3. **Manual Public URL Override Section**:
   - Allows administrators behind reverse proxies or external load balancers to configure an FQDN override (e.g. `https://sso.company.com:8443`).

---

## 4. SQLite Persistence & Configuration Lifecycle

- **Bootstrap Defaults**: On cold startup, `config.yaml` supplies the initial server port and defaults.
- **SQLite Single Source of Truth**: When an administrator selects an interface and clicks Save, the selection is persisted into `gateway_settings` under `selected_network_interface` and `selected_network_ip`.
- **Application Startup**:
  1. SAMLGuard discovers active interfaces on startup.
  2. SAMLGuard loads `SelectedInterface` and `SelectedIP` from SQLite.
  3. SAMLGuard checks `FindInterfaceByIP(selectedIP, true)`.
  4. If the IP exists, it activates normally and logs interface verification.
  5. If the IP does not exist on the host, SAMLGuard logs a warning and marks `is_ip_available = false`, displaying an alert banner in Admin Settings. It **never** silently switches interfaces.
- **Zero Configuration Split-Brain**: `config.yaml` is never modified during interface selection or runtime operation.

---

## 5. SAML Protocol & Security Safeguards

1. **Downstream ITA ACS Independence**:
   - Schneider Electric IT Advisor callback URL (`https://192.168.0.119/auth/saml/acs`) remains completely isolated from SAMLGuard's Gateway ACS (`/saml/acs`).
   - Outbound AuthnRequests to upstream IdPs always specify SAMLGuard's Gateway ACS as `AssertionConsumerServiceURL`.
2. **Dual-ACS & Destination Compatibility**:
   - SAMLGuard's policy validator accepts assertions addressed to `SSOURL`, canonical `/login`, and `/saml/sso`.
3. **TLS SAN Validation**:
   - `checkTLSCertValidForCurrentIP` validates configured TLS certificates against:
     - IP Subject Alternative Names (`cert.IPAddresses`).
     - DNS Subject Alternative Names (`cert.DNSNames`).
     - Subject Common Name (`cert.Subject.CommonName`).
   - If a mismatch is detected, a warning badge is shown in the UI. TLS verification is **never disabled**.

---

## 6. Verification and Test Results

The simplified architecture was verified across unit, integration, and E2E test suites:

```text
=== RUN   TestDiscoverInterfaces_FiltersLoopbackAndVirtual
--- PASS: TestDiscoverInterfaces_FiltersLoopbackAndVirtual (0.00s)
=== RUN   TestManager_EndpointGenerationAndITAIndependence
--- PASS: TestManager_EndpointGenerationAndITAIndependence (0.00s)
=== RUN   TestManager_CustomEntityID
--- PASS: TestManager_CustomEntityID (0.00s)
=== RUN   TestManager_ManualPublicURLOverride
--- PASS: TestManager_ManualPublicURLOverride (0.00s)
=== RUN   TestManager_SelectInterfaceAndDisappearingIP
--- PASS: TestManager_SelectInterfaceAndDisappearingIP (0.00s)
=== RUN   TestAdminNetworkStatus_Get
--- PASS: TestAdminNetworkStatus_Get (0.92s)
=== RUN   TestAdminNetworkConfiguration_PostManualOverride
--- PASS: TestAdminNetworkConfiguration_PostManualOverride (0.10s)
=== RUN   TestAdminNetworkConfiguration_SelectInterface
--- PASS: TestAdminNetworkConfiguration_SelectInterface (0.10s)
=== RUN   TestAdminNetworkConfiguration_InvalidInputs
--- PASS: TestAdminNetworkConfiguration_InvalidInputs (0.10s)
=== RUN   TestAdminNetworkConfiguration_AutoModeReversion
--- PASS: TestAdminNetworkConfiguration_AutoModeReversion (0.10s)
=== RUN   TestGatewayACSArchitectureSeparation
--- PASS: TestGatewayACSArchitectureSeparation (0.10s)
=== RUN   TestTLSCertValidForCurrentIP
--- PASS: TestTLSCertValidForCurrentIP (0.14s)

PASS: All tests across ./cmd/..., ./internal/..., ./pkg/... passed successfully.
PASS: go vet reported zero issues.
```

---

## 7. Limitations & Recommendations

1. **Multi-Homed Binding**: The HTTP listener currently binds to `0.0.0.0` or configured port while SAML endpoints advertise the administrator-selected IPv4 address. If future requirements mandate binding exclusively to a specific socket IP, Go's `net.Listen("tcp4", selectedIP+":"+port)` can be introduced in server setup.
2. **Certificate Provisioning**: When changing host IP on an appliance with self-signed TLS certificates, administrators should regenerate or reissue the TLS certificate with the new IP SAN using SAMLGuard's certificate generation tools or an ACME provider.
