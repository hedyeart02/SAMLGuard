# SAMLGuard Phase 2.7 – Final Architecture Verification Report

**Date:** November 18, 2026  
**Auditor:** Antigravity Agent  
**Scope:** Read-Only Verification of Network Simplification Implementation (Phase 2.7)  
**Status:** Verification Complete  

---

## Executive Summary

A comprehensive, read-only architectural verification of the Phase 2.7 Network Configuration Simplification was performed. All automated tests across all repository modules passed with zero failures (`-count=1`), and static analysis via `go vet` completed with zero warnings.

The implementation successfully eliminates the previous 15-second background network polling goroutine, interface scoring heuristics, and silent interface switching. The system now enforces an explicit, administrator-driven network interface selection model with persistent SQLite storage and on-demand discovery.

---

## 1. Network Selection Behavior

| Item | Requirement | Verification Details & File References | Classification |
| :--- | :--- | :--- | :--- |
| **1.1** | **Admin can select specific interface and IPv4 address** | Verified in [`web/templates/admin_settings.html`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/web/templates/admin_settings.html#L2235-L2248) (`#netInterfaceSelect`) and [`internal/gateway/handler/admin.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/admin.go#L1987-L2060) (`HandleAdminNetworkConfigurationPost`). Payloads contain `interface_name` and `ip_address`, which are validated against non-loopback/non-unspecified IPv4 addresses. | **PASS** |
| **1.2** | **Interface name and IP persisted together** | Verified in [`internal/config/save.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/save.go#L39-L40) (`SelectedNetworkInterface`, `SelectedNetworkIP`) and [`ApplyAdminSettings`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/save.go#L124-L130). Both fields are committed atomically to SQLite `gateway_settings`. | **PASS** |
| **1.3** | **Startup restores exact saved selection** | Verified in [`internal/config/manager.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/manager.go#L51-L59) (`NewManager`) and [`cmd/samlguard/main.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/cmd/samlguard/main.go#L120-L136). Saved values overwrite bootstrap defaults and initialize `network.NewManager`. | **PASS** |
| **1.4** | **No silent switching if interface disappears** | Verified in [`cmd/samlguard/main.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/cmd/samlguard/main.go#L138-L152) and [`internal/network/manager.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/network/manager.go#L130-L141) (`IsIPAvailable`). If the selected IP is missing on startup or recheck, SAMLGuard logs a warning and flags `is_ip_available: false`. It **never** mutates the persisted selection. | **PASS** |
| **1.5** | **IP reappearing on another interface** | Verified in [`internal/network/interfaces.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/network/interfaces.go#L107-L144) (`FindInterfaceByIP`) and [`web/templates/admin_settings.html`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/web/templates/admin_settings.html#L3546-L3553). The dropdown matching logic matches both interface name and IP (`data.selected_interface === iface.name && data.selected_ip === iface.primary_ip`). If the IP migrates to another interface (e.g. `eth0` -> `eth1`), the interface mismatch is visible to the admin. | **PASS** |
| **1.6** | **Refresh does not mutate saved selection** | Verified in [`web/templates/admin_settings.html`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/web/templates/admin_settings.html#L3532-L3564) (`refreshNetworkInterfaces`) and [`internal/gateway/handler/admin.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/admin.go#L1892-L1984) (`HandleAdminNetworkStatusGet`). `GET /admin/network/status` performs a read-only rescan; zero database writes or state mutations occur. | **PASS** |

---

## 2. Listener vs Advertised IP

### Findings

- **HTTP Server Binding Address:**
  - In [`cmd/samlguard/main.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/cmd/samlguard/main.go#L510-L514):
    ```go
    serverAddr := cfg.Server.Address()
    srv := &http.Server{
        Addr:              serverAddr,
        Handler:           engine,
        ReadHeaderTimeout: 10 * time.Second,
        ReadTimeout:       cfg.Server.ReadTimeout,
        WriteTimeout:      cfg.Server.WriteTimeout,
    }
    ```
  - In [`internal/config/config.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/config.go#L63-L68):
    ```go
    func (s ServerConfig) Address() string {
        if s.Host == "" {
            return fmt.Sprintf(":%d", s.Port)
        }
        return fmt.Sprintf("%s:%d", s.Host, s.Port)
    }
    ```
  - Default configuration (`config.yaml`) sets `host: "0.0.0.0"`. Therefore, the HTTP server listener binds to `0.0.0.0:18080` (all IPv4 interfaces on the host).

- **Scope of Selected Interface:**
  - The administrator-selected interface and IPv4 address strictly govern the **advertised canonical SAML endpoints** and protocol metadata:
    - SAML Entity ID (`https://<selected_ip>:18080`)
    - Gateway ACS URL (`https://<selected_ip>:18080/saml/acs`)
    - Single Sign-On URL (`https://<selected_ip>:18080/login`)
    - Single Logout URL (`https://<selected_ip>:18080/logout`)
    - Metadata URL (`https://<selected_ip>:18080/metadata`)
    - SAML Policy Destination validation ([`cmd/samlguard/main.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/cmd/samlguard/main.go#L231-L255))

- **UI Accuracy:**
  - The UI description in [`web/templates/admin_settings.html`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/web/templates/admin_settings.html#L2197-L2199) accurately states:
    > *"Select the host network interface and IPv4 address used for canonical SAML endpoints."*
  - The help text under Selected SAMLGuard IP notes:
    > *"Active IPv4 host address explicitly selected by the administrator."*

- **Recommendation:**
  - **Retain `0.0.0.0` as the default listener binding.** Binding to `0.0.0.0` avoids catastrophic listener crashes if an interface link temporarily drops (e.g., during cable disconnects, DHCP renews, or switch reboots). Advertising the explicitly selected IP ensures that all SAML assertions, metadata descriptors, and downstream ITA configurations are strictly bound to the administrator's intended network interface.

**Classification:** **PASS**

---

## 3. Configuration Simplicity & Legacy Cleanup Audit

| Finding | File & Reference | Classification | Details & Recommendation |
| :--- | :--- | :--- | :--- |
| **No Background Polling Goroutines** | [`internal/network/`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/network/) | **PASS** | Verified that `detector.go`, `detector_test.go`, and all background tickers/goroutines have been completely deleted. |
| **No Periodic Browser Polling** | [`web/templates/admin_settings.html`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/web/templates/admin_settings.html#L3446) | **PASS** | `setInterval(pollNetworkStatus, 10000)` was removed. Interface scanning is 100% on-demand. |
| **Dual Persistence Field (`PreferredNetworkInterface`)** | [`internal/config/save.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/save.go#L38-L39) | **MINOR ISSUE** | `PreferredNetworkInterface` is retained in `AdminSettingsPayload` alongside `SelectedNetworkInterface` to prevent breaking existing API consumers. In a future major cleanup, `PreferredNetworkInterface` can be fully deprecated. |
| **Residual Function `UpdateDynamicEndpoints`** | [`internal/config/manager.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/manager.go#L133-L175) | **MINOR ISSUE** | `UpdateDynamicEndpoints` was originally implemented for the Phase 2.4 background IP change callback. It is covered by unit tests in `manager_test.go`, but is no longer invoked by `main.go`. It does not cause harm or instability. |
| **Obsolete Network Mode Field Name** | [`internal/config/config.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/config/config.go#L57) | **PASS** | `NetworkMode` distinguishes between `"auto"` (interface-bound IP) and `"manual"` (manual FQDN override). Its usage is valid and active. |

---

## 4. SAML Endpoint Consistency

| Endpoint | Generator / Source | Generated Example | Verification Result |
| :--- | :--- | :--- | :--- |
| **Entity ID** | `netManager.EntityID()` | `https://192.168.0.178:18080` | **PASS** (or custom override if configured) |
| **SSO URL** | `netManager.SSOURL()` | `https://192.168.0.178:18080/login` | **PASS** |
| **SLO URL** | `netManager.SLOURL()` | `https://192.168.0.178:18080/logout` | **PASS** |
| **Gateway ACS** | `netManager.GatewayACSURL()` | `https://192.168.0.178:18080/saml/acs` | **PASS** |
| **SP Metadata** | `netManager.SPMetadataURL()` | `https://192.168.0.178:18080/saml/metadata/sp` | **PASS** |
| **IdP Metadata** | `netManager.IdPMetadataURL()` | `https://192.168.0.178:18080/saml/metadata/idp` | **PASS** |
| **Combined Metadata** | `netManager.MetadataURL()` | `https://192.168.0.178:18080/metadata` | **PASS** |

### Downstream Schneider IT Advisor Independence

- **Downstream ACS URL:** Maintained strictly as `cfg.SAML.ACSURL` (`https://192.168.0.119/auth/saml/acs`).
- **ITA API URL:** Maintained strictly as `cfg.ITA.APIURL` (`https://192.168.0.119/api/v1`).
- **Separation Verification:** Tested in [`internal/gateway/handler/admin_network_test.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/admin_network_test.go#L335-L359) (`TestGatewayACSArchitectureSeparation`). Gateway ACS and Downstream ITA ACS are never conflated, and outbound AuthnRequests never leak ITA's downstream ACS.

### SAML Protocol Validation Checks

- **Destination Validation:** Verified in [`internal/gateway/validator/concrete.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/validator/concrete.go#L160-L192). Validates against dynamic resolver, `ExpectedDestination`, and `AllowedDestinations`.
- **Recipient Validation:** Verified in [`internal/gateway/handler/handler.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/handler.go#L779-L801). Ensures `SubjectConfirmationData Recipient` strictly matches the Gateway ACS.
- **InResponseTo Correlation:** Verified in [`internal/gateway/handler/handler.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/handler.go#L760-L777). Rejects unsolicited responses or mismatched request IDs.
- **Audience Enforcement:** Verified in [`internal/gateway/handler/handler.go`](file:///c:/Users/SESA757023/Documents/Hidayat%20Websites/MFA%20Golang/internal/gateway/handler/handler.go#L819-L832). Validates assertion against `cfg.SAML.AllowedAudiences`.

**Classification:** **PASS**

---

## 5. UI Verification (Admin Settings → Service Providers)

| Element | Location in Template | Functional Behavior | Classification |
| :--- | :--- | :--- | :--- |
| **Dropdown with Interface & IPv4** | Lines 2235–2244 | Populates `<select id="netInterfaceSelect">` with `{{.DisplayName}} – {{.PrimaryIP}}`. Shows `[virtual]` badge for container adapters. | **PASS** |
| **Restored Selection** | Lines 2237–2239 | Evaluates `{{if and (eq $.SelectedNetworkInterface .Name) (eq $.SelectedNetworkIP .PrimaryIP)}}selected{{end}}`. Restores exact saved interface on cold reload. | **PASS** |
| **Refresh Interfaces Button** | Lines 2243–2245 | Triggers `refreshNetworkInterfaces()`, making an AJAX call to `/admin/network/status` and rebuilding options in place. | **PASS** |
| **Save Configuration Button** | Lines 2246–2248 | Triggers `saveSelectedNetworkInterface()`, sending POST to `/admin/network/configuration` with the selected interface name and IP. | **PASS** |
| **Missing Interface Warning** | Lines 2217–2228 | `#netMissingIPBanner` displays warning with missing IP value if `IsNetworkIPAvailable == false`. | **PASS** |
| **Read-Only Endpoints Display** | Lines 2262–2298 | `#netSelectedIP`, `#netPublicBaseURL`, `#netGatewayACSURL`, `#netMetadataURL` display live values and provide working clipboard copy buttons. | **PASS** |
| **TLS SAN Status Pill** | Lines 2209–2212 | `#netTLSSANPill` displays `🔒 TLS SAN Valid` or `⚠️ TLS SAN Mismatch` according to certificate SAN check against selected IP/domain. | **PASS** |

---

## 6. Test Verification (Execution Output)

### Unit, Integration & E2E Tests

Command:
```powershell
go test -count=1 ./cmd/... ./internal/... ./pkg/...
```

Output:
```text
ok  	github.com/hidayat-SE/samlguard/cmd/samlguard		5.719s
?   	github.com/hidayat-SE/samlguard/cmd/samlguard-cli	[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/config		0.809s
?   	github.com/hidayat-SE/samlguard/internal/federation/adapter	[no test files]
?   	github.com/hidayat-SE/samlguard/internal/federation/adapter/entra	[no test files]
?   	github.com/hidayat-SE/samlguard/internal/federation/certificate	[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/federation/metadata	0.434s
?   	github.com/hidayat-SE/samlguard/internal/federation/model	[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/gateway		0.491s
ok  	github.com/hidayat-SE/samlguard/internal/gateway/binding	0.436s
?   	github.com/hidayat-SE/samlguard/internal/gateway/builder	[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/gateway/capture	1.844s
ok  	github.com/hidayat-SE/samlguard/internal/gateway/handler	7.325s
?   	github.com/hidayat-SE/samlguard/internal/gateway/model		[no test files]
?   	github.com/hidayat-SE/samlguard/internal/gateway/parser		[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/gateway/pipeline	0.482s
ok  	github.com/hidayat-SE/samlguard/internal/gateway/resolver	0.508s
ok  	github.com/hidayat-SE/samlguard/internal/gateway/validator	0.381s
ok  	github.com/hidayat-SE/samlguard/internal/ita			1.045s
ok  	github.com/hidayat-SE/samlguard/internal/mfa			2.695s
?   	github.com/hidayat-SE/samlguard/internal/model			[no test files]
ok  	github.com/hidayat-SE/samlguard/internal/network		0.468s
?   	github.com/hidayat-SE/samlguard/internal/plugin			[no test files]
?   	github.com/hidayat-SE/samlguard/internal/policy/saml		[no test files]
?   	github.com/hidayat-SE/samlguard/internal/shared			[no test files]
?   	github.com/hidayat-SE/samlguard/internal/shared/context		[no test files]
?   	github.com/hidayat-SE/samlguard/internal/shared/persistence	[no test files]
ok  	github.com/hidayat-SE/samlguard/pkg/config			0.487s
?   	github.com/hidayat-SE/samlguard/pkg/crypto			[no test files]
?   	github.com/hidayat-SE/samlguard/pkg/errors			[no test files]
?   	github.com/hidayat-SE/samlguard/pkg/logger			[no test files]
?   	github.com/hidayat-SE/samlguard/pkg/metrics			[no test files]
ok  	github.com/hidayat-SE/samlguard/pkg/middleware			0.519s
ok  	github.com/hidayat-SE/samlguard/pkg/ratelimiter			1.828s
ok  	github.com/hidayat-SE/samlguard/pkg/replay			0.278s
?   	github.com/hidayat-SE/samlguard/pkg/response			[no test files]
?   	github.com/hidayat-SE/samlguard/pkg/saml			[no test files]
```

### Static Analysis

Command:
```powershell
go vet ./cmd/... ./internal/... ./pkg/...
```

Output:
```text
(Zero warnings or errors. Exit code 0.)
```

---

## 7. Findings Summary Table

| Category | Finding Description | Severity | Action Required |
| :--- | :--- | :--- | :--- |
| Network Selection | Admin interface & IP selection with zero silent switching | **PASS** | None |
| Persistence | SQLite `gateway_settings` atomic commit & restore | **PASS** | None |
| Listener Architecture | `0.0.0.0` socket listener vs advertised IP separation | **PASS** | None |
| SAML Security | InResponseTo, Recipient, Destination, and Audience guards | **PASS** | None |
| UI Interface | On-demand refresh, save feedback, missing IP banner | **PASS** | None |
| Legacy Polling | Removal of all background polling timers & goroutines | **PASS** | None |
| Test Coverage | All unit, integration, and E2E tests pass with `-count=1` | **PASS** | None |
| Code Hygiene | `UpdateDynamicEndpoints` retained but uncalled by `main` | **MINOR ISSUE** | Retain for backwards compatibility or deprecate in Phase 3 |
| Payload Compatibility | `PreferredNetworkInterface` duplicate field | **MINOR ISSUE** | Retain for backwards compatibility or deprecate in Phase 3 |

**MUST FIX Count:** `0`  
**MINOR ISSUE Count:** `2`  
**PASS Count:** `7`  

---

## Conclusion & Readiness

The Phase 2.7 implementation is clean, robust, lightweight, and fully functional. It strictly honors all user architectural constraints, avoids over-engineering, maintains complete separation of downstream Schneider IT Advisor endpoints, and passes all verification gates.
