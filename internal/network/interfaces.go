package network

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo describes a discovered host network interface and its IPv4 addresses.
type InterfaceInfo struct {
	Name        string   `json:"name"`         // e.g. "eth0", "Ethernet"
	DisplayName string   `json:"display_name"` // e.g. "Ethernet (eth0)"
	IPs         []string `json:"ips"`          // List of valid IPv4 addresses
	PrimaryIP   string   `json:"primary_ip"`   // Primary/first IPv4 address
	IsUp        bool     `json:"is_up"`        // Interface operational flag
	IsVirtual   bool     `json:"is_virtual"`   // True if docker, veth, wsl, etc.
}

// Test hook variables (defaults use standard net package)
var (
	interfacesProvider = net.Interfaces
	addrProvider       = func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
)

// SetTestProviders allows unit tests to inject deterministic network interfaces.
func SetTestProviders(ifacesFn func() ([]net.Interface, error), addrsFn func(iface *net.Interface) ([]net.Addr, error)) {
	if ifacesFn != nil {
		interfacesProvider = ifacesFn
	} else {
		interfacesProvider = net.Interfaces
	}
	if addrsFn != nil {
		addrProvider = addrsFn
	} else {
		addrProvider = func(iface *net.Interface) ([]net.Addr, error) {
			return iface.Addrs()
		}
	}
}

// ResetTestProviders resets the interface discovery hooks to the standard net package.
func ResetTestProviders() {
	interfacesProvider = net.Interfaces
	addrProvider = func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
}

// DiscoverInterfaces enumerates available non-loopback network interfaces with valid IPv4 addresses.
// If includeVirtual is false, container bridges and virtual interfaces are omitted.
func DiscoverInterfaces(includeVirtual bool) ([]InterfaceInfo, error) {
	ifaces, err := interfacesProvider()
	if err != nil {
		return nil, fmt.Errorf("enumerating network interfaces: %w", err)
	}

	results := make([]InterfaceInfo, 0)
	for _, iface := range ifaces {
		// Exclude loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Exclude down / non-operational interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		isVirtual := isVirtualInterface(iface.Name)
		if isVirtual && !includeVirtual {
			continue
		}

		addrs, err := addrProvider(&iface)
		if err != nil {
			continue
		}

		var validIPv4s []string
		for _, addr := range addrs {
			ip := extractIPv4(addr)
			if isValidHostIPv4(ip) {
				validIPv4s = append(validIPv4s, ip.String())
			}
		}

		// Exclude interfaces without valid IPv4 addresses
		if len(validIPv4s) == 0 {
			continue
		}

		results = append(results, InterfaceInfo{
			Name:        iface.Name,
			DisplayName: formatDisplayName(iface.Name),
			IPs:         validIPv4s,
			PrimaryIP:   validIPv4s[0],
			IsUp:        iface.Flags&net.FlagUp != 0,
			IsVirtual:   isVirtual,
		})
	}

	return results, nil
}

// FindInterfaceByIP checks whether targetIP is currently bound to an active interface.
func FindInterfaceByIP(targetIP string, includeVirtual bool) (*InterfaceInfo, bool) {
	clean := strings.TrimSpace(targetIP)
	if clean == "" {
		return nil, false
	}

	ifaces, err := DiscoverInterfaces(includeVirtual)
	if err != nil {
		return nil, false
	}

	for _, iface := range ifaces {
		for _, ip := range iface.IPs {
			if ip == clean {
				info := iface
				return &info, true
			}
		}
	}

	// If not found in physical interfaces, search virtual interfaces as fallback check
	if !includeVirtual {
		allIfaces, err := DiscoverInterfaces(true)
		if err == nil {
			for _, iface := range allIfaces {
				for _, ip := range iface.IPs {
					if ip == clean {
						info := iface
						return &info, true
					}
				}
			}
		}
	}

	return nil, false
}

// isVirtualInterface identifies common container, hypervisor and tunnel interface names.
func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	virtualKeywords := []string{
		"docker",
		"br-",
		"veth",
		"virbr",
		"vboxnet",
		"vmnet",
		"wsl",
		"tailscale",
		"tun",
		"tap",
		"cali",
		"flannel",
		"cni",
		"vethernet",
		"dummy",
		"bridge",
		"teredo",
		"isatap",
	}

	for _, kw := range virtualKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// extractIPv4 extracts a 4-byte IPv4 address from net.Addr.
func extractIPv4(addr net.Addr) net.IP {
	var rawIP net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		rawIP = v.IP
	case *net.IPAddr:
		rawIP = v.IP
	}
	if rawIP == nil {
		return nil
	}
	return rawIP.To4()
}

// isValidHostIPv4 ensures the IP is non-loopback, non-link-local, non-multicast and non-broadcast.
func isValidHostIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}

	// Reject 0.0.0.0/8 (unspecified)
	if v4[0] == 0 {
		return false
	}
	// Reject 127.0.0.0/8 (loopback)
	if v4[0] == 127 {
		return false
	}
	// Reject 169.254.0.0/16 (link-local / APIPA)
	if v4[0] == 169 && v4[1] == 254 {
		return false
	}
	// Reject multicast / broadcast (>= 224.0.0.0)
	if v4[0] >= 224 {
		return false
	}

	return true
}

// formatDisplayName constructs a user-friendly label for the interface.
func formatDisplayName(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "ethernet") || strings.HasPrefix(lower, "eth") || strings.HasPrefix(lower, "en") {
		return fmt.Sprintf("Ethernet (%s)", name)
	}
	if strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wlan") || strings.HasPrefix(lower, "wl") {
		return fmt.Sprintf("Wi-Fi (%s)", name)
	}
	return name
}
