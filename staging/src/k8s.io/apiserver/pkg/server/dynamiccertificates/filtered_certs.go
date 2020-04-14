package dynamiccertificates

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"k8s.io/klog"
)

type FilterContent struct {
	Normalized     string
	Enabled        bool
	Interfaces     []*net.Interface
	ExcludeSrcCIDR []*net.IPNet
	RequireSrcCIDR []*net.IPNet
}

// CertFilterFn takes a tls.ClientHelloInfo and returns true if the filter matches the connection.
type CertFilterFn func(clientHello *tls.ClientHelloInfo) bool

// NewDynamicFilterContentFromFiles returns a dynamic FilteredCertKeyContentProvider based on a cert and key filename and filter set.
func NewFilterContent(filters map[string][]string, normalized string) (*FilterContent, error) {
	f := &FilterContent{
		Normalized: normalized,
		Enabled:    true,
	}

	for name, detail := range filters {
		switch name {
		case "interface":
			softFail := false
			for _, n := range detail {
				itf, err := net.InterfaceByName(strings.TrimSpace(n))
				if err != nil {
					// soft failure to allow for hotadd/heterogeneous topologies but we still require
					// a restart to pick up the new interface
					klog.Warningf("Unable to locate interface specified in filter: %s", n)
					softFail = true
					continue
				}

				f.Interfaces = append(f.Interfaces, itf)
			}

			// if interface filters were specified but none could be found then this filter needs to
			// be disabled or it will present as one without any interface restrictions and will
			// therefore match much more widely than is desirable.
			if softFail && len(f.Interfaces) == 0 {
				f.Enabled = false
			}

		case "exclude-src-cidr":
			for _, n := range detail {
				_, cidr, err := net.ParseCIDR(strings.TrimSpace(n))
				if err != nil {
					return nil, fmt.Errorf("unable to parse CIDR specified in filter: %v", err)
				}

				f.ExcludeSrcCIDR = append(f.ExcludeSrcCIDR, cidr)
			}

		case "require-src-cidr":
			for _, n := range detail {
				_, cidr, err := net.ParseCIDR(strings.TrimSpace(n))
				if err != nil {
					return nil, fmt.Errorf("unable to parse CIDR specified in filter: %v", err)
				}

				f.RequireSrcCIDR = append(f.RequireSrcCIDR, cidr)
			}

		default:
			return nil, fmt.Errorf("unknown filter type for selecting certificates: %s", name)
		}
	}

	return f, nil
}

// Description returns a normalized string represtentation of the filters associated with this certificate.
func (f *FilterContent) Description() string {
	return f.Normalized
}

// Filter returns a filter function that will return a certificate if the connection information
// supplied matches the filter conditions.
// This may return nil if the filter is disabled.
func (f *FilterContent) Filter() CertFilterFn {
	if !f.Enabled {
		return nil
	}

	return func(clientHello *tls.ClientHelloInfo) bool {
		laddr, lok := clientHello.Conn.LocalAddr().(*net.TCPAddr)
		raddr, rok := clientHello.Conn.RemoteAddr().(*net.TCPAddr)
		if !lok || !rok {
			return false
		}

		if len(f.RequireSrcCIDR) != 0 {
			match := false
			for _, cidr := range f.RequireSrcCIDR {
				if cidr.Contains(raddr.IP) {
					match = true
					break
				}
			}

			if !match {
				klog.V(3).Infof("Rejected use of cert as %s is not in required source CIDRs", raddr.IP.String())
				return false
			}
		}

		for _, cidr := range f.ExcludeSrcCIDR {
			if cidr.Contains(raddr.IP) {
				klog.V(3).Infof("Rejected use of cert as %s contains %s", cidr.String(), raddr.IP.String())
				return false
			}
		}

		if len(f.Interfaces) == 0 {
			return true
		}

		for _, intf := range f.Interfaces {
			addrs, err := intf.Addrs()
			if err != nil {
				klog.Errorf("Unable to retrieve addresses assocaited with interface %s for serving filtered certificate: %v", intf.Name, err)
				return false
			}

			for i := range addrs {
				addr, ok := addrs[i].(*net.IPNet)
				if !ok {
					klog.Warningf("Unexpected address type on interface during certificate filtering: %T %v", addrs[i], addrs[i])
					continue
				}

				if !addr.IP.Equal(laddr.IP) {
					klog.V(3).Infof("Discarding interface address that does not match conn info: %s != %s", addr.IP, laddr.IP)
					continue
				}

				return true
			}
		}

		return false
	}
}
