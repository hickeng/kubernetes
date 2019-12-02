/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"k8s.io/klog"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	defaultKeepAlivePeriod = 3 * time.Minute
)

// GetCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
// This is based on https://golang.org/src/crypto/tls/common.go getCertificate function
// however it is extended to serve differentiated certificates based on incoming IP.
// This duplicates that function because it's necessary to unset c.Certificates in order
// to activate this callback even in non-SNI path, so the fallthrough handling will not
// suffice.
func (s *SecureServingInfo) GetCertificate (clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {

	if len(s.SNICerts) == 0 && len(s.FilteredCerts) == 0 {
		if s.Cert == nil {
			return nil, errors.New("tls: no certificates configured")
		}

		return s.Cert, nil
	}

	if len(clientHello.ServerName) > 0 {
		name := strings.ToLower(clientHello.ServerName)
		for len(name) > 0 && name[len(name)-1] == '.' {
			name = name[:len(name)-1]
		}

		if cert, ok := s.SNICerts[name]; ok {
			return cert, nil
		}

		// try replacing labels in the name with wildcards until we get a
		// match.
		labels := strings.Split(name, ".")
		for i := range labels {
			labels[i] = "*"
			candidate := strings.Join(labels, ".")
			if cert, ok := s.SNICerts[candidate]; ok {
				return cert, nil
			}
		}
	}

	// determine if there is a cert configured that matches the rich filters
	for _, filter := range s.FilteredCerts {
		klog.V(3).Infof("Checking for filtered cert with %v and %v", clientHello.Conn.LocalAddr(), clientHello.Conn.RemoteAddr())

		cert := filter(clientHello)
		if cert != nil {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return s.Cert, nil
}

// Serve runs the secure http server. It fails only if certificates cannot be loaded or the initial listen call fails.
// The actual server loop (stoppable by closing stopCh) runs in a go routine, i.e. Serve does not block.
// It returns a stoppedCh that is closed when all non-hijacked active requests have been processed.
func (s *SecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, error) {
	if s.Listener == nil {
		return nil, fmt.Errorf("listener must not be nil")
	}

	secureServer := &http.Server{
		Addr:           s.Listener.Addr().String(),
		Handler:        handler,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			Certificates:      nil,
			NameToCertificate: s.SNICerts,
			GetCertificate:    s.GetCertificate,
			// Can't use SSLv3 because of POODLE and BEAST
			// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
			// Can't use TLSv1.1 because of RC4 cipher usage
			MinVersion: tls.VersionTLS12,
			// enable HTTP2 for go's 1.7 HTTP Server
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	if s.DisableHTTP2 {
		klog.Info("Forcing use of http/1.1 only")
		secureServer.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	if s.MinTLSVersion > 0 {
		secureServer.TLSConfig.MinVersion = s.MinTLSVersion
	}
	if len(s.CipherSuites) > 0 {
		secureServer.TLSConfig.CipherSuites = s.CipherSuites
	}

	if s.ClientCA != nil {
		// Populate PeerCertificates in requests, but don't reject connections without certificates
		// This allows certificates to be validated by authenticators, while still allowing other auth types
		secureServer.TLSConfig.ClientAuth = tls.RequestClientCert
		// Specify allowed CAs for client certificates
		secureServer.TLSConfig.ClientCAs = s.ClientCA
	}

	// At least 99% of serialized resources in surveyed clusters were smaller than 256kb.
	// This should be big enough to accommodate most API POST requests in a single frame,
	// and small enough to allow a per connection buffer of this size multiplied by `MaxConcurrentStreams`.
	const resourceBody99Percentile = 256 * 1024

	http2Options := &http2.Server{}

	// shrink the per-stream buffer and max framesize from the 1MB default while still accommodating most API POST requests in a single frame
	http2Options.MaxUploadBufferPerStream = resourceBody99Percentile
	http2Options.MaxReadFrameSize = resourceBody99Percentile

	// use the overridden concurrent streams setting or make the default of 250 explicit so we can size MaxUploadBufferPerConnection appropriately
	if s.HTTP2MaxStreamsPerConnection > 0 {
		http2Options.MaxConcurrentStreams = uint32(s.HTTP2MaxStreamsPerConnection)
	} else {
		http2Options.MaxConcurrentStreams = 250
	}

	// increase the connection buffer size from the 1MB default to handle the specified number of concurrent streams
	http2Options.MaxUploadBufferPerConnection = http2Options.MaxUploadBufferPerStream * int32(http2Options.MaxConcurrentStreams)

	if !s.DisableHTTP2 {
		// apply settings to the server
		if err := http2.ConfigureServer(secureServer, http2Options); err != nil {
			return nil, fmt.Errorf("error configuring http2: %v", err)
		}
	}

	klog.Infof("Serving securely on %s", secureServer.Addr)
	return RunServer(secureServer, s.Listener, shutdownTimeout, stopCh)
}

// RunServer spawns a go-routine continuously serving until the stopCh is
// closed.
// It returns a stoppedCh that is closed when all non-hijacked active requests
// have been processed.
// This function does not block
// TODO: make private when insecure serving is gone from the kube-apiserver
func RunServer(
	server *http.Server,
	ln net.Listener,
	shutDownTimeout time.Duration,
	stopCh <-chan struct{},
) (<-chan struct{}, error) {
	if ln == nil {
		return nil, fmt.Errorf("listener must not be nil")
	}

	// Shutdown server gracefully.
	stoppedCh := make(chan struct{})
	go func() {
		defer close(stoppedCh)
		<-stopCh
		ctx, cancel := context.WithTimeout(context.Background(), shutDownTimeout)
		server.Shutdown(ctx)
		cancel()
	}()

	go func() {
		defer utilruntime.HandleCrash()

		var listener net.Listener
		listener = tcpKeepAliveListener{ln.(*net.TCPListener)}
		if server.TLSConfig != nil {
			listener = tls.NewListener(listener, server.TLSConfig)
		}

		err := server.Serve(listener)

		msg := fmt.Sprintf("Stopped listening on %s", ln.Addr().String())
		select {
		case <-stopCh:
			klog.Info(msg)
		default:
			panic(fmt.Sprintf("%s due to error: %v", msg, err))
		}
	}()

	return stoppedCh, nil
}

type NamedTLSCert struct {
	TLSCert tls.Certificate

	// Names is a list of domain patterns: fully qualified domain names, possibly prefixed with
	// wildcard segments.
	Names []string
}

type FilteredTLSCert struct {
	TLSCert tls.Certificate

	Enabled        bool
	Interfaces     []*net.Interface
	ExcludeSrcCIDR []*net.IPNet
	RequireSrcCIDR []*net.IPNet
}

func NewCertFilter(cert *tls.Certificate, filters map[string][]string) (*FilteredTLSCert, error) {
	f := &FilteredTLSCert{
		TLSCert: *cert,
		Enabled: true,
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
					return nil, fmt.Errorf("unable to parse CIDR specified in filter: %v", )
				}

				f.ExcludeSrcCIDR = append(f.ExcludeSrcCIDR, cidr)
			}

		case "require-src-cidr":
			for _, n := range detail {
				_, cidr, err := net.ParseCIDR(strings.TrimSpace(n))
				if err != nil {
					return nil, fmt.Errorf("unable to parse CIDR specified in filter: %v", )
				}

				f.RequireSrcCIDR = append(f.RequireSrcCIDR, cidr)
			}

		default:
			return nil, fmt.Errorf("unknown filter type for selecting certificates: %s", name)
		}
	}

	return f, nil
}

// FilterFn returns a filter function that will return a certificate if the connection information
// supplied matches the filter conditions.
// This may return nil if the filter is disabled.
func (f *FilteredTLSCert) FilterFn() CertFilterFn {
	if !f.Enabled {
		return nil
	}

	return func(clientHello *tls.ClientHelloInfo) *tls.Certificate {
		laddr, lok := clientHello.Conn.LocalAddr().(*net.TCPAddr)
		raddr, rok := clientHello.Conn.RemoteAddr().(*net.TCPAddr)
		if !lok || !rok {
			return nil
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
				return nil
			}
		}

		for _, cidr := range f.ExcludeSrcCIDR {
			if cidr.Contains(raddr.IP) {
				klog.V(3).Infof("Rejected use of cert as %s contains %s", cidr.String(), raddr.IP.String())
				return nil
			}
		}

		if len(f.Interfaces) == 0 {
			return &f.TLSCert
		}

		for _, intf := range f.Interfaces {
			addrs, err := intf.Addrs()
			if err != nil {
				klog.Errorf("Unable to retrieve addresses assocaited with interface %s for serving filtered certificate: %v", err)
				return nil
			}

			for i := range addrs {
				addr, ok := addrs[i].(*net.IPNet)
				if !ok {
					klog.Warning("Unexpected address type on interface during certificate filtering: %T %v", addrs[i], addrs[i])
					continue
				}

				if !addr.IP.Equal(laddr.IP) {
					klog.V(3).Infof("Discarding interface address that does not match conn info: %s != %s", addr.IP, laddr.IP)
					continue
				}

				return &f.TLSCert
			}
		}

		return nil
	}
}

// GetNamedCertificateMap returns a map of *tls.Certificate by name. It's
// suitable for use in tls.Config#NamedCertificates. Returns an error if any of the certs
// cannot be loaded. Returns nil if len(certs) == 0
func GetNamedCertificateMap(certs []NamedTLSCert) (map[string]*tls.Certificate, error) {
	// register certs with implicit names first, reverse order such that earlier trump over the later
	byName := map[string]*tls.Certificate{}
	for i := len(certs) - 1; i >= 0; i-- {
		if len(certs[i].Names) > 0 {
			continue
		}
		cert := &certs[i].TLSCert

		// read names from certificate common names and DNS names
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("empty SNI certificate, skipping")
		}
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse error for SNI certificate: %v", err)
		}
		cn := x509Cert.Subject.CommonName
		if cn == "*" || len(validation.IsDNS1123Subdomain(strings.TrimPrefix(cn, "*."))) == 0 {
			byName[cn] = cert
		}
		for _, san := range x509Cert.DNSNames {
			byName[san] = cert
		}
		// intentionally all IPs in the cert are ignored as SNI forbids passing IPs
		// to select a cert. Before go 1.6 the tls happily passed IPs as SNI values.
	}

	// register certs with explicit names last, overwriting every of the implicit ones,
	// again in reverse order.
	for i := len(certs) - 1; i >= 0; i-- {
		namedCert := &certs[i]
		for _, name := range namedCert.Names {
			byName[name] = &certs[i].TLSCert
		}
	}

	return byName, nil
}


// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
//
// Copied from Go 1.7.2 net/http/server.go
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(defaultKeepAlivePeriod)
	return tc, nil
}
