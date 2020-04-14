/*
Copyright 2019 The Kubernetes Authors.

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

package dynamiccertificates

import (
	"bytes"
	"crypto/tls"
)

// CertKeyContentProvider provides a certificate and matching private key
type CertKeyContentProvider interface {
	// Name is just an identifier
	Name() string
	// CurrentCertKeyContent provides cert and key byte content
	CurrentCertKeyContent() ([]byte, []byte)
}

// SNICertKeyContentProvider provides a certificate and matching private key as well as optional explicit names
type SNICertKeyContentProvider interface {
	CertKeyContentProvider
	// SNINames provides names used for SNI. May return nil.
	SNINames() []string
}

// FilterCertKeyContentProvider provides a certificate and matching private key as well as a filter set.
type FilterCertKeyContentProvider interface {
	CertKeyContentProvider
	// Filter returns a function taking a ClientHelloInfo struct and returning true/false for if this cert matches the connection.
	Filter() CertFilterFn
	// Description returns a normalized string form of the filters used.
	Description() string
}

// certKeyContent holds the content for the cert and key
type certKeyContent struct {
	cert      []byte
	key       []byte
	processed *tls.Certificate
}

func (c *certKeyContent) Equal(rhs *certKeyContent) bool {
	if c == nil || rhs == nil {
		return c == rhs
	}

	return bytes.Equal(c.key, rhs.key) && bytes.Equal(c.cert, rhs.cert)
}

// sniCertKeyContent holds the content for the cert and key as well as any explicit names
type sniCertKeyContent struct {
	certKeyContent
	sniNames []string
}

func (c *sniCertKeyContent) Equal(rhs *sniCertKeyContent) bool {
	if c == nil || rhs == nil {
		return c == rhs
	}

	if len(c.sniNames) != len(rhs.sniNames) {
		return false
	}

	for i := range c.sniNames {
		if c.sniNames[i] != rhs.sniNames[i] {
			return false
		}
	}

	return c.certKeyContent.Equal(&rhs.certKeyContent)
}

// filterCertKeyContent holds the content for the cert and key as well a matching function
type filterCertKeyContent struct {
	certKeyContent
	filter      CertFilterFn
	description string
}

func (c *filterCertKeyContent) Equal(rhs *filterCertKeyContent) bool {
	if c == nil || rhs == nil {
		return c == rhs
	}

	if c.description != rhs.description {
		return false
	}

	return c.certKeyContent.Equal(&rhs.certKeyContent)
}
