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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const workItemKey = "key"

// DynamicServingCertificateController dynamically loads certificates and provides a golang tls compatible dynamic GetCertificate func.
type DynamicServingCertificateController struct {
	// baseTLSConfig is the static portion of the tlsConfig for serving to clients.  It is copied and the copy is mutated
	// based on the dynamic cert state.
	baseTLSConfig tls.Config

	// clientCA provides the very latest content of the ca bundle
	clientCA CAContentProvider
	// servingCert provides the very latest content of the default serving certificate
	servingCert CertKeyContentProvider
	// sniCerts are a list of CertKeyContentProvider with associated names used for SNI
	sniCerts []SNICertKeyContentProvider
	// filteredCerts is a set of functions to be called that will return a Certificate if the parameter
	// matches the filter criteria, otherwise returning nil.
	filterCerts []FilterCertKeyContentProvider

	// currentlyServedContent holds the original bytes that we are serving. This is used to decide if we need to set a
	// new atomic value. The types used for efficient TLSConfig preclude using the processed value.
	currentlyServedContent *dynamicCertificateContent
	// currentServingTLSConfig holds a *tls.Config that will be used to serve requests
	currentServingTLSConfig atomic.Value

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue         workqueue.RateLimitingInterface
	eventRecorder events.EventRecorder
}

var _ Listener = &DynamicServingCertificateController{}

// NewDynamicServingCertificateController returns a controller that can be used to keep a TLSConfig up to date.
func NewDynamicServingCertificateController(
	baseTLSConfig tls.Config,
	clientCA CAContentProvider,
	servingCert CertKeyContentProvider,
	sniCerts []SNICertKeyContentProvider,
	filteredCerts []FilterCertKeyContentProvider,
	eventRecorder events.EventRecorder,
) *DynamicServingCertificateController {
	c := &DynamicServingCertificateController{
		baseTLSConfig: baseTLSConfig,
		clientCA:      clientCA,
		servingCert:   servingCert,
		sniCerts:      sniCerts,
		filterCerts:   filteredCerts,

		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "DynamicServingCertificateController"),
		eventRecorder: eventRecorder,
	}

	return c
}

// GetConfigForClient is an implementation of tls.Config.GetConfigForClient
func (c *DynamicServingCertificateController) GetConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	uncastObj := c.currentServingTLSConfig.Load()
	if uncastObj == nil {
		return nil, errors.New("dynamiccertificates: configuration not ready")
	}
	tlsConfig, ok := uncastObj.(*tls.Config)
	if !ok {
		return nil, errors.New("dynamiccertificates: unexpected config type")
	}

	return tlsConfig.Clone(), nil
}

// newTLSContent determines the next set of content for overriding the baseTLSConfig.
func (c *DynamicServingCertificateController) newTLSContent() (*dynamicCertificateContent, error) {
	newContent := &dynamicCertificateContent{}

	if c.clientCA != nil {
		currClientCABundle := c.clientCA.CurrentCABundleContent()
		// we allow removing all client ca bundles because the server is still secure when this happens. it just means
		// that there isn't a hint to clients about which client-cert to used.  this happens when there is no client-ca
		// yet known for authentication, which can happen in aggregated apiservers and some kube-apiserver deployment modes.
		newContent.clientCA = caBundleContent{caBundle: currClientCABundle}
	}

	if c.servingCert != nil {
		currServingCert, currServingKey := c.servingCert.CurrentCertKeyContent()
		if len(currServingCert) == 0 || len(currServingKey) == 0 {
			return nil, fmt.Errorf("not loading an empty serving certificate from %q", c.servingCert.Name())
		}

		newContent.servingCert = certKeyContent{cert: currServingCert, key: currServingKey}
	}

	for i, sniCert := range c.sniCerts {
		currCert, currKey := sniCert.CurrentCertKeyContent()
		if len(currCert) == 0 || len(currKey) == 0 {
			return nil, fmt.Errorf("not loading an empty SNI certificate from %d/%q", i, sniCert.Name())
		}

		newContent.sniCerts = append(newContent.sniCerts, sniCertKeyContent{certKeyContent: certKeyContent{cert: currCert, key: currKey}, sniNames: sniCert.SNINames()})
	}

	for i, filterCert := range c.filterCerts {
		currCert, currKey := filterCert.CurrentCertKeyContent()
		if len(currCert) == 0 || len(currKey) == 0 {
			return nil, fmt.Errorf("not loading an empty filter certificate from %d/%q", i, filterCert.Name())
		}

		newContent.filterCerts = append(newContent.filterCerts, filterCertKeyContent{
			certKeyContent: certKeyContent{cert: currCert, key: currKey},
			filter:         filterCert.Filter(),
			description:    filterCert.Description(),
		})
	}

	return newContent, nil
}

// syncCerts gets newTLSContent, if it has changed from the existing, the content is parsed and stored for usage in
// GetConfigForClient.
func (c *DynamicServingCertificateController) syncCerts() error {
	newContent, err := c.newTLSContent()
	if err != nil {
		return err
	}
	// if the content is the same as what we currently have, we can simply skip it.  This works because we are single
	// threaded.  If you ever make this multi-threaded, add a lock.
	if newContent.Equal(c.currentlyServedContent) {
		return nil
	}

	// make a shallow copy and override the dynamic pieces which have changed.
	newTLSConfigCopy := c.baseTLSConfig.Clone()

	// parse new content to add to TLSConfig
	if len(newContent.clientCA.caBundle) > 0 {
		newClientCAPool := x509.NewCertPool()
		newClientCAs, err := cert.ParseCertsPEM(newContent.clientCA.caBundle)
		if err != nil {
			return fmt.Errorf("unable to load client CA file %q: %v", string(newContent.clientCA.caBundle), err)
		}
		for i, cert := range newClientCAs {
			klog.V(2).Infof("loaded client CA [%d/%q]: %s", i, c.clientCA.Name(), GetHumanCertDetail(cert))
			if c.eventRecorder != nil {
				c.eventRecorder.Eventf(nil, nil, v1.EventTypeWarning, "TLSConfigChanged", "CACertificateReload", "loaded client CA [%d/%q]: %s", i, c.clientCA.Name(), GetHumanCertDetail(cert))
			}

			newClientCAPool.AddCert(cert)
		}

		newTLSConfigCopy.ClientCAs = newClientCAPool
		newContent.clientCA.processed = newClientCAPool
	}

	if len(newContent.servingCert.cert) > 0 && len(newContent.servingCert.key) > 0 {
		cert, err := tls.X509KeyPair(newContent.servingCert.cert, newContent.servingCert.key)
		if err != nil {
			return fmt.Errorf("invalid serving cert keypair: %v", err)
		}

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("invalid serving cert: %v", err)
		}

		klog.V(2).Infof("loaded serving cert [%q]: %s", c.servingCert.Name(), GetHumanCertDetail(x509Cert))
		if c.eventRecorder != nil {
			c.eventRecorder.Eventf(nil, nil, v1.EventTypeWarning, "TLSConfigChanged", "ServingCertificateReload", "loaded serving cert [%q]: %s", c.servingCert.Name(), GetHumanCertDetail(x509Cert))
		}

		newTLSConfigCopy.Certificates = []tls.Certificate{cert}
		newContent.servingCert.processed = &cert
	}

	if len(newContent.sniCerts) > 0 {
		newTLSConfigCopy.NameToCertificate, err = c.BuildNamedCertificates(newContent.sniCerts)
		if err != nil {
			return fmt.Errorf("unable to build named certificate map: %v", err)
		}
	}

	for i := range newContent.filterCerts {
		cert, err := tls.X509KeyPair(newContent.filterCerts[i].cert, newContent.filterCerts[i].key)
		if err != nil {
			return fmt.Errorf("invalid filter cert keypair [%d/%q]: %v", i, c.filterCerts[i].Name(), err)
		}

		// error isn't possible given above call
		x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
		klog.V(2).Infof("loaded filter cert [%q] [%q]: %s", c.filterCerts[i].Name(), c.filterCerts[i].Description(), GetHumanCertDetail(x509Cert))
		if c.eventRecorder != nil {
			c.eventRecorder.Eventf(nil, nil, v1.EventTypeWarning, "TLSConfigChanged", "FilteredCertificateReload", "loaded filtered cert [%q] [%q]: %s", c.filterCerts[i].Name(), c.filterCerts[i].Description(), GetHumanCertDetail(x509Cert))
		}

		newContent.filterCerts[i].processed = &cert
	}

	// install the GetCertificate callback to handle SNI and filtered certs
	err = c.installGetCertificateHandler(newTLSConfigCopy, newContent.filterCerts)
	if err != nil {
		return fmt.Errorf("unable to install get certificate handler for filter cert support: %v", err)
	}

	// store new values of content for serving.
	c.currentServingTLSConfig.Store(newTLSConfigCopy)
	c.currentlyServedContent = newContent // this is single threaded, so we have no locking issue

	return nil
}

func (c *DynamicServingCertificateController) installGetCertificateHandler(config *tls.Config, filterCerts []filterCertKeyContent) error {
	var cert *tls.Certificate
	if len(config.Certificates) > 0 {
		cert = &config.Certificates[0]
	}

	sni := config.NameToCertificate

	// need to nil these fields to get through to the GetCertificate callback
	config.Certificates = nil
	config.NameToCertificate = nil

	// GetCertificate returns the best certificate for the given ClientHelloInfo,
	// defaulting to the first element of c.Certificates.
	// This is based on https://golang.org/src/crypto/tls/common.go getCertificate function
	// however it is extended to serve differentiated certificates based on incoming IP.
	// This duplicates that function because it's necessary to unset c.Certificates in order
	// to activate this callback even in non-SNI path, so the fallthrough handling will not
	// suffice.
	config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(sni) == 0 && len(filterCerts) == 0 {
			if cert == nil {
				return nil, errors.New("tls: no certificates configured")
			}

			return cert, nil
		}

		if len(clientHello.ServerName) > 0 {
			name := strings.ToLower(clientHello.ServerName)
			for len(name) > 0 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}

			if cert, ok := sni[name]; ok {
				return cert, nil
			}

			// try replacing labels in the name with wildcards until we get a
			// match.
			labels := strings.Split(name, ".")
			for i := range labels {
				labels[i] = "*"
				candidate := strings.Join(labels, ".")
				if cert, ok := sni[candidate]; ok {
					return cert, nil
				}
			}
		}

		// determine if there is a cert configured that matches the rich filters
		for _, filterCert := range filterCerts {
			klog.V(3).Infof("Checking for filtered cert with %v and %v", clientHello.Conn.LocalAddr(), clientHello.Conn.RemoteAddr())

			if filterCert.filter(clientHello) {
				return filterCert.processed, nil
			}
		}

		// If nothing matches, return the first certificate.
		if cert == nil {
			return nil, errors.New("tls: no fallback certificate configured")
		}

		return cert, nil
	}

	return nil
}

// RunOnce runs a single sync step to ensure that we have a valid starting configuration.
func (c *DynamicServingCertificateController) RunOnce() error {
	return c.syncCerts()
}

// Run starts the kube-apiserver and blocks until stopCh is closed.
func (c *DynamicServingCertificateController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting DynamicServingCertificateController")
	defer klog.Infof("Shutting down DynamicServingCertificateController")

	// synchronously load once.  We will trigger again, so ignoring any error is fine
	_ = c.RunOnce()

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	// start timer that rechecks every minute, just in case.  this also serves to prime the controller quickly.
	go wait.Until(func() {
		c.Enqueue()
	}, 1*time.Minute, stopCh)

	<-stopCh
}

func (c *DynamicServingCertificateController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *DynamicServingCertificateController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.syncCerts()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// Enqueue a method to allow separate control loops to cause the certificate controller to trigger and read content.
func (c *DynamicServingCertificateController) Enqueue() {
	c.queue.Add(workItemKey)
}
